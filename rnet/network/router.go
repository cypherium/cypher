package network

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
)

// Router handles all networking operations such as:
//   * listening to incoming connections using a host.Listener method
//   * opening up new connections using host.Connect method
//   * dispatching incoming message using a Dispatcher
//   * dispatching outgoing message maintaining a translation
//   between ServerIdentity <-> address
//   * managing the re-connections of non-working Conn
// Most caller should use the creation function like NewKCPRouter(...),
// NewLocalRouter(...) then use the Host such as:
//
//   router.Start() // will listen for incoming Conn and block
//   router.Stop() // will stop the listening and the managing of all Conn
type Router struct {
	// id is our own ServerIdentity
	ServerIdentity *ServerIdentity
	// address is the real-actual address used by the listener.
	address Address
	// Dispatcher is used to dispatch incoming message to the right recipient
	Dispatcher
	// Host listens for new connections
	host Host
	// connections keeps track of all active connections. Because a connection
	// can be opened at the same time on both endpoints, there can be more
	// than one connection per ServerIdentityID.
	connections map[ServerIdentityID][]Conn
	sync.Mutex

	// boolean flag indicating that the router is already clos{ing,ed}.
	isClosed bool

	// wg waits for all handleConn routines to be done.
	wg sync.WaitGroup

	// Every handler in this list is called by this router when a network error occurs (Timeout, Connection
	// Closed, or EOF). Those handler should be added by using SetErrorHandler(). The 1st argument is the remote
	// server with whom the error happened
	connectionErrorHandlers []func(*ServerIdentity)

	// keep bandwidth of closed connections
	traffic counterSafe
	// If paused is not nil, then handleConn will stop processing. When unpaused
	// it will break the connection. This is for testing node failure cases.
	paused chan bool
	// This field should only be set during testing. It disables an important
	// log message meant to discourage KCP connections.
	UnauthOk bool

	sendsMap map[ServerIdentityID]int
	sendMu   sync.Mutex
}

// NewRouter returns a new Router attached to a ServerIdentity and the host we want to
// use.
func NewRouter(own *ServerIdentity, h Host) *Router {
	r := &Router{
		ServerIdentity:          own,
		connections:             make(map[ServerIdentityID][]Conn),
		host:                    h,
		Dispatcher:              NewBlockingDispatcher(),
		connectionErrorHandlers: make([]func(*ServerIdentity), 0),
	}
	r.address = h.Address()
	r.sendsMap = make(map[ServerIdentityID]int)
	log.Info("New router", "address", r.address)
	return r
}

// Pause casues the router to stop after reading the next incoming message. It
// sleeps until it is woken up by Unpause. For testing use only.
func (r *Router) Pause() {
	r.Lock()
	if r.paused == nil {
		r.paused = make(chan bool)
	}
	r.Unlock()
}

// Unpause reverses a previous call to Pause. All paused connections are closed
// and the Router is again ready to process messages normally. For testing use only.
func (r *Router) Unpause() {
	r.Lock()
	if r.paused != nil {
		close(r.paused)
		r.paused = nil
	}
	r.Unlock()
}

// Start the listening routine of the underlying Host. This is a
// blocking call until r.Stop() is called.
func (r *Router) Start() {
	// Any incoming connection waits for the remote server identity
	// and will create a new handling routine.
	err := r.host.Listen(func(c Conn) {
		dst, err := r.receiveServerIdentity(c)
		if err != nil {
			if !strings.Contains(err.Error(), "EOF") {
				// Avoid printing error message if it's just a stray connection.
				log.Error("Receiving server identity", "from", c.Remote().NetworkAddress(), "error", err)
			}
			if err := c.Close(); err != nil {
				log.Error("Couldn't close secure connection:", "error", err)
			}
			return
		}
		if err := r.registerConnection(dst, c); err != nil {
			log.Warn("does not accept incoming connection because it's closed", "address", r.address, "from", c.Remote())
			return
		}
		// start handleConn in a go routine that waits for incoming messages and
		// dispatches them.
		if err := r.launchHandleRoutine(dst, c); err != nil {
			log.Warn("does not accept incoming connection because it's closed", "address", r.address, "from", c.Remote())
			return
		}
	})
	if err != nil {
		log.Error("Start", "Error listening:", err)
	}
}

// Stop the listening routine, and stop any routine of handling
// connections. Calling r.Start(), then r.Stop() then r.Start() again leads to
// an undefined behaviour. Callers should most of the time re-create a fresh
// Router.
func (r *Router) Stop() error {
	var err error
	err = r.host.Stop()
	r.Unpause()
	r.Lock()
	// set the isClosed to true
	r.isClosed = true

	// then close all connections
	for _, arr := range r.connections {
		// take all connections to close
		for _, c := range arr {
			if err := c.Close(); err != nil {
				log.Error("Stop", "Error", err)
			}
		}
	}
	// wait for all handleConn to finish
	r.Unlock()
	r.wg.Wait()

	if err != nil {
		return err
	}
	return nil
}

func (r *Router) GetBlocks(e *ServerIdentity) int {
	if e != nil {
		r.sendMu.Lock()
		blocksLen := r.sendsMap[e.ID]
		r.sendMu.Unlock()
		return blocksLen
	} else {
		for id, _ := range r.connections {
			log.Info("NetBlocks", "id", id, "num", r.sendsMap[id])
		}
	}
	return 0
}

// Send sends to an ServerIdentity without wrapping the msg into a ProtocolMsg
func (r *Router) Send(e *ServerIdentity, msg Message, bForeConnect bool) (uint64, error) {
	if msg == nil {
		return 0, errors.New("Can't send nil-packet")
	}

	r.sendMu.Lock()
	blocksLen := r.sendsMap[e.ID]
	if blocksLen > params.MaxSendBlocks { //max queue is 5
		r.sendMu.Unlock()
		log.Info("Router.Send", "busy address", e.Address.String())
		return 0, errors.New("Network send queue overflow!")
	}
	r.sendsMap[e.ID]++
	r.sendMu.Unlock()

	defer func() {
		r.sendMu.Lock()
		r.sendsMap[e.ID]--
		r.sendMu.Unlock()
	}()

	// If sending to ourself, directly dispatch it
	if e.Address.String() == r.ServerIdentity.Address.String() { //Sending to ourself
		packet := &Envelope{
			ServerIdentity: e,
			MsgType:        MessageType(msg),
			Msg:            msg,
		}

		r.Dispatch(packet)
		//??if err := r.Dispatch(packet); err != nil {
		//??	return 0, fmt.Errorf("Error dispatching: %s", err)
		//??}
		// Marshal the message to get its length
		b, err := Marshal(msg)
		if err != nil {
			return 0, err
		}
		//log.Debug("Message sent")

		return uint64(len(b)), nil
	}

	var totSentLen uint64
	var c Conn
	if !bForeConnect {
		c = r.connection(e.ID)
	}
	if c == nil {
		var sentLen uint64
		var err error
		c, sentLen, err = r.connect(e)
		totSentLen += sentLen
		if err != nil {
			return totSentLen, err
		}
	}

	//log.Debug("Send msg", "address", r.address, "to", e, "msg", msg)
	sentLen, err := c.Send(msg)
	totSentLen += sentLen
	if err != nil {
		log.Warn("Send msg try again", "address", r.address, "Couldn't send to", e, "error", err)
		c, sentLen, err := r.connect(e)
		totSentLen += sentLen
		if err != nil {
			return totSentLen, err
		}
		sentLen, err = c.Send(msg)
		totSentLen += sentLen
		if err != nil {
			return totSentLen, err
		}
	}
	//log.Debug("Message sent")
	return totSentLen, nil
}

// connect starts a new connection and launches the listener for incoming
// messages.
func (r *Router) connect(si *ServerIdentity) (Conn, uint64, error) {
	log.Debug("Connect", "Connecting to", si.Address)
	c, err := r.host.Connect(si)
	if err != nil {
		log.Error("Connect", "Could not connect to", si.Address, "error", err)
		return nil, 0, err
	}
	log.Info("Connect", "Connected to", si.Address)
	var sentLen uint64
	if sentLen, err = c.Send(r.ServerIdentity); err != nil {
		return nil, sentLen, err
	}

	if err = r.registerConnection(si, c); err != nil {
		return nil, sentLen, err
	}

	if err = r.launchHandleRoutine(si, c); err != nil {
		return nil, sentLen, err
	}
	return c, sentLen, nil

}

func (r *Router) removeConnection(id ServerIdentityID, c Conn) {
	r.Lock()
	defer r.Unlock()

	var toDelete = -1
	arr := r.connections[id]
	for i, cc := range arr {
		if c == cc {
			toDelete = i
		}
	}

	if toDelete == -1 {
		log.Error("Remove a connection which is not registered !?")
		return
	}

	arr[toDelete] = arr[len(arr)-1]
	arr[len(arr)-1] = nil
	r.connections[id] = arr[:len(arr)-1]
}

// triggerConnectionErrorHandlers trigger all registered connectionsErrorHandlers
func (r *Router) triggerConnectionErrorHandlers(remote *ServerIdentity) {
	for _, v := range r.connectionErrorHandlers {
		v(remote)
	}
}

// handleConn waits for incoming messages and calls the dispatcher for
// each new message. It only quits if the connection is closed or another
// unrecoverable error in the connection appears.
func (r *Router) handleConn(remote *ServerIdentity, c Conn) {
	defer r.closeConnect(remote.ID, c)
	//address := c.Remote()
	//log.Info("HandleConn", "address", r.address, "Handling new connection from", remote.Address)
	try := 0
	for {
		packet, err := c.Receive()

		// Be careful not to hold r's mutex while
		// pausing, or else Unpause would deadlock.
		r.Lock()
		paused := r.paused
		r.Unlock()
		if paused != nil {
			<-paused
			r.Lock()
			r.paused = nil
			r.Unlock()
			return
		}

		if r.Closed() || c.IsClosed() {
			return
		}

		if err != nil {
			if err == ErrTimeout {
				//log.Lvlf5("%s drops %s connection: timeout", r.ServerIdentity.Address, remote.Address)
				r.triggerConnectionErrorHandlers(remote)
				return
				//continue
			}

			if err == ErrClosed || err == ErrEOF {
				// Connection got closed.
				log.Warn("HandleConn drops connection: closed", "address", r.ServerIdentity.Address, "remot", remote.Address)
				r.triggerConnectionErrorHandlers(remote)
				return
			}
			// Temporary error, continue.
			//log.Debug("HandleConn", "", r.ServerIdentity, "Error with connection", address, "=>", err)
			try++
			if try > 3 {
				return
			}
			continue
		}
		try = 0

		packet.ServerIdentity = remote

		if err := r.Dispatch(packet); err != nil {
			log.Error("HandleConn", "Error dispatching:", err)
		}

	}
}

// connection returns the first connection associated with this ServerIdentity.
// If no connection is found, it returns nil.
func (r *Router) connection(sid ServerIdentityID) Conn {
	r.Lock()
	defer r.Unlock()
	arr := r.connections[sid]
	if len(arr) == 0 {
		return nil
	}
	return arr[0]
}

// registerConnection registers a ServerIdentity for a new connection, mapped with the
// real physical address of the connection and the connection itself.
// It uses the networkLock mutex.
func (r *Router) registerConnection(remote *ServerIdentity, c Conn) error {
	log.Debug("registerConnection", "", r.address, "Registers", remote.Address)
	r.Lock()
	defer r.Unlock()
	if r.isClosed {
		return ErrClosed
	}
	_, okc := r.connections[remote.ID]
	if okc {
		log.Debug("Connection already registered. Appending new connection to same identity.")
	}
	r.connections[remote.ID] = append(r.connections[remote.ID], c)
	return nil
}

func (r *Router) launchHandleRoutine(dst *ServerIdentity, c Conn) error {
	r.Lock()
	defer r.Unlock()
	if r.isClosed {
		return ErrClosed
	}
	r.wg.Add(1)
	go r.handleConn(dst, c)
	return nil
}

// Closed returns true if the router is closed (or is closing). For a router
// to be closed means that a call to Stop() must have been made.
func (r *Router) Closed() bool {
	r.Lock()
	defer r.Unlock()
	return r.isClosed
}

// Tx implements monitor/CounterIO
// It returns the Tx for all connections managed by this router
func (r *Router) Tx() uint64 {
	r.Lock()
	defer r.Unlock()
	var tx uint64
	for _, arr := range r.connections {
		for _, c := range arr {
			tx += c.Tx()
		}
	}
	tx += r.traffic.Tx()
	return tx
}

// Rx implements monitor/CounterIO
// It returns the Rx for all connections managed by this router
func (r *Router) Rx() uint64 {
	r.Lock()
	defer r.Unlock()
	var rx uint64
	for _, arr := range r.connections {
		for _, c := range arr {
			rx += c.Rx()
		}
	}
	rx += r.traffic.Rx()
	return rx
}

// Listening returns true if this router is started.
func (r *Router) Listening() bool {
	return r.host.Listening()
}

// receiveServerIdentity takes a fresh new conn issued by the listener and
// wait for the server identities of the remote party. It returns
// the ServerIdentity of the remote party and register the connection.
func (r *Router) receiveServerIdentity(c Conn) (*ServerIdentity, error) {
	// Receive the other ServerIdentity
	nm, err := c.Receive()
	if err != nil {
		return nil, fmt.Errorf("Error while receiving ServerIdentity during negotiation %s", err)
	}
	// Check if it is correct
	if nm.MsgType != ServerIdentityType {
		return nil, fmt.Errorf("Received wrong type during negotiation %s", nm.MsgType.String())
	}

	// Set the ServerIdentity for this connection
	dst := nm.Msg.(*ServerIdentity)

	log.Debug("receiveServerIdentity", "", r.address, "from", dst.Address)
	return dst, nil
}

// AddErrorHandler adds a network error handler function for this router. The functions will be called
// on network error (e.g. Timeout, Connection Closed, or EOF) with the identity of the faulty
// remote host as 1st parameter.
func (r *Router) AddErrorHandler(errorHandler func(*ServerIdentity)) {
	r.connectionErrorHandlers = append(r.connectionErrorHandlers, errorHandler)
}

// AdjustConnect close all remote connects that not in mlist
func (r *Router) AdjustConnect(mlist map[ServerIdentityID]bool) {
	for id, arr := range r.connections {
		_, ok := mlist[id]
		if !ok {
			for _, c := range arr {
				r.closeConnect(id, c)
			}
		}
	}
}

func (r *Router) CloseConnectByID(id ServerIdentityID) {
	arr := r.connections[id]
	for _, c := range arr {
		r.closeConnect(id, c)
	}
}

func (r *Router) closeConnect(id ServerIdentityID, c Conn) {
	if err := c.Close(); err != nil {
		log.Error("CloseConnect", "", r.address, "having error closing conn to", c.Remote(), "error", err)
	}
	rx, tx := c.Rx(), c.Tx()
	r.traffic.updateRx(rx)
	r.traffic.updateTx(tx)
	r.wg.Done()
	r.removeConnection(id, c)
	log.Debug("CloseConnect", "remote", c.Remote(), "rx", rx, "tx", tx)
}
