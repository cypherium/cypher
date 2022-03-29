package network

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"

	//	"net"
	"strings"
	"sync"
	"time"

	"github.com/cypherium/cypher/log"
	kcp "github.com/xtaci/kcp-go"
)

//----------------------------------------------------------------------------------------------------
const (
	def_headerSize    = 6
	def_MaxPacketSize = 10 * 1024 * 1024
)

var (
	def_headerMagic = []byte{0xCC, 0xFF, 0xDD}
)

//----------------------------------------------------------------------------------------------------

// a connection will return an io.EOF after ReadTimeout if nothing has been
// sent.
var ReadTimeout = 3 * time.Minute // 60 * time.Second

// Global lock for 'ReadTimeout'
// Using a 'RWMutex' to be as efficient as possible, because it will be used
// quite a lot in 'Receive()'.
var readTimeoutLock = sync.RWMutex{}

// NewKCPAddress returns a new Address that has type PlainKCP with the given
// address addr.
func NewKCPAddress(addr string) Address {
	return NewAddress(PlainKCP, addr)
}

// NewKCPRouter returns a new Router using KCPHost as the underlying Host.
func NewKCPRouter(sid *ServerIdentity) (*Router, error) {
	return NewKCPRouterWithListenAddr(sid, "")
}

// NewKCPRouterWithListenAddr returns a new Router using KCPHost with the
// given listen address as the underlying Host.
func NewKCPRouterWithListenAddr(sid *ServerIdentity, listenAddr string) (*Router, error) {
	h, err := NewKCPHostWithListenAddr(sid, listenAddr)
	if err != nil {
		return nil, err
	}
	r := NewRouter(sid, h)
	return r, nil
}

// KCPConn implements the Conn interface using plain, unencrypted KCP.
type KCPConn struct {
	// The connection used
	//conn net.Conn
	conn      *kcp.UDPSession
	closed    bool
	closedMut sync.Mutex
	// So we only handle one receiving packet at a time
	receiveMutex sync.Mutex
	// So we only handle one sending packet at a time
	sendMutex sync.Mutex

	counterSafe
}

// NewKCPConn will open a KCPConn to the given address.
// In case of an error it returns a nil KCPConn and the error.
func NewKCPConn(addr Address) (conn *KCPConn, err error) {
	netAddr := addr.NetworkAddress()
	for i := 1; i <= MaxRetryConnect; i++ {
		//c, err := net.Dial("tcp", netAddr)
		//c, err := net.DialTimeout("tcp", netAddr, 60*time.Second)
		var c *kcp.UDPSession
		c, err = kcp.DialWithOptions(netAddr, nil, 10, 3)
		if err == nil {
			conn = &KCPConn{
				conn: c,
			}
			return
		}
		if i < MaxRetryConnect {
			time.Sleep(WaitRetry)
		}
	}
	if err == nil {
		err = ErrTimeout
	}
	return
}

// Receive get the bytes from the connection then decodes the buffer.
// It returns the Envelope containing the message,
// or EmptyEnvelope and an error if something wrong happened.
func (c *KCPConn) Receive() (env *Envelope, e error) {
	buff, err := c.receiveRaw()
	if err != nil {
		return nil, err
	}

	id, body, err := Unmarshal(buff)
	return &Envelope{
		MsgType: id,
		Msg:     body,
	}, err
}

// receiveRaw reads the size of the message, then the
// whole message. It returns the raw message as slice of bytes.
// If there is no message available, it blocks until one becomes
// available.
// In case of an error it returns a nil slice and the error.
func (c *KCPConn) setReadDeadline(d time.Duration) {
	readTimeoutLock.RLock()
	if d > 0 {
		c.conn.SetReadDeadline(time.Now().Add(d))
	} else {
		c.conn.SetReadDeadline(time.Time{})
	}
	readTimeoutLock.RUnlock()
}

func (c *KCPConn) receiveRaw() ([]byte, error) {
	c.receiveMutex.Lock()
	defer c.receiveMutex.Unlock()

	headBuf := make([]byte, def_headerSize)
	c.setReadDeadline(ReadTimeout)
	_, err := io.ReadFull(c.conn, headBuf)
	c.setReadDeadline(0)
	if err != nil {
		//log.Debug("read message header fail", "error", err)
		return nil, err
	}

	// Check the message header
	total := readInt24(headBuf)
	if headBuf[3] != def_headerMagic[0] || headBuf[4] != def_headerMagic[1] || headBuf[5] != def_headerMagic[2] {
		err := fmt.Errorf("Buffer head not match! ")
		log.Info("receiveRaw", "header check fail", "error", err)
		return nil, err
	}

	if total > def_MaxPacketSize {
		return nil, fmt.Errorf("%v sends too big packet: %v>%v", c.conn.RemoteAddr().String(), total, def_MaxPacketSize)
	}

	b := make([]byte, total)
	//------------------------------------------------------------------------------
	var read uint32
	var buffer bytes.Buffer
	for read < total {
		// Read the size of the next packet.
		c.setReadDeadline(ReadTimeout)
		n, err := c.conn.Read(b)
		c.setReadDeadline(0)
		// Quit if there is an error.
		if err != nil {
			c.updateRx(def_headerSize + uint64(read))
			return nil, handleError(err)
		}
		// Append the read bytes into the buffer.
		if _, err := buffer.Write(b[:n]); err != nil {
			log.Error("receiveRaw", "Couldn't write to buffer:", err)
		}
		read += uint32(n)
		b = b[n:]
	}

	// register how many bytes we read. (4 is for the frame size
	// that we read up above).
	c.updateRx(def_headerSize + uint64(read))
	return buffer.Bytes(), nil
}

// Send converts the NetworkMessage into an ApplicationMessage
// and sends it using send().
// It returns the number of bytes sent and an error if anything was wrong.
func (c *KCPConn) Send(msg Message) (uint64, error) {
	c.sendMutex.Lock()
	defer c.sendMutex.Unlock()

	b, err := Marshal(msg)
	if err != nil {
		return 0, fmt.Errorf("Error marshaling  message: %s", err.Error())
	}
	return c.sendRaw(b)
}

// sendRaw writes the number of bytes of the message to the network then the
// whole message b in slices of size maxChunkSize.
// In case of an error it aborts.
func (c *KCPConn) sendRaw(b []byte) (uint64, error) {
	// First write the size
	packetSize := uint32(len(b))

	headBuf := make([]byte, def_headerSize)
	putInt24(packetSize, headBuf)
	copy(headBuf[3:], def_headerMagic)

	if _, err := c.conn.Write(headBuf); err != nil {
		return 0, err
	}

	// Then send everything through the connection
	// Send chunk by chunk
	//	log.Lvl5("Sending from", c.conn.LocalAddr(), "to", c.conn.RemoteAddr())
	var sent uint32
	for sent < packetSize {
		n, err := c.conn.Write(b[sent:])
		if err != nil {
			sentLen := def_headerSize + uint64(sent)
			c.updateTx(sentLen)
			return sentLen, handleError(err)
		}
		sent += uint32(n)
	}
	// update stats on the connection. Plus 4 for the uint32 for the frame size.
	sentLen := def_headerSize + uint64(sent)
	c.updateTx(sentLen)
	return sentLen, nil
}

// Remote returns the name of the peer at the end point of
// the connection.
func (c *KCPConn) Remote() Address {
	return Address(c.conn.RemoteAddr().String())
}

// Local returns the local address and port.
func (c *KCPConn) Local() Address {
	return NewKCPAddress(c.conn.LocalAddr().String())
}

// Type returns PlainKCP.
func (c *KCPConn) Type() ConnType {
	return PlainKCP
}

//IsClosed  return connection closing
func (c *KCPConn) IsClosed() bool {
	c.closedMut.Lock()
	defer c.closedMut.Unlock()
	return c.closed
}

// Close the connection.
// Returns error if it couldn't close the connection.
func (c *KCPConn) Close() error {
	c.closedMut.Lock()
	defer c.closedMut.Unlock()
	if c.closed == true {
		return ErrClosed
	}
	err := c.conn.Close()
	c.closed = true
	if err != nil {
		handleError(err)
	}
	return nil
}

// handleError translates the network-layer error to a set of errors
// used in our packages.
func handleError(err error) error {
	if strings.Contains(err.Error(), "use of closed") || strings.Contains(err.Error(), "broken pipe") {
		return ErrClosed
	} else if strings.Contains(err.Error(), "canceled") {
		return ErrCanceled
	} else if err == io.EOF || strings.Contains(err.Error(), "EOF") {
		return ErrEOF
	}

	netErr, ok := err.(net.Error)
	if !ok {
		return ErrUnknown
	}
	if netErr.Timeout() {
		return ErrTimeout
	}
	return ErrUnknown
}

// KCPListener implements the Host-interface using Kcp as a communication
// channel.
type KCPListener struct {
	// the underlying golang/net listener.
	listener *kcp.Listener //net.Listener
	// the close channel used to indicate to the listener we want to quit.
	quit chan bool
	// quitListener is a channel to indicate to the closing function that the
	// listener has actually really quit.
	quitListener  chan bool
	listeningLock sync.Mutex
	listening     bool

	// closed tells the listen routine to return immediately if a
	// Stop() has been called.
	closed bool

	// actual listening addr which might differ from initial address in
	// case of ":0"-address.
	addr net.Addr

	// Is this a KCP or a TLS listener?
	conntype ConnType
}

// NewKCPListener returns a KCPListener. This function binds globally using
// the port of 'addr'.
// It returns the listener and an error if one occurred during
// the binding.
// A subsequent call to Address() gives the actual listening
// address which is different if you gave it a ":0"-address.
func NewKCPListener(addr Address) (*KCPListener, error) {
	return NewKCPListenerWithListenAddr(addr, "")
}

// NewKCPListenerWithListenAddr returns a KCPListener. This function binds to the
// given 'listenAddr'. If it is empty, the function binds globally using
// the port of 'addr'.
// It returns the listener and an error if one occurred during
// the binding.
// A subsequent call to Address() gives the actual listening
// address which is different if you gave it a ":0"-address.
func NewKCPListenerWithListenAddr(addr Address, listenAddr string) (*KCPListener, error) {
	if addr.ConnType() != PlainKCP && addr.ConnType() != TLS {
		return nil, errors.New("KCPListener can only listen on KCP and TLS addresses")
	}
	t := &KCPListener{
		conntype:     addr.ConnType(),
		quit:         make(chan bool),
		quitListener: make(chan bool),
	}
	listenOn, err := getListenAddress(addr, listenAddr)
	if err != nil {
		return nil, err
	}
	ln, err := kcp.ListenWithOptions(listenOn, nil, 10, 3) //Listen(listenOn)
	if err != nil {
		return nil, errors.New("Error opening listener: " + err.Error())
	}
	t.listener = ln
	t.addr = t.listener.Addr()
	return t, nil
}

// Listen starts to listen for incoming connections and calls fn for every
// connection-request it receives.
// If the connection is closed, an error will be returned.
func (t *KCPListener) Listen(fn func(Conn)) error {
	receiver := func(tc Conn) {
		go fn(tc)
	}
	return t.listen(receiver)
}

// listen is the private function that takes a function that takes a KCPConn.
// That way we can control what to do of the KCPConn before returning it to the
// function given by the user. fn is called in the same routine.
func (t *KCPListener) listen(fn func(Conn)) error {
	t.listeningLock.Lock()
	if t.closed == true {
		t.listeningLock.Unlock()
		return nil
	}
	log.Info("Listener Start !!")

	t.listening = true
	t.listeningLock.Unlock()
	for {
		conn, err := t.listener.AcceptKCP()
		if err != nil {
			select {
			case <-t.quit:
				t.quitListener <- true
				return nil
			default:
			}
			continue
		}
		c := KCPConn{conn: conn}
		fn(&c)
	}
}

// Stop the listener. It waits till all connections are closed
// and returned from.
// If there is no listener it will return an error.
func (t *KCPListener) Stop() error {
	// lets see if we launched a listening routing
	t.listeningLock.Lock()
	defer t.listeningLock.Unlock()

	log.Info("Listener Stop !!")

	close(t.quit)

	if t.listener != nil {
		if err := t.listener.Close(); err != nil {
			if handleError(err) != ErrClosed {
				return err
			}
		}
	}
	var stop bool
	if t.listening {
		for !stop {
			select {
			case <-t.quitListener:
				stop = true
			case <-time.After(time.Millisecond * 50):
				continue
			}
		}
	}

	t.quit = make(chan bool)
	t.listening = false
	t.closed = true
	return nil
}

// Address returns the listening address.
func (t *KCPListener) Address() Address {
	t.listeningLock.Lock()
	defer t.listeningLock.Unlock()
	return NewAddress(t.conntype, t.addr.String())
}

// Listening returns whether it's already listening.
func (t *KCPListener) Listening() bool {
	t.listeningLock.Lock()
	defer t.listeningLock.Unlock()
	return t.listening
}

// getListenAddress returns the address the listener should listen
// on given the server's address (addr) and the address it was told to listen
// on (listenAddr), which could be empty.
// Rules:
// 1. If there is no listenAddr, bind globally with addr.
// 2. If there is only an IP in listenAddr, take the port from addr.
// 3. If there is an IP:Port in listenAddr, take only listenAddr.
// Otherwise return an error.
func getListenAddress(addr Address, listenAddr string) (string, error) {
	// If no `listenAddr`, bind globally.
	if listenAddr == "" {
		return GlobalBind(addr.NetworkAddress())
	}
	_, port, err := net.SplitHostPort(addr.NetworkAddress())
	if err != nil {
		return "", err
	}

	// If 'listenAddr' only contains the host, combine it with the port
	// of 'addr'.
	splitted := strings.Split(listenAddr, ":")
	if len(splitted) == 1 && port != "" {
		return splitted[0] + ":" + port, nil
	}

	// If host and port in `listenAddr`, choose this one.
	hostListen, portListen, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "", err
	}
	if hostListen != "" && portListen != "" {
		return listenAddr, nil
	}

	return "", fmt.Errorf("Invalid combination of 'addr' (%s) and 'listenAddr' (%s)", addr.NetworkAddress(), listenAddr)
}

// KCPHost implements the Host interface using KCP connections.
type KCPHost struct {
	sid *ServerIdentity
	*KCPListener
}

// NewKCPHost returns a new Host using KCP connection based type.
func NewKCPHost(sid *ServerIdentity) (*KCPHost, error) {
	return NewKCPHostWithListenAddr(sid, "")
}

// NewKCPHostWithListenAddr returns a new Host using KCP connection based type
// listening on the given address.
func NewKCPHostWithListenAddr(sid *ServerIdentity, listenAddr string) (*KCPHost, error) {
	h := &KCPHost{sid: sid}
	var err error
	h.KCPListener, err = NewKCPListenerWithListenAddr(sid.Address, listenAddr)
	return h, err
}

// Connect can only connect to PlainKCP connections.
// It will return an error if it is not a PlainKCP-connection-type.
func (t *KCPHost) Connect(si *ServerIdentity) (Conn, error) {
	switch si.Address.ConnType() {
	case PlainKCP:
		c, err := NewKCPConn(si.Address)
		return c, err
	case InvalidConnType:
		return nil, errors.New("This address is not correctly formatted: " + si.Address.String())
	}
	return nil, fmt.Errorf("KCPHost %s can't handle this type of connection: %s", si.Address, si.Address.ConnType())
}

func readInt24(b []byte) uint32 {
	return uint32(b[2]) | uint32(b[1])<<8 | uint32(b[0])<<16
}

func putInt24(v uint32, b []byte) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}
