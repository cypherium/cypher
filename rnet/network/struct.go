package network

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/dedis/protobuf"
	uuid "gopkg.in/satori/go.uuid.v1"
)

// MaxRetryConnect defines how many times we should try to connect.
const MaxRetryConnect = 3

// WaitRetry is the timeout on connection-setups.
const WaitRetry = 20 * time.Millisecond

// ErrClosed is when a connection has been closed.
var ErrClosed = errors.New("Connection Closed")

// ErrEOF is when the connection sends an EOF signal (mostly because it has
// been shut down).
var ErrEOF = errors.New("EOF")

// ErrCanceled means something went wrong in the sending or receiving part.
var ErrCanceled = errors.New("Operation Canceled")

// ErrTimeout is raised if the timeout has been reached.
var ErrTimeout = errors.New("Timeout Error")

// ErrUnknown is an unknown error.
var ErrUnknown = errors.New("Unknown Error")

// Size is a type to reprensent the size that is sent before every packet to
// correctly decode it.
type Size uint32

// Envelope is a container for any Message received through the network that
// contains the Message itself as well as some metadata such as the type and the
// sender. This is created by the network stack upon reception and is never
// transmitted.
type Envelope struct {
	// The ServerIdentity of the remote peer we are talking to.
	// Basically, this means that when you open a new connection to someone, and
	// or listen to incoming connections, the network library will already
	// make some exchange between the two communicants so each knows the
	// ServerIdentity of the others.
	ServerIdentity *ServerIdentity
	// What kind of msg do we have
	MsgType MessageTypeID
	// A *pointer* to the underlying message
	Msg Message
	// which constructors are used
	Constructors protobuf.Constructors
}

// ServerIdentity is used to represent a Server in the whole internet.
// It's based on a address key, and there can be one or more addresses to contact it.
type ServerIdentity struct {
	// The ServerIdentityID corresponding to that address key
	ID ServerIdentityID
	// A slice of addresses of where that Id might be found
	Address Address
	// Description of the server
	Description string
}

// ServerIdentityID uniquely identifies an ServerIdentity struct
type ServerIdentityID uuid.UUID

// String returns a canonical representation of the ServerIdentityID.
func (eId ServerIdentityID) String() string {
	return uuid.UUID(eId).String()
}

// Equal returns true if both ServerIdentityID are equal or false otherwise.
func (eId ServerIdentityID) Equal(other ServerIdentityID) bool {
	return uuid.Equal(uuid.UUID(eId), uuid.UUID(other))
}

// IsNil returns true iff the ServerIdentityID is Nil
func (eId ServerIdentityID) IsNil() bool {
	return eId.Equal(ServerIdentityID(uuid.Nil))
}

func (si *ServerIdentity) String() string {
	return si.Address.String()
}

// ServerIdentityType can be used to recognise an ServerIdentity-message
var ServerIdentityType = RegisterMessage(ServerIdentity{})

// NewServerIdentity creates a new ServerIdentity based on a address key and with a slice
// of IP-addresses where to find that entity. The Id is based on a
// version5-UUID which can include a URL that is based on it's address key.
func NewServerIdentity(address string) *ServerIdentity {
	si := &ServerIdentity{
		Address: Address("kcp://" + address),
	}
	si.ID = ServerIdentityID(uuid.NewV5(uuid.NamespaceURL, NamespaceURL+"id/"+address))
	return si
}

// GlobalBind returns the global-binding address. Given any IP:PORT combination,
// it will return ":PORT".
func GlobalBind(address string) (string, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}
	return ":" + port, nil
}

// counterSafe is a struct that enables to update two counters Rx & Tx
// atomically that can be have increasing values.
// It's main use is for Conn to update how many bytes they've
// written / read. This struct implements the monitor.CounterIO interface.
type counterSafe struct {
	tx uint64
	rx uint64
	sync.Mutex
}

// Rx returns the rx counter
func (c *counterSafe) Rx() (out uint64) {
	c.Lock()
	out = c.rx
	c.Unlock()
	return
}

// Tx returns the tx counter
func (c *counterSafe) Tx() (out uint64) {
	c.Lock()
	out = c.tx
	c.Unlock()
	return
}

// updateRx adds delta to the rx counter
func (c *counterSafe) updateRx(delta uint64) {
	c.Lock()
	c.rx += delta
	c.Unlock()
}

// updateTx adds delta to the tx counter
func (c *counterSafe) updateTx(delta uint64) {
	c.Lock()
	c.tx += delta
	c.Unlock()
}
