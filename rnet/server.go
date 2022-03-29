package rnet

import (
	"fmt"
	"sync"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/rnet/network"
	"rsc.io/goversion/version"
)

// Server connects the Router and the Services together. It sets
// up everything and returns once a working network has been set up.
type Server struct {
	*network.Router
	serviceManager *serviceManager
	//	statusReporterStruct *statusReporterStruct
	// protocols holds a map of all available protocols and how to create an
	// instance of it
	//protocols *protocolStorage
	// when this node has been started
	started time.Time
	// once everything's up and running
	closeitChannel chan bool
	IsStarted      bool
}

// NewServer returns a fresh Server tied to a given Router.
// If dbPath is "", the server will write its database to the default
// location. If dbPath is != "", it is considered a temp dir, and the
// DB is deleted on close.
func newServer(r *network.Router) *Server {
	c := &Server{
		//	statusReporterStruct: newStatusReporterStruct(),
		Router:         r,
		closeitChannel: make(chan bool),
	}
	c.serviceManager = newServiceManager(c)
	return c
}

func NewKcpServer(addr string) *Server {
	serverIdentity := &network.ServerIdentity{}
	serverIdentity.Address = network.Address("kcp://" + addr)
	return NewServerKCPWithListenAddr(serverIdentity, "")
}

// NewServerKCPWithListenAddr returns a new Server out of a private-key and
// its related address within the ServerIdentity. The server will use a
// KcpRouter listening on the given address as Router.
func NewServerKCPWithListenAddr(e *network.ServerIdentity, listenAddr string) *Server {
	r, _ := network.NewKCPRouterWithListenAddr(e, listenAddr)
	return newServer(r)
}

var gover version.Version
var goverOnce sync.Once
var goverOk = false

// Close closes the  Router
func (c *Server) Close() error {
	c.Lock()
	if c.IsStarted {
		// c.closeitChannel <- true
		c.IsStarted = false
	}
	c.Unlock()
	err := c.Router.Stop()
	log.Warn("Close", "Host Close", c.ServerIdentity.Address, "listening?", c.Router.Listening())
	return err
}

// Address returns the address used by the Router.
func (c *Server) Address() network.Address {
	return c.ServerIdentity.Address
}

// Service returns the service with the given name.
func (c *Server) Service(name string) Service {
	return c.serviceManager.service(name)
}

// GetService is kept for backward-compatibility.
func (c *Server) GetService(name string) Service {
	log.Warn("This method is deprecated - use `Server.Service` instead")
	return c.Service(name)
}

// Start makes the router listen on their respective
// ports. It returns once all servers are started.
func (c *Server) Start() {
	c.started = time.Now()
	log.Info(fmt.Sprintf("Starting server at %s on address %s ", c.started.Format("2006-01-02 15:04:05"), c.ServerIdentity.Address))
	go c.Router.Start()
	for !c.Router.Listening() {
		time.Sleep(50 * time.Millisecond)
	}
	c.Lock()
	c.IsStarted = true
	c.Unlock()
	// Wait for closing of the channel
	//<-c.closeitChannel
}

// CloseConnect close remote connection
func (c *Server) AdjustConnect(list []*common.Cnode) {
}
