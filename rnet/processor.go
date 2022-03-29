package rnet

import (
	"errors"
	"net/http"
	"reflect"

	"github.com/dedis/protobuf"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/rnet/network"
)

// ServiceProcessor allows for an easy integration of external messages
// into the Services. You have to embed it into your Service-struct as
// a pointer. It will process client requests that have been registered
// with RegisterMessage.
type ServiceProcessor struct {
	handlers map[string]serviceHandler
	*Context
}

// serviceHandler stores the handler and the message-type.
type serviceHandler struct {
	handler interface{}
	msgType reflect.Type
}

// NewServiceProcessor initializes your ServiceProcessor.
func NewServiceProcessor(c *Context) *ServiceProcessor {
	return &ServiceProcessor{
		handlers: make(map[string]serviceHandler),
		Context:  c,
	}
}

var errType = reflect.TypeOf((*error)(nil)).Elem()

// Process implements the Processor interface and dispatches ClientRequest messages.
func (p *ServiceProcessor) Process(env *network.Envelope) {
	panic("Cannot handle message.")
}

// ProcessClientRequest takes a request from a websocket client, calculates the reply
// and sends it back. It uses the path to find the appropriate handler-
// function. It implements the Server interface.
func (p *ServiceProcessor) ProcessClientRequest(req *http.Request, path string, buf []byte) ([]byte, error) {
	mh, ok := p.handlers[path]
	reply, err := func() (interface{}, error) {
		if !ok {
			err := errors.New("The requested message hasn't been registered: " + path)
			log.Error("ProcessClientRequest", "error", err)
			return nil, err
		}
		msg := reflect.New(mh.msgType).Interface()
		err := protobuf.DecodeWithConstructors(buf, msg, network.DefaultConstructors())
		if err != nil {
			return nil, err
		}

		to := reflect.TypeOf(mh.handler).In(0)
		f := reflect.ValueOf(mh.handler)

		arg := reflect.New(to.Elem())
		arg.Elem().Set(reflect.ValueOf(msg).Elem())
		ret := f.Call([]reflect.Value{arg})

		ierr := ret[1].Interface()
		if ierr != nil {
			return nil, ierr.(error)
		}
		return ret[0].Interface(), nil
	}()
	if err != nil {
		return nil, err
	}
	buf, err = protobuf.Encode(reply)
	if err != nil {
		log.Error("ProcessClientRequest", "error", err)
		return nil, errors.New("")
	}
	return buf, nil
}
