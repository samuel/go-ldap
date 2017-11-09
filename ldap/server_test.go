package ldap

import (
	"crypto/tls"
	"errors"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
	"time"
)

func TestServer_Shutdown(t *testing.T) {
	// try to start with closed listener
	server := &Server{factory: &listenerFactoryMock{}, stopC: make(chan struct{})}
	assert.NoError(t, server.Shutdown())
	assert.Equal(t, errors.New("unable to serve because server is allready stopped"), server.Serve("", ""))

	// shutdown while serving
	server = &Server{factory: &listenerFactoryMock{}, stopC: make(chan struct{})}
	time.AfterFunc(2*time.Second, func() { server.Shutdown() })
	assert.NoError(t, server.Serve("", ""))
}

// listenerFactoryMock - listener factory mock for unit testing
var _ listenerFactory = (*listenerFactoryMock)(nil)

type listenerFactoryMock struct{}

func (_ *listenerFactoryMock) newListener(network, address string) (net.Listener, error) {
	return newListenerMock(), nil
}

func (_ *listenerFactoryMock) newTLSListener(network, addr string, config *tls.Config) (net.Listener, error) {
	return newListenerMock(), nil
}

// listenerMock - net.Listener mock for unit testing
var _ net.Listener = (*listenerMock)(nil)

type listenerMock struct {
	stopC chan struct{}
}

func newListenerMock() *listenerMock {
	return &listenerMock{
		stopC: make(chan struct{}),
	}
}

func (l *listenerMock) Accept() (net.Conn, error) {
	<-l.stopC
	return nil, errors.New("listener is closed")
}

func (l *listenerMock) Close() error {
	close(l.stopC)
	return nil
}

func (l *listenerMock) Addr() net.Addr {
	return nil
}
