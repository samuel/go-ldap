package ldap

import (
	"crypto/tls"
	"errors"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestWaitGroup_Wait(t *testing.T) {
	var (
		w      = newWaitGroup()
		readyC = make(chan struct{})
		stuck  bool
	)

	go func() {
		w.wait()
		close(readyC)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	select {
	case <-ctx.Done():
		stuck = true
	case <-readyC:
		// ok
	}

	assert.False(t, stuck)
}

func TestWaitGroup_AddDone(t *testing.T) {
	var (
		w      = newWaitGroup()
		n      = 1000
		readyC = make(chan struct{})
		stuck  bool
	)

	for i := 0; i < n; i++ {
		go func() {
			w.add()
			time.Sleep(1 * time.Millisecond)
			w.done()
		}()
	}

	go func() {
		w.wait()
		close(readyC)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(2*n)*time.Millisecond)
	defer cancel()

	select {
	case <-ctx.Done():
		stuck = true
	case <-readyC:
		// ok
	}

	assert.False(t, stuck)
	assert.Equal(t, int32(0), atomic.LoadInt32(&w.counter))
}

func TestServer_Shutdown(t *testing.T) {
	// try to start with closed listener
	server := &Server{factory: &listenerFactoryMock{}, stopC: make(chan struct{}), wg: newWaitGroup()}
	assert.NoError(t, server.Shutdown())
	assert.NoError(t, server.Serve("", ""))

	var (
		readyC = make(chan struct{})
		stuck  bool
	)

	// shutdown while serving
	server = &Server{factory: &listenerFactoryMock{}, stopC: make(chan struct{}), wg: newWaitGroup()}
	n := 10
	for i := 0; i < n; i++ {
		go func() {
			assert.NoError(t, server.Serve("", ""))
		}()
	}

	time.AfterFunc(1*time.Second, func() {
		server.Shutdown()
		close(readyC)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	select {
	case <-ctx.Done():
		stuck = true
	case <-readyC:
		// ok
	}

	assert.False(t, stuck)
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
