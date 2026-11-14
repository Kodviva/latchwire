package daemon

import (
	"context"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/Kodviva/latchwire/internal/ipc"
)

var regPairs atomic.Int32

// connPair returns the daemon side of a fresh connection.
func connPair(t *testing.T, e *env) *ipc.Conn {
	t.Helper()
	return connPairWith(t, e, nil)
}

// connPairWith is connPair; setup, if set, registers the agent side's
// handlers before it serves.
func connPairWith(t *testing.T, e *env, setup func(ac *ipc.Conn)) *ipc.Conn {
	t.Helper()
	path := fmt.Sprintf("%s-r%d", e.socket, regPairs.Add(1))
	l, err := ipc.ListenUsers(path, ipc.OpenUserTable(filepath.Join(t.TempDir(), "users.json")))
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *ipc.Conn, 1)
	go func() {
		c, err := ipc.Accept(l)
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	ac, err := ipc.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	dc := <-accepted
	l.Close()
	if dc == nil {
		t.Fatal("accept failed")
	}
	if setup != nil {
		setup(ac)
	}
	go ac.Serve(context.Background())
	go dc.Serve(context.Background())
	t.Cleanup(func() { ac.Close(); dc.Close() })
	return dc
}

func TestRegisterOnClosedConnIgnored(t *testing.T) {
	e := newEnv(t, envOpts{noAgent: true})
	dc := connPair(t, e)
	dc.Close()
	<-dc.Done()
	e.m.agentRegister(dc, 1000, []uint32{serialA})
	e.m.mu.Lock()
	n := len(e.m.agents)
	e.m.mu.Unlock()
	if n != 0 {
		t.Fatalf("agents has %d entries, want 0", n)
	}
	if got := e.m.agentFor(serialA, 1000); got != nil {
		t.Fatal("agentFor returned the closed connection")
	}
}

func TestLateRegisterAfterDropDoesNotResurrect(t *testing.T) {
	e := newEnv(t, envOpts{noAgent: true})
	dead := connPair(t, e)
	e.m.agentRegister(dead, 1000, []uint32{serialA})
	dead.Close()
	<-dead.Done()
	e.m.dropAgent(dead)
	e.m.agentRegister(dead, 1000, []uint32{serialA}) // the late handler
	live := connPair(t, e)
	e.m.agentRegister(live, 1000, []uint32{serialA})
	e.m.mu.Lock()
	_, resurrected := e.m.agents[dead]
	e.m.mu.Unlock()
	if resurrected {
		t.Fatal("dropped connection was re-inserted")
	}
	if got := e.m.agentFor(serialA, 1000); got != live {
		t.Fatalf("agentFor = %v, want the live connection", got)
	}
}
