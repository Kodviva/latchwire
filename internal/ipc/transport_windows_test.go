package ipc

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Kodviva/latchwire/internal/ipc/ipctest"
)

// A listener closes right after a client came in, while it is creating the
// next instance of the pipe. Close once hung there.
func TestCloseAfterAcceptDoesNotHang(t *testing.T) {
	for i := 0; i < 300; i++ {
		path := ipctest.Path(t)
		l, err := ListenUsers(path, OpenUserTable(filepath.Join(t.TempDir(), "users.json")))
		if err != nil {
			t.Fatal(err)
		}
		accepted := make(chan *Conn, 1)
		go func() {
			c, err := Accept(l)
			if err != nil {
				c = nil
			}
			accepted <- c
		}()
		client, err := Dial(path)
		if err != nil {
			t.Fatal(err)
		}
		server := <-accepted
		if server == nil {
			t.Fatal("accept failed")
		}
		closed := make(chan struct{})
		go func() {
			l.Close()
			close(closed)
		}()
		select {
		case <-closed:
		case <-time.After(10 * time.Second):
			t.Fatalf("round %d: Close hung", i)
		}
		client.Close()
		server.Close()
	}
}
