package ipc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"

	"github.com/Kodviva/latchwire/internal/datadir"
	"github.com/Kodviva/latchwire/internal/msg"
)

const (
	// helloByte is the first thing a client sends: a server can read a
	// client's token only after it has read from the pipe.
	helloByte = 'L'
	// helloTimeout bounds how long a client may hold a handshake slot.
	helloTimeout = 2 * time.Second
	// maxHandshakes bounds the clients being identified at once.
	maxHandshakes = 32
	// pipeBuffer is the size of each pipe buffer.
	pipeBuffer = 64 << 10

	// pipeDACL lets authenticated users connect; who they are decides what
	// they may do. Anonymous and remote clients have no way in: anonymous
	// logons are not authenticated users and the pipe rejects remote
	// clients (FILE_PIPE_REJECT_REMOTE_CLIENTS, set by namedpipe). The
	// default integrity label keeps out low-integrity processes.
	//
	// 0x0012019B is FILE_GENERIC_READ | FILE_GENERIC_WRITE without
	// FILE_APPEND_DATA, which on a pipe means FILE_CREATE_PIPE_INSTANCE.
	// GW would hold it, and a user could then add an instance of this pipe
	// and answer its clients, whose owner check would still pass: the
	// owner belongs to the pipe, not to the instance. Dial asks for no
	// more than this.
	pipeDACL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0012019B;;;AU)"
)

var impersonateNamedPipeClient = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

// Users returns the service's table of users.
var Users = sync.OnceValue(func() *UserTable {
	return OpenUserTable(filepath.Join(datadir.Dir(), "users.json"))
})

// handled is what a pipe connection offers besides net.Conn.
type handled interface{ Handle() windows.Handle }

// Dial connects to the pipe at path and checks that it belongs to the
// service before sending anything: the first process to create a pipe name
// owns it, and this connection carries X25519 results and configurations.
// A pipe that is not there reads as ECONNREFUSED, which is what callers see
// when the daemon does not run on Unix. PeerUID is 0: only a trusted owner
// gets this far.
func Dial(path string) (*Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	cfg := namedpipe.DialConfig{Identification: true}
	nc, err := cfg.DialContext(ctx, path)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) || errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("ipc: %s: %w", path, syscall.ECONNREFUSED)
		}
		return nil, err
	}
	if err := checkPipeOwner(nc.(handled).Handle()); err != nil {
		nc.Close()
		return nil, err
	}
	nc.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := nc.Write([]byte{helloByte}); err != nil {
		nc.Close()
		return nil, err
	}
	return newConn(nc, 0, 0), nil
}

func checkPipeOwner(h windows.Handle) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("ipc: reading the pipe's owner: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("ipc: reading the pipe's owner: %w", err)
	}
	if s := owner.String(); !trustedPipeOwner(s) {
		return fmt.Errorf(msg.IPCUntrustedPipeFmt, s)
	}
	return nil
}

// pipeSD returns the pipe's security descriptor. Its owner is the one
// clients check: LocalSystem for the service, Administrators for an
// elevated `latchwire daemon` in a console (only SYSTEM can assign SYSTEM).
func pipeSD() (*windows.SECURITY_DESCRIPTOR, error) {
	owner := "BA"
	if t := windows.GetCurrentProcessToken(); t != 0 {
		if u, err := t.GetTokenUser(); err == nil && u.User.Sid.String() == systemSID {
			owner = "SY"
		}
	}
	return windows.SecurityDescriptorFromString("O:" + owner + pipeDACL)
}

// authListener identifies each client in its own goroutine, so a client
// that connects and says nothing cannot hold up the others.
type authListener struct {
	l     net.Listener
	conns chan *Conn
	done  chan struct{}
	once  sync.Once
}

// Listen creates the pipe at path. A pipe of that name that exists already,
// whoever made it, is an error: the first instance decides who owns the
// name.
func Listen(path string) (net.Listener, error) {
	sd, err := pipeSD()
	if err != nil {
		return nil, err
	}
	cfg := namedpipe.ListenConfig{SecurityDescriptor: sd, InputBufferSize: pipeBuffer, OutputBufferSize: pipeBuffer}
	l, err := cfg.Listen(path)
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return nil, fmt.Errorf("%w: %s", ErrAddrInUse, path)
		}
		return nil, err
	}
	al := &authListener{l: l, conns: make(chan *Conn), done: make(chan struct{})}
	go al.acceptLoop()
	return al, nil
}

func (al *authListener) acceptLoop() {
	slots := make(chan struct{}, maxHandshakes)
	for {
		nc, err := al.l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("ipc: accept: %v", err)
			select {
			case <-time.After(50 * time.Millisecond):
				continue
			case <-al.done:
				return
			}
		}
		select {
		case slots <- struct{}{}:
		case <-al.done:
			nc.Close()
			return
		}
		go func() {
			defer func() { <-slots }()
			c, err := identify(nc)
			if err != nil {
				log.Printf("ipc: refusing a client: %v", err)
				nc.Close()
				return
			}
			select {
			case al.conns <- c:
			case <-al.done:
				c.Close()
			}
		}()
	}
}

func (al *authListener) Accept() (net.Conn, error) { return nil, errors.New("ipc: use ipc.Accept") }

func (al *authListener) Addr() net.Addr { return al.l.Addr() }

func (al *authListener) Close() error {
	al.once.Do(func() { close(al.done) })
	return al.l.Close()
}

// Accept returns the next identified client.
func Accept(l net.Listener) (*Conn, error) {
	al, ok := l.(*authListener)
	if !ok {
		return nil, errors.New("ipc: not a pipe listener")
	}
	select {
	case c := <-al.conns:
		return c, nil
	case <-al.done:
		return nil, net.ErrClosed
	}
}

// identify reads the client's hello and its token.
func identify(nc net.Conn) (*Conn, error) {
	nc.SetReadDeadline(time.Now().Add(helloTimeout))
	var b [1]byte
	if _, err := io.ReadFull(nc, b[:]); err != nil {
		return nil, err
	}
	if b[0] != helloByte {
		return nil, errors.New("bad hello")
	}
	nc.SetReadDeadline(time.Time{})
	h, ok := nc.(handled)
	if !ok {
		return nil, errors.New("not a pipe")
	}
	tok, err := peerToken(h.Handle())
	if err != nil {
		return nil, err
	}
	defer tok.Close()
	user, err := tok.GetTokenUser()
	if err != nil {
		return nil, err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	admin, err := tok.IsMember(admins)
	if err != nil {
		return nil, err
	}
	uid, elevated, err := classifyPeer(user.User.Sid.String(), admin, Users())
	if err != nil {
		return nil, err
	}
	return newConn(nc, uid, elevated), nil
}

// peerToken returns the identification token of the client of pipe h. The
// token comes from the kernel's record of the connection, so unlike a
// process ID it cannot be recycled, and it is the client's own: an
// impersonating client is the user it impersonates. A client that connected
// with SECURITY_ANONYMOUS fails here.
//
// The impersonation belongs to this OS thread. If it cannot be ended, the
// thread must never run anything else: the goroutine ends with the thread
// still locked, which makes the runtime destroy it.
func peerToken(h windows.Handle) (windows.Token, error) {
	runtime.LockOSThread()
	if r, _, e := impersonateNamedPipeClient.Call(uintptr(h)); r == 0 {
		runtime.UnlockOSThread()
		return 0, os.NewSyscallError("ImpersonateNamedPipeClient", e)
	}
	var tok windows.Token
	thread, err := windows.GetCurrentThread()
	if err == nil {
		err = windows.OpenThreadToken(thread, windows.TOKEN_QUERY, true, &tok)
	}
	if rerr := windows.RevertToSelf(); rerr != nil {
		if tok != 0 {
			tok.Close()
		}
		log.Printf("ipc: RevertToSelf: %v", rerr)
		runtime.Goexit()
	}
	runtime.UnlockOSThread()
	if err != nil {
		return 0, fmt.Errorf("reading the client's token: %w", err)
	}
	return tok, nil
}
