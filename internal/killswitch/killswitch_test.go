package killswitch

import (
	"errors"
	"runtime"
	"testing"
)

func TestNewPlatform(t *testing.T) {
	r := &recorder{}
	f, err := New(r, newJournal(t))
	switch runtime.GOOS {
	case "darwin":
		// pf: nothing runs until a Set.
		if _, ok := f.(*pfFirewall); err != nil || !ok || len(r.cmds) != 0 {
			t.Fatalf("New on darwin: %T, %v, ran %q; want the pf firewall", f, err, r.cmds)
		}
		return
	case "windows":
		// WFP: the engine opens on the first Set.
		if err != nil || f == nil {
			t.Fatalf("New on windows: %v, %v; want the WFP firewall", f, err)
		}
		return
	case "linux":
	default:
		if !errors.Is(err, ErrUnsupported) || f != nil {
			t.Fatalf("New on %s: %v, %v; want ErrUnsupported", runtime.GOOS, f, err)
		}
		return
	}
	if err != nil || f == nil {
		t.Fatalf("New: %v", err)
	}
	r.missing = true
	if _, err := New(r, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("New without nft: %v, want ErrUnsupported", err)
	}
}

// The journal owner can never be a tunnel's interface name, so Cleanup and
// the configurers never confuse the kill switch with a tunnel.
func TestJournalOwnerIsNoInterfaceName(t *testing.T) {
	ok := false
	for _, c := range JournalOwner {
		if c == ':' || c == '/' {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("JournalOwner %q could be an interface name", JournalOwner)
	}
}
