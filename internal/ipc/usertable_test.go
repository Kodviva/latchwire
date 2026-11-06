package ipc

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const (
	alice = "S-1-5-21-1004336348-1177238915-682003330-1001"
	bob   = "S-1-5-21-1004336348-1177238915-682003330-1002"
)

func TestAssignStableAcrossReload(t *testing.T) {
	p := filepath.Join(t.TempDir(), "users.json")
	u := OpenUserTable(p)
	a, err := u.Assign(alice)
	if err != nil {
		t.Fatal(err)
	}
	b, err := u.Assign(bob)
	if err != nil {
		t.Fatal(err)
	}
	if a != firstUserID || b != firstUserID+1 {
		t.Fatalf("uids %d, %d", a, b)
	}
	if again, _ := u.Assign(alice); again != a {
		t.Fatalf("second Assign = %d, want %d", again, a)
	}
	u = OpenUserTable(p)
	if got, err := u.Assign(bob); err != nil || got != b {
		t.Fatalf("after reload: %d, %v", got, err)
	}
	if s, ok := u.SID(a); !ok || s != alice {
		t.Fatalf("SID(%d) = %q, %v", a, s, ok)
	}
}

func TestAssignNeverReuses(t *testing.T) {
	p := filepath.Join(t.TempDir(), "users.json")
	u := OpenUserTable(p)
	u.Assign(alice)
	u = OpenUserTable(p)
	got, err := u.Assign(bob)
	if err != nil {
		t.Fatal(err)
	}
	if got <= firstUserID {
		t.Fatalf("new uid %d reuses an old one", got)
	}
}

func TestCorruptTableRefused(t *testing.T) {
	for name, text := range map[string]string{
		"junk":      "not json",
		"version":   `{"version":9,"next":1001,"users":{}}`,
		"low uid":   `{"version":1,"next":1001,"users":{"` + alice + `":5}}`,
		"uid>=next": `{"version":1,"next":1000,"users":{"` + alice + `":1000}}`,
		"dup":       `{"version":1,"next":1002,"users":{"` + alice + `":1000,"` + bob + `":1000}}`,
		"bad sid":   `{"version":1,"next":1001,"users":{"root":1000}}`,
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "users.json")
			if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			u := OpenUserTable(p)
			if _, err := u.Assign(alice); !errors.Is(err, ErrUserTable) {
				t.Fatalf("Assign: %v", err)
			}
			if b, _ := os.ReadFile(p); string(b) != text {
				t.Fatal("the damaged file was rewritten")
			}
		})
	}
}

func TestRejectsBadSID(t *testing.T) {
	u := OpenUserTable(filepath.Join(t.TempDir(), "users.json"))
	for _, s := range []string{"", "S-1", "S-1-", "S-1-5-", "S-1-5--18", `S-1-5-18\x`, "s-1-5-18", "x"} {
		if _, err := u.Assign(s); err == nil {
			t.Fatalf("Assign(%q) accepted", s)
		}
	}
}

func TestClassifySystem(t *testing.T) {
	uid, el, err := classifyPeer(systemSID, true, nil)
	if err != nil || uid != 0 || el != 0 {
		t.Fatalf("%d %d %v", uid, el, err)
	}
}

func TestClassifyElevated(t *testing.T) {
	u := OpenUserTable(filepath.Join(t.TempDir(), "users.json"))
	uid, el, err := classifyPeer(alice, true, u)
	if err != nil || uid != 0 || el != firstUserID {
		t.Fatalf("%d %d %v", uid, el, err)
	}
}

func TestClassifyPlain(t *testing.T) {
	u := OpenUserTable(filepath.Join(t.TempDir(), "users.json"))
	// The same user unelevated gets the uid its elevated self is bound to.
	_, el, _ := classifyPeer(alice, true, u)
	uid, el2, err := classifyPeer(alice, false, u)
	if err != nil || uid != el || el2 != 0 {
		t.Fatalf("%d %d %v", uid, el2, err)
	}
}

func TestClassifyTableFailure(t *testing.T) {
	p := filepath.Join(t.TempDir(), "users.json")
	os.WriteFile(p, []byte("junk"), 0o600)
	u := OpenUserTable(p)
	if uid, el, err := classifyPeer(alice, true, u); err != nil || uid != 0 || el != 0 {
		t.Fatalf("elevated: %d %d %v", uid, el, err)
	}
	if _, _, err := classifyPeer(alice, false, u); err == nil {
		t.Fatal("an unprivileged user passed without a table")
	}
}

func TestPipeOwnerTrusted(t *testing.T) {
	for sid, want := range map[string]bool{
		systemSID:      true,
		"S-1-5-32-544": true,
		alice:          false,
		"S-1-5-32-545": false,
		"S-1-1-0":      false,
		"":             false,
	} {
		if got := trustedPipeOwner(sid); got != want {
			t.Errorf("trustedPipeOwner(%q) = %v", sid, got)
		}
	}
}
