package ipc

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Windows identifies users by SID, while everything above this package (a
// tunnel's allowed users, the binding of a tunnel to its user, the policy
// file) identifies them by uint32. UserTable connects the two: a SID gets
// the next free number the first time it is seen and keeps it for good.
//
// The table is exact, not a hash: a collision would hand one user's tunnels
// to another. It is also why a damaged file is never rebuilt: renumbering
// would do the same. A table that cannot be read fails every lookup instead,
// so unprivileged users are refused while elevated ones go on working (uid
// 0 needs no table), and an administrator repairs or removes the file, which
// asks for the allowed users to be set again.

const (
	// firstUserID is the first uid handed out; numbers below it stay free
	// so that no entry can be mistaken for root (0).
	firstUserID = 1000
	// maxUsers bounds the table. Only accounts that can log on get here.
	maxUsers = 4096

	systemSID = "S-1-5-18"
)

// ErrUserTable says that the user table is unusable or full.
var ErrUserTable = errors.New("ipc: user table unusable")

type userTableFile struct {
	Version int               `json:"version"`
	Next    uint32            `json:"next"`
	Users   map[string]uint32 `json:"users"` // SID to uid
}

const userTableVersion = 1

// UserTable is the persistent mapping of SIDs to uids.
type UserTable struct {
	path string

	mu   sync.Mutex
	f    userTableFile
	bad  error // why the file cannot be used
	sids map[uint32]string
}

// OpenUserTable loads the table at path. A missing file is an empty table.
// A file that does not validate leaves a table whose calls all fail.
func OpenUserTable(path string) *UserTable {
	t := &UserTable{path: path, sids: map[uint32]string{}}
	t.f = userTableFile{Version: userTableVersion, Next: firstUserID, Users: map[string]uint32{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return t
	}
	if err != nil {
		t.bad = err
		return t
	}
	var f userTableFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.bad = fmt.Errorf("%s: %w", path, err)
		return t
	}
	if err := f.validate(); err != nil {
		t.bad = fmt.Errorf("%s: %w", path, err)
		return t
	}
	t.f = f
	for s, id := range f.Users {
		t.sids[id] = s
	}
	return t
}

func (f *userTableFile) validate() error {
	if f.Version != userTableVersion {
		return fmt.Errorf("unsupported version %d", f.Version)
	}
	if f.Next < firstUserID || len(f.Users) > maxUsers {
		return errors.New("bad counters")
	}
	seen := map[uint32]bool{}
	for s, id := range f.Users {
		if !validSID(s) || id < firstUserID || id >= f.Next || seen[id] {
			return fmt.Errorf("bad entry %q", s)
		}
		seen[id] = true
	}
	return nil
}

// validSID accepts the string form of a SID: S-1, then numbers.
func validSID(s string) bool {
	if len(s) < 5 || len(s) > 184 || s[:4] != "S-1-" {
		return false
	}
	digits := 0
	for i := 4; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			digits++
		case c == '-' && digits > 0:
			digits = 0
		default:
			return false
		}
	}
	return digits > 0
}

// Assign returns sid's uid, giving it the next one the first time. The new
// entry reaches the disk before the uid is returned, so a uid in a policy
// file never outlives its entry.
func (t *UserTable) Assign(sid string) (uint32, error) {
	if !validSID(sid) {
		return 0, fmt.Errorf("%w: invalid SID", ErrUserTable)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.bad != nil {
		return 0, fmt.Errorf("%w: %w", ErrUserTable, t.bad)
	}
	if id, ok := t.f.Users[sid]; ok {
		return id, nil
	}
	if len(t.f.Users) >= maxUsers {
		return 0, fmt.Errorf("%w: full", ErrUserTable)
	}
	id := t.f.Next
	t.f.Users[sid], t.f.Next = id, id+1
	if err := t.flushLocked(); err != nil {
		delete(t.f.Users, sid)
		t.f.Next = id
		return 0, fmt.Errorf("%w: %w", ErrUserTable, err)
	}
	t.sids[id] = sid
	return id, nil
}

// SID returns the SID of uid.
func (t *UserTable) SID(uid uint32) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.sids[uid]
	return s, ok
}

// flushLocked replaces the file atomically. The data directory's DACL
// (datadir.Secure) protects it.
func (t *UserTable) flushLocked() error {
	b, err := json.Marshal(t.f)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(t.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(t.path), ".users-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after the rename
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), t.path)
}

// classifyPeer turns a client's token into its identity: uid is what the
// daemon authorizes by, elevated the user behind a uid of 0.
//
// LocalSystem is root. admin says that the token has BUILTIN\Administrators
// enabled, which UAC gives only to elevated processes: that is Windows's
// sudo, so the client is root as well, and the user behind it is kept the
// way SUDO_UID keeps it on Unix. A table failure costs an elevated client
// only that user. Everyone else needs the table.
func classifyPeer(sid string, admin bool, t *UserTable) (uid, elevated uint32, err error) {
	if sid == systemSID {
		return 0, 0, nil
	}
	id, err := t.Assign(sid)
	if admin {
		if err != nil {
			return 0, 0, nil
		}
		return 0, id, nil
	}
	if err != nil {
		return 0, 0, err
	}
	return id, 0, nil
}

// trustedPipeOwner reports whether a pipe owned by sid is the service's.
// Only SYSTEM and elevated administrators can own an object as those SIDs,
// so a process squatting on the name is told apart.
func trustedPipeOwner(sid string) bool {
	return sid == systemSID || sid == "S-1-5-32-544"
}
