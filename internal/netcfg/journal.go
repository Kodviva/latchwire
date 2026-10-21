package netcfg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultJournalPath is where the daemon keeps its journal.
const DefaultJournalPath = "/var/run/latchwire/journal.json"

// Step is one system command. Stdin carries data that must not appear in the
// arguments; secrets never belong in a Step, because the journal is a file.
//
// Persistent marks an undo step whose change outlives the interface (an ip
// rule, a sysctl, an nft table): when it fails, Remove keeps it in the
// journal for a retry instead of forgetting it.
type Step struct {
	Name       string   `json:"name"`
	Args       []string `json:"args,omitempty"`
	Stdin      []byte   `json:"stdin,omitempty"`
	Persistent bool     `json:"persistent,omitempty"`
}

func (s Step) String() string {
	return strings.Join(append([]string{s.Name}, s.Args...), " ")
}

func (s Step) clone() Step {
	s.Args = append([]string(nil), s.Args...)
	s.Stdin = append([]byte(nil), s.Stdin...)
	return s
}

func cloneSteps(in []Step) []Step {
	out := make([]Step, len(in))
	for i, s := range in {
		out[i] = s.clone()
	}
	return out
}

// Journal records, per owner, the commands that undo what was applied to the
// system. A record is written (and synced) before the change it undoes, so a
// crash leaves the undo steps behind for Cleanup. Steps are kept in apply
// order; undoing runs them in reverse.
type Journal struct {
	path string

	recovered bool // the file was unreadable as a journal and moved aside

	mu     sync.Mutex
	owners map[string][]Step
}

type journalFile struct {
	Version int               `json:"version"`
	Owners  map[string][]Step `json:"owners"`
}

const journalVersion = 1

// OpenJournal loads the journal at path. A missing file is an empty journal;
// the file and its directory are created on the first Record.
//
// A file that cannot be parsed, or has another version, is moved to
// path+".corrupt-<unix time>" and the journal starts empty, so a damaged file
// can never keep the daemon (and, with a kill switch, the network) down;
// RecoveredFromCorruption reports it. Plain read errors fail, and so does a
// journal directory or file that is not safe to trust (see checkTrusted).
func OpenJournal(path string) (*Journal, error) {
	j := &Journal{path: path, owners: map[string][]Step{}}
	if err := checkTrusted(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := checkTrusted(path); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return j, nil
	}
	if err != nil {
		return nil, fmt.Errorf("netcfg: reading journal: %w", err)
	}
	var f journalFile
	err = json.Unmarshal(b, &f)
	if err == nil && f.Version != journalVersion {
		err = fmt.Errorf("unsupported version %d", f.Version)
	}
	if err != nil {
		aside := fmt.Sprintf("%s.corrupt-%d", path, time.Now().Unix())
		if rerr := os.Rename(path, aside); rerr != nil {
			log.Printf("netcfg: journal %s is unusable (%v) and could not be moved aside (%v); starting empty", path, err, rerr)
		} else {
			log.Printf("netcfg: journal %s is unusable (%v); moved to %s, starting empty", path, err, aside)
		}
		j.recovered = true
		return j, nil
	}
	for o, steps := range f.Owners {
		j.owners[o] = steps
	}
	return j, nil
}

// RecoveredFromCorruption reports whether OpenJournal found an unusable file
// and started empty: whatever the old journal held is not known, so well-known
// objects (such as the kill switch's firewall rules) must be cleared by name.
func (j *Journal) RecoveredFromCorruption() bool { return j.recovered }

// checkTrusted fails when the daemon runs as root and p exists but is not
// owned by root or is group- or world-writable: an unprivileged user could
// plant undo commands that root then runs. Without root there is nothing to
// protect and nothing to check.
func checkTrusted(p string) error {
	if geteuid() != 0 {
		return nil
	}
	fi, err := os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("netcfg: checking %s: %w", p, err)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("netcfg: %s is writable by others (mode %v)", p, fi.Mode().Perm())
	}
	if uid, ok := ownerUID(fi); ok && uid != trustedUID {
		return fmt.Errorf("netcfg: %s is owned by uid %d, not root", p, uid)
	}
	return nil
}

// geteuid and trustedUID are variables so tests can exercise the checks
// without being root.
var (
	geteuid           = os.Geteuid
	trustedUID uint32 = 0
)

// Record replaces owner's undo steps (apply order) and persists them.
func (j *Journal) Record(owner string, undo []Step) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	old, had := j.owners[owner]
	j.owners[owner] = cloneSteps(undo)
	if err := j.flushLocked(); err != nil {
		if had {
			j.owners[owner] = old
		} else {
			delete(j.owners, owner)
		}
		return err
	}
	return nil
}

// Forget drops owner's record and persists the change. Unknown owners are a
// no-op.
func (j *Journal) Forget(owner string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	old, had := j.owners[owner]
	if !had {
		return nil
	}
	delete(j.owners, owner)
	if err := j.flushLocked(); err != nil {
		j.owners[owner] = old
		return err
	}
	return nil
}

// Entries returns a copy of every owner's undo steps (apply order).
func (j *Journal) Entries() map[string][]Step {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make(map[string][]Step, len(j.owners))
	for o, s := range j.owners {
		out[o] = cloneSteps(s)
	}
	return out
}

// flushLocked writes the journal atomically: a temporary file in the same
// directory is written and synced, renamed over the journal, and the
// directory is synced.
func (j *Journal) flushLocked() error {
	dir := filepath.Dir(j.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("netcfg: journal directory: %w", err)
	}
	b, err := json.Marshal(journalFile{Version: journalVersion, Owners: j.owners})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".journal-*")
	if err != nil {
		return fmt.Errorf("netcfg: writing journal: %w", err)
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("netcfg: writing journal: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		return fmt.Errorf("netcfg: writing journal: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("netcfg: writing journal: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("netcfg: writing journal: %w", err)
	}
	if err := os.Rename(name, j.path); err != nil {
		return fmt.Errorf("netcfg: writing journal: %w", err)
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// Cleanup undoes what the journal still holds for every owner keep does not
// claim (keep nil: none is claimed), then forgets that owner. It runs at
// service start, before tunnels load. Undo is best effort: the interface or
// route is usually gone already, so a failing step does not stop the rest,
// and the owner is forgotten either way. The errors are joined and returned.
// When ctx ends, Cleanup stops at once and forgets nothing it did not finish:
// the failures of a cancelled run say nothing about the system.
func Cleanup(ctx context.Context, r Runner, j *Journal, keep func(owner string) bool) error {
	entries := j.Entries()
	owners := make([]string, 0, len(entries))
	for o := range entries {
		owners = append(owners, o)
	}
	sort.Strings(owners)
	var errs []error
	for _, o := range owners {
		if keep != nil && keep(o) {
			continue
		}
		steps := entries[o]
		for i := len(steps) - 1; i >= 0 && ctx.Err() == nil; i-- {
			s := steps[i]
			if _, err := r.Run(ctx, s.Name, s.Args, s.Stdin); err != nil && !alreadyUndone(s, err) {
				errs = append(errs, fmt.Errorf("cleanup %s: %s: %w", o, s, err))
			}
		}
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		if err := j.Forget(o); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
