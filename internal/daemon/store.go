package daemon

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/Kodviva/latchwire/internal/config"
	"github.com/Kodviva/latchwire/internal/keyref"
)

// DefaultSocket is the daemon's socket path.
const DefaultSocket = "/var/run/latchwire.sock"

// DefaultStoreDir returns where tunnel configurations are kept on this
// platform.
func DefaultStoreDir() string {
	if runtime.GOOS == "darwin" {
		return "/Library/Application Support/Latchwire/tunnels"
	}
	return "/etc/latchwire/tunnels"
}

const (
	confExt = ".conf"
	// pinExt files hold the identity public keys pinned after a tunnel's
	// first successful handshake, one "<KeyRef> <base64>" line each.
	pinExt = ".pins"
)

// validName accepts wg-quick style interface names: 1-15 of [A-Za-z0-9_=+.-],
// not starting with a dot. The name is also the file name in the store, so
// it can never contain a path separator.
func validName(s string) bool {
	if len(s) == 0 || len(s) > 15 || s[0] == '.' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("_=+.-", c) >= 0) {
			return false
		}
	}
	return true
}

// store keeps one <name>.conf per tunnel, mode 0600 in a 0700 directory. The
// files hold no private key, but they do reveal peers and preshared keys.
type store struct {
	dir string
}

func (s *store) ensureDir() error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(s.dir, 0o700)
}

// load parses every stored tunnel. A file that no longer parses is logged
// and skipped so one bad file does not take the others down.
func (s *store) load() (map[string]*config.Tunnel, error) {
	if err := s.ensureDir(); err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	out := map[string]*config.Tunnel{}
	for _, e := range ents {
		name, ok := strings.CutSuffix(e.Name(), confExt)
		if !ok || !e.Type().IsRegular() || !validName(name) {
			continue
		}
		f, err := os.Open(filepath.Join(s.dir, e.Name()))
		if err != nil {
			log.Printf("daemon: store: %s: %v", e.Name(), err)
			continue
		}
		t, err := config.Parse(name, f)
		f.Close()
		if err != nil {
			log.Printf("daemon: store: %s: %v", e.Name(), err)
			continue
		}
		out[name] = t
	}
	return out, nil
}

// save writes a tunnel's configuration.
func (s *store) save(name, text string) error {
	if !validName(name) {
		return errors.New("invalid name")
	}
	return s.writeAtomic(name+confExt, text)
}

// writeAtomic writes file in the store with mode 0600 (temporary file,
// fsync, rename).
func (s *store) writeAtomic(file, text string) error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.WriteString(text); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.dir, file))
}

// loadPins returns the pinned identity keys of a tunnel (empty if none).
func (s *store) loadPins(name string) (map[keyref.Ref][32]byte, error) {
	pins := map[keyref.Ref][32]byte{}
	if !validName(name) {
		return pins, errors.New("invalid name")
	}
	data, err := os.ReadFile(filepath.Join(s.dir, name+pinExt))
	if errors.Is(err, os.ErrNotExist) {
		return pins, nil
	}
	if err != nil {
		return pins, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		refStr, keyStr, ok := strings.Cut(line, " ")
		ref, rerr := keyref.Parse(refStr)
		key, kerr := base64.StdEncoding.DecodeString(keyStr)
		if !ok || rerr != nil || kerr != nil || len(key) != 32 {
			return map[keyref.Ref][32]byte{}, errors.New("malformed pin file")
		}
		pins[ref] = [32]byte(key)
	}
	return pins, nil
}

func (s *store) savePins(name string, pins map[keyref.Ref][32]byte) error {
	if !validName(name) {
		return errors.New("invalid name")
	}
	lines := make([]string, 0, len(pins))
	for ref, key := range pins {
		lines = append(lines, ref.String()+" "+base64.StdEncoding.EncodeToString(key[:])+"\n")
	}
	slices.Sort(lines)
	return s.writeAtomic(name+pinExt, strings.Join(lines, ""))
}

// remove deletes a tunnel's configuration and its pins.
func (s *store) remove(name string) error {
	if !validName(name) {
		return fmt.Errorf("invalid name")
	}
	var first error
	for _, ext := range []string{confExt, pinExt} {
		err := os.Remove(filepath.Join(s.dir, name+ext))
		if err != nil && !errors.Is(err, os.ErrNotExist) && first == nil {
			first = err
		}
	}
	return first
}

// removePins deletes stale pins, for example before a name is reused.
func (s *store) removePins(name string) error {
	err := os.Remove(filepath.Join(s.dir, name+pinExt))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
