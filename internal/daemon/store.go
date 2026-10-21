package daemon

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Kodviva/latchwire/internal/config"
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

const confExt = ".conf"

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

// load parses every stored tunnel. A file that no longer parses (for
// example a Plan 1 configuration whose MTU is outside 1280-9000) is logged
// as not loaded and skipped, so one bad file does not take the others
// down.
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
			log.Printf("daemon: WARNING: tunnel %s is not loaded: %s: %v; fix the file, or remove the tunnel and add it again", name, filepath.Join(s.dir, e.Name()), err)
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

// remove deletes a tunnel's configuration.
func (s *store) remove(name string) error {
	if !validName(name) {
		return fmt.Errorf("invalid name")
	}
	err := os.Remove(filepath.Join(s.dir, name+confExt))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// The endpoint cache: <name>.endpoints holds, for each peer whose endpoint
// is a host name, the address the last successful lookup found. A connect
// whose lookup fails for a transient reason uses it (under the kill switch
// the resolver may reach no DNS server while the tunnel is down). Literal
// endpoints are never cached.
const (
	endpointsExt     = ".endpoints"
	endpointsVersion = 1
	// maxEndpointsFile bounds what is read from a cache file.
	maxEndpointsFile = 64 << 10
)

// cachedEndpoint is one peer's entry: the endpoint as configured
// (host:port), the address it resolved to (ip:port) and when.
type cachedEndpoint struct {
	Endpoint string    `json:"endpoint"`
	Addr     string    `json:"addr"`
	Resolved time.Time `json:"resolved"`
}

type endpointsFile struct {
	Version int                       `json:"version"`
	Peers   map[string]cachedEndpoint `json:"peers"` // hex public key
}

// saveEndpoints replaces name's endpoint cache.
func (s *store) saveEndpoints(name string, peers map[string]cachedEndpoint) error {
	if !validName(name) {
		return errors.New("invalid name")
	}
	b, err := json.Marshal(endpointsFile{Version: endpointsVersion, Peers: peers})
	if err != nil {
		return err
	}
	return s.writeAtomic(name+endpointsExt, string(b))
}

// loadEndpoints reads name's endpoint cache. A missing file is an empty
// cache; a file that is not a regular file, is writable by others, is too
// large or does not validate in every entry is an error (the caller ignores
// it).
func (s *store) loadEndpoints(name string) (map[string]cachedEndpoint, error) {
	if !validName(name) {
		return nil, errors.New("invalid name")
	}
	p := filepath.Join(s.dir, name+endpointsExt)
	fi, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	switch {
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("%s: not a regular file", p)
	case fi.Mode().Perm()&0o022 != 0:
		return nil, fmt.Errorf("%s: writable by group or others (mode %v)", p, fi.Mode().Perm())
	case fi.Size() > maxEndpointsFile:
		return nil, fmt.Errorf("%s: larger than %d bytes", p, maxEndpointsFile)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f endpointsFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%s: trailing data", p)
	}
	if f.Version != endpointsVersion {
		return nil, fmt.Errorf("%s: unsupported version %d", p, f.Version)
	}
	for k, e := range f.Peers {
		if err := validCachedEndpoint(k, e); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}
	return f.Peers, nil
}

// validCachedEndpoint checks one cache entry: a lowercase hex X25519 public
// key, a host:port endpoint, a literal unicast ip:port without a zone, and
// the time of the lookup.
func validCachedEndpoint(key string, e cachedEndpoint) error {
	if k, err := hex.DecodeString(key); err != nil || len(k) != 32 || hex.EncodeToString(k) != key {
		return fmt.Errorf("bad peer key %q", key)
	}
	if _, port, err := net.SplitHostPort(e.Endpoint); err != nil || port == "" {
		return fmt.Errorf("bad endpoint %q", e.Endpoint)
	}
	ap, err := netip.ParseAddrPort(e.Addr)
	a := ap.Addr()
	if err != nil || ap.Port() == 0 || a.Zone() != "" || a.Is4In6() || a.IsUnspecified() || a.IsMulticast() {
		return fmt.Errorf("bad address %q", e.Addr)
	}
	if e.Resolved.IsZero() {
		return errors.New("no lookup time")
	}
	return nil
}

// removeEndpoints deletes name's endpoint cache.
func (s *store) removeEndpoints(name string) error {
	if !validName(name) {
		return errors.New("invalid name")
	}
	err := os.Remove(filepath.Join(s.dir, name+endpointsExt))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// The kill switch's tunnel record: killswitch.state (0600, never a tunnel
// file: those end in .conf, .endpoints or .policy) lists the tunnels an
// active kill switch blocks for, with the key and user each is bound to.
// A daemon restarted after a crash restores exactly those (P17).
const (
	ksTunnelsFile    = "killswitch.state"
	ksTunnelsVersion = 1
	maxKSTunnelsFile = 64 << 10
)

type ksTunnelsRecord struct {
	Version int        `json:"version"`
	Tunnels []ksTunnel `json:"tunnels"`
}

// saveKillSwitchTunnels replaces the record.
func (s *store) saveKillSwitchTunnels(ts []ksTunnel) error {
	b, err := json.Marshal(ksTunnelsRecord{Version: ksTunnelsVersion, Tunnels: ts})
	if err != nil {
		return err
	}
	return s.writeAtomic(ksTunnelsFile, string(b))
}

// loadKillSwitchTunnels reads the record. A missing file is an empty
// record; a file that is not a regular file, is writable by group or
// others, is too large or does not validate is an error.
func (s *store) loadKillSwitchTunnels() ([]ksTunnel, error) {
	p := filepath.Join(s.dir, ksTunnelsFile)
	fi, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	switch {
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("%s: not a regular file", p)
	case fi.Mode().Perm()&0o022 != 0:
		return nil, fmt.Errorf("%s: writable by group or others (mode %v)", p, fi.Mode().Perm())
	case fi.Size() > maxKSTunnelsFile:
		return nil, fmt.Errorf("%s: larger than %d bytes", p, maxKSTunnelsFile)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r ksTunnelsRecord
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%s: trailing data", p)
	}
	if r.Version != ksTunnelsVersion {
		return nil, fmt.Errorf("%s: unsupported version %d", p, r.Version)
	}
	for _, t := range r.Tunnels {
		if !validName(t.Name) {
			return nil, fmt.Errorf("%s: invalid tunnel name %q", p, t.Name)
		}
	}
	return r.Tunnels, nil
}

// removeKillSwitchTunnels deletes the record.
func (s *store) removeKillSwitchTunnels() error {
	err := os.Remove(filepath.Join(s.dir, ksTunnelsFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
