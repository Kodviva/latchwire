package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/Kodviva/latchwire/internal/config"
)

// Kill switch policies (Policy.KillSwitch).
const (
	// KillSwitchAuto turns the kill switch on for a tunnel with exactly
	// one peer whose AllowedIPs hold 0.0.0.0/0 or ::/0 (the
	// wireguard-windows rule): a tunnel meant to carry everything.
	KillSwitchAuto = "auto"
	KillSwitchOn   = "on"
	KillSwitchOff  = "off"
)

// Policy is what a tunnel may do beyond its configuration. It is kept in
// the store as <name>.policy (JSON, 0600); a tunnel without one gets
// defaultPolicy.
type Policy struct {
	// KillSwitch is auto (also when empty), on or off.
	KillSwitch string `json:"kill_switch,omitempty"`
}

const (
	policyExt = ".policy"
	// maxPolicyFile bounds what is read from a policy file.
	maxPolicyFile = 64 << 10
)

func defaultPolicy() Policy { return Policy{KillSwitch: KillSwitchAuto} }

// failClosedPolicy stands in for a policy file that cannot be used: the
// kill switch is on, so a damaged file never opens a leak.
func failClosedPolicy() Policy { return Policy{KillSwitch: KillSwitchOn} }

// armed reports whether p turns the kill switch on for cfg.
func (p Policy) armed(cfg *config.Tunnel) bool {
	switch p.KillSwitch {
	case KillSwitchOn:
		return true
	case KillSwitchOff:
		return false
	}
	if len(cfg.Peers) != 1 {
		return false
	}
	for _, a := range cfg.Peers[0].AllowedIPs {
		if a.Bits() == 0 {
			return true
		}
	}
	return false
}

// loadPolicy reads name's policy. A missing file is the default policy; a
// file that is not a regular file, is writable by group or others, is too
// large, or does not decode exactly into a Policy with known values is an
// error.
func (s *store) loadPolicy(name string) (Policy, error) {
	if !validName(name) {
		return Policy{}, errors.New("invalid name")
	}
	p := filepath.Join(s.dir, name+policyExt)
	fi, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return defaultPolicy(), nil
	}
	if err != nil {
		return Policy{}, err
	}
	switch {
	case !fi.Mode().IsRegular():
		return Policy{}, fmt.Errorf("%s: not a regular file", p)
	case fi.Mode().Perm()&0o022 != 0:
		return Policy{}, fmt.Errorf("%s: writable by group or others (mode %v)", p, fi.Mode().Perm())
	case fi.Size() > maxPolicyFile:
		return Policy{}, fmt.Errorf("%s: larger than %d bytes", p, maxPolicyFile)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return Policy{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var pol Policy
	if err := dec.Decode(&pol); err != nil {
		return Policy{}, fmt.Errorf("%s: %w", p, err)
	}
	if dec.More() {
		return Policy{}, fmt.Errorf("%s: trailing data", p)
	}
	switch pol.KillSwitch {
	case "":
		pol.KillSwitch = KillSwitchAuto
	case KillSwitchAuto, KillSwitchOn, KillSwitchOff:
	default:
		return Policy{}, fmt.Errorf("%s: kill_switch must be auto, on or off, not %q", p, pol.KillSwitch)
	}
	return pol, nil
}

// policyFor reads name's policy; one that cannot be used is logged and
// replaced by the fail-closed policy.
func (s *store) policyFor(name string) Policy {
	p, err := s.loadPolicy(name)
	if err != nil {
		log.Printf("daemon: tunnel %s: unusable policy, the kill switch is on: %v", name, err)
		return failClosedPolicy()
	}
	return p
}

// removePolicy deletes name's policy.
func (s *store) removePolicy(name string) error {
	if !validName(name) {
		return errors.New("invalid name")
	}
	err := os.Remove(filepath.Join(s.dir, name+policyExt))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
