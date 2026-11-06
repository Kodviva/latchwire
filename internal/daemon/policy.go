package daemon

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Kodviva/latchwire/internal/config"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
	"github.com/Kodviva/latchwire/internal/netmon"
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
// the store as <name>.policy (JSON, 0600, written atomically); a tunnel
// without one gets defaultPolicy.
type Policy struct {
	// KillSwitch is auto (also when empty), on or off.
	KillSwitch string `json:"kill_switch,omitempty"`
	// AutoConnect connects the tunnel, while it is disconnected, when the
	// agent of a user who may connect it reports its YubiKey: at login
	// (agent.register) or when the card is inserted.
	AutoConnect bool `json:"auto_connect,omitempty"`
	// OnDemand connects the tunnel on networks not in TrustedNetworks.
	OnDemand bool `json:"on_demand,omitempty"`
	// TrustedNetworks are network IDs (netmon.NetworkID); never "unknown"
	// or "none" (P10).
	TrustedNetworks []string `json:"trusted_networks,omitempty"`
	// AllowedUsers are the uids that may connect the tunnel besides the
	// administrators (R19 still applies to them). Empty: administrators
	// only.
	AllowedUsers []uint32 `json:"allowed_users,omitempty"`
}

const (
	policyExt = ".policy"
	// maxPolicyFile bounds what is read from a policy file.
	maxPolicyFile = 64 << 10
	// maxPolicyList bounds TrustedNetworks and AllowedUsers (far below what
	// maxPolicyFile holds).
	maxPolicyList = 256
)

func defaultPolicy() Policy { return Policy{KillSwitch: KillSwitchAuto} }

// failClosedPolicy stands in for a policy file that cannot be used: the
// kill switch is on, so a damaged file never opens a leak; nothing happens
// automatically and only administrators may connect.
func failClosedPolicy() Policy { return Policy{KillSwitch: KillSwitchOn} }

// allows reports whether uid is one of the allowed users.
func (p Policy) allows(uid uint32) bool { return slices.Contains(p.AllowedUsers, uid) }

// validate checks the values of p (KillSwitch already normalized).
func (p Policy) validate() error {
	switch p.KillSwitch {
	case KillSwitchAuto, KillSwitchOn, KillSwitchOff:
	default:
		return fmt.Errorf(msg.PolicyKillSwitchValueFmt, p.KillSwitch)
	}
	if len(p.TrustedNetworks) > maxPolicyList || len(p.AllowedUsers) > maxPolicyList {
		return fmt.Errorf(msg.PolicyListTooLongFmt, maxPolicyList)
	}
	for _, id := range p.TrustedNetworks {
		if err := ValidTrustedNetwork(id); err != nil {
			return err
		}
	}
	return nil
}

// ValidTrustedNetwork checks that id can be a trusted network: a network
// ID as netmon.NetworkID makes it (16 lowercase hex digits). "unknown" and
// "none" name no particular network and are never trusted (P10).
func ValidTrustedNetwork(id string) error {
	if id == netmon.UnknownNetwork || id == netmon.NoNetwork {
		return fmt.Errorf(msg.PolicyUntrustableNetworkFmt, id)
	}
	if len(id) != 16 || strings.Trim(id, "0123456789abcdef") != "" {
		return fmt.Errorf(msg.PolicyBadNetworkIDFmt, id)
	}
	return nil
}

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
	case writableByOthers(fi):
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
	if pol.KillSwitch == "" {
		pol.KillSwitch = KillSwitchAuto
	}
	if err := pol.validate(); err != nil {
		return Policy{}, fmt.Errorf("%s: %w", p, err)
	}
	return pol, nil
}

// savePolicy replaces name's policy (0600, temporary file, fsync, rename).
func (s *store) savePolicy(name string, p Policy) error {
	if !validName(name) {
		return errors.New("invalid name")
	}
	if p.KillSwitch == "" {
		p.KillSwitch = KillSwitchAuto
	}
	if err := p.validate(); err != nil {
		return err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return s.writeAtomic(name+policyExt, string(b))
}

// hasPolicy reports whether name has a policy file (of whatever content).
func (s *store) hasPolicy(name string) bool {
	_, err := os.Lstat(filepath.Join(s.dir, name+policyExt))
	return !errors.Is(err, os.ErrNotExist)
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

// getPolicy is tunnel.policy.get: the policy in effect for the tunnel (the
// fail-closed one when its file is unusable).
func (m *Manager) getPolicy(name string) (ipc.TunnelPolicy, error) {
	m.mu.Lock()
	t := m.tunnels[name]
	m.mu.Unlock()
	if t == nil {
		return ipc.TunnelPolicy{}, errNotFound
	}
	return m.policyStatus(t, m.store.policyFor(name)), nil
}

// setPolicy is tunnel.policy.set (administrators only): it applies req to
// the tunnel's policy file and returns the new policy. A file that cannot
// be used is replaced, starting from the fail-closed policy. On-demand and
// the trusted networks are evaluated at once; AutoConnect counts from the
// next agent report or connect; the
// kill switch from the tunnel's next connect. A user no longer allowed loses
// the tunnel at once: a binding of that user that no administrator made is
// taken down (P20).
func (m *Manager) setPolicy(req ipc.TunnelPolicySet) (ipc.TunnelPolicy, error) {
	m.polMu.Lock()
	defer m.polMu.Unlock()
	m.mu.Lock()
	t := m.tunnels[req.Name]
	m.mu.Unlock()
	if t == nil {
		return ipc.TunnelPolicy{}, errNotFound
	}
	pol, err := m.store.loadPolicy(req.Name)
	if err != nil {
		log.Printf("daemon: tunnel %s: replacing the unusable policy (%v), starting from the fail-closed one", req.Name, err)
		pol = failClosedPolicy()
	}
	if req.KillSwitch != "" {
		pol.KillSwitch = req.KillSwitch
	}
	if req.AutoConnect != nil {
		pol.AutoConnect = *req.AutoConnect
	}
	if req.OnDemand != nil {
		pol.OnDemand = *req.OnDemand
	}
	pol.TrustedNetworks = editList(pol.TrustedNetworks, req.Trust, req.Untrust)
	pol.AllowedUsers = editList(pol.AllowedUsers, req.Allow, req.Deny)
	if err := pol.validate(); err != nil {
		return ipc.TunnelPolicy{}, &ipc.Error{Code: ipc.CodeBadRequest, Message: fmt.Sprintf(msg.DaemonBadPolicyFmt, err)}
	}
	if err := m.store.savePolicy(req.Name, pol); err != nil {
		log.Printf("daemon: store %s policy: %v", req.Name, err)
		return ipc.TunnelPolicy{}, &ipc.Error{Code: ipc.CodeInternal, Message: fmt.Sprintf(msg.DaemonPolicyStoreFailedFmt, err)}
	}
	log.Printf("daemon: tunnel %s: policy set: %+v", req.Name, pol)
	m.kickOnDemand() // on-demand and the trusted networks count at once
	blocking := m.revoke(t, pol)
	st := m.policyStatus(t, pol)
	st.RevokedBlocking = blocking
	return st, nil
}

// revoke takes t from its user when it is bound (connecting, connected,
// waiting for its card) to a user that pol no longer allows, or failed
// (error) while bound to that user, unless an administrator made the
// binding or the user is an administrator. m.polMu is held, so no connect
// can bind t under the old policy meanwhile (see connect). It reports
// whether t was left blocking.
//
// A tunnel whose kill switch is on (as installed: t.policy) is not
// released (P21): it loses its key and user (unbound, as a restart restores
// an unbound tunnel) and keeps blocking, in card_removed, or in error when
// it had failed; the denied user's card reconnects nothing, and only an
// administrator's down lifts it. The kill switch record follows (no key,
// no user), so a restart restores it unbound too. Any other tunnel is taken
// down to disconnected.
func (m *Manager) revoke(t *tunnel, pol Policy) (blocking bool) {
	held := func(t *tunnel) bool { // under Manager.mu
		return t.hasRef && (t.bound() || t.state == StateError)
	}
	m.mu.Lock()
	uid := t.uid
	cand := held(t) && !t.adminBound && !pol.allows(uid)
	m.mu.Unlock()
	if !cand || m.admin(uid) {
		return false
	}
	state := StateDisconnected
	cond := func(t *tunnel) bool { // under Manager.mu, with the teardown
		if !held(t) || t.adminBound || t.uid != uid {
			return false
		}
		if t.policy.armed(t.cfg) {
			state = StateCardRemoved
			if t.state == StateError {
				state = StateError
			}
			t.hasRef, t.uid, t.adminBound = false, 0, false
		}
		return true
	}
	// teardown reads state after cond ran.
	if !m.teardownTo(t, &state, cond) {
		return false
	}
	if state != StateDisconnected {
		log.Printf("daemon: tunnel %s: uid %d is no longer an allowed user; tunnel down (%s) and unbound, its kill switch keeps blocking until an administrator takes it down", t.name, uid, state)
		return true
	}
	log.Printf("daemon: tunnel %s: uid %d is no longer an allowed user, tunnel down", t.name, uid)
	return false
}

// editList returns list with add added and then remove removed, sorted and
// without duplicates (nil when empty).
func editList[T cmp.Ordered](list, add, remove []T) []T {
	out := append(slices.Clone(list), add...)
	out = slices.DeleteFunc(out, func(v T) bool { return slices.Contains(remove, v) })
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// policyStatus is p, t's policy file, as tunnel.policy.get and
// tunnel.policy.set report it. While t is not disconnected its kill switch
// follows the policy read at its connect; when that setting differs from
// p's, it is reported as KillSwitchInEffect.
func (m *Manager) policyStatus(t *tunnel, p Policy) ipc.TunnelPolicy {
	st := ipc.TunnelPolicy{Name: t.name, KillSwitch: p.KillSwitch, AutoConnect: p.AutoConnect, OnDemand: p.OnDemand,
		TrustedNetworks: slices.Clone(p.TrustedNetworks), AllowedUsers: slices.Clone(p.AllowedUsers)}
	m.mu.Lock()
	if t.state != StateDisconnected && t.policy.KillSwitch != p.KillSwitch {
		st.KillSwitchInEffect = t.policy.KillSwitch
	}
	m.mu.Unlock()
	return st
}
