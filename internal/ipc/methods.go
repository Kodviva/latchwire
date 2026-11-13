package ipc

import "slices"

// Method names. Direction is part of the name's prefix: agent.* go from the
// per-user agent to the daemon, key.* from the daemon to the agent, and
// tunnel.* and network.* from the CLI to the daemon.
const (
	MethodAgentRegister = "agent.register"
	MethodAgentEvent    = "agent.event"

	MethodKeyPublic = "key.public"
	MethodKeyX25519 = "key.x25519"

	MethodTunnelAdd        = "tunnel.add"
	MethodTunnelRemove     = "tunnel.remove"
	MethodTunnelConnect    = "tunnel.connect"
	MethodTunnelDisconnect = "tunnel.disconnect"
	MethodTunnelStatus     = "tunnel.status"
	MethodTunnelPolicyGet  = "tunnel.policy.get"
	MethodTunnelPolicySet  = "tunnel.policy.set"

	MethodNetworkCurrent = "network.current"

	// Windows only: the mapping of SIDs to uids (see UserTable).
	MethodUserID  = "user.id"
	MethodUserSID = "user.sid"
)

// Error codes carried in Error.Code.
const (
	CodeForbidden   = "forbidden"
	CodeNotFound    = "not_found"
	CodeInternal    = "internal"
	CodeUnavailable = "unavailable"

	// Codes the agent returns for key.public and key.x25519, so the daemon
	// can tell PIN problems from a missing card.
	CodeBadRequest    = "bad_request"     // malformed ref or peer
	CodeWrongPIN      = "wrong_pin"       // keyprovider.PINError
	CodePINBlocked    = "pin_blocked"     // keyprovider.ErrPINBlocked
	CodePINRequired   = "pin_required"    // keyprovider.ErrPINRequired (not entered, cancelled)
	CodeLowOrderPoint = "low_order_point" // keyprovider.ErrLowOrderPoint
)

// Event types for AgentEvent.Type.
const (
	EventCardInserted = "card_inserted"
	EventCardRemoved  = "card_removed"
	EventPINReady     = "pin_ready"
)

// AgentRegister is the params of agent.register: the card serials the agent
// currently sees.
type AgentRegister struct {
	Serials []uint32 `json:"serials"`
}

// AgentEvent is the params of agent.event.
type AgentEvent struct {
	Type   string `json:"type"`
	Serial uint32 `json:"serial"`
}

// KeyRequest is the params of key.public (Peer empty) and key.x25519. Peer is
// the standard base64 encoding of a 32-byte X25519 public key. Deadline is
// optional: unix milliseconds after which the caller no longer waits for the
// answer (0 = none); the agent then gives up instead of asking for a PIN.
type KeyRequest struct {
	Ref      string `json:"ref"`
	Peer     string `json:"peer,omitempty"`
	Deadline int64  `json:"deadline,omitempty"`
}

// KeyPublicResult is the result of key.public; Public is standard base64 of
// 32 bytes.
type KeyPublicResult struct {
	Public string `json:"public"`
}

// KeyX25519Result is the result of key.x25519; Shared is standard base64 of
// 32 bytes. It is secret: never log a message that carries it.
type KeyX25519Result struct {
	Shared string `json:"shared"`
}

// TunnelAdd is the params of tunnel.add. Owner is the user the tunnel is
// added for (the CLI sends SUDO_UID): the only user besides the
// administrators who may connect it. 0 leaves it to the administrators.
type TunnelAdd struct {
	Name   string `json:"name"`
	Config string `json:"config"`
	Owner  uint32 `json:"owner,omitempty"`
}

// TunnelName is the params of tunnel.remove, tunnel.connect and
// tunnel.disconnect.
type TunnelName struct {
	Name string `json:"name"`
}

// TunnelPolicy is the result of tunnel.policy.get and tunnel.policy.set: a
// tunnel's policy. KillSwitch is auto, on or off. AutoConnect connects the
// tunnel when the agent of an allowed user reports its YubiKey (at login or
// when the card is inserted). OnDemand and TrustedNetworks (network IDs)
// drive the automatic connect on untrusted networks. AllowedUsers are the
// uids that may connect the tunnel besides the administrators.
// KillSwitchInEffect, when set, is the kill switch setting the tunnel still
// runs with (it is not disconnected): KillSwitch applies at its next
// connect. RevokedBlocking (tunnel.policy.set) says that the change took
// the tunnel from a user no longer allowed and its kill switch keeps
// blocking until an administrator takes it down.
type TunnelPolicy struct {
	Name               string   `json:"name"`
	KillSwitch         string   `json:"killSwitch"`
	AutoConnect        bool     `json:"autoConnect,omitempty"`
	OnDemand           bool     `json:"onDemand,omitempty"`
	TrustedNetworks    []string `json:"trustedNetworks,omitempty"`
	AllowedUsers       []uint32 `json:"allowedUsers,omitempty"`
	KillSwitchInEffect string   `json:"killSwitchInEffect,omitempty"`
	RevokedBlocking    bool     `json:"revokedBlocking,omitempty"`
}

// TunnelPolicySet is the params of tunnel.policy.set: the changes to make
// to a tunnel's policy. Empty or nil fields leave the policy as it is.
// Trust and Allow are added first, then Untrust and Deny removed.
type TunnelPolicySet struct {
	Name        string   `json:"name"`
	KillSwitch  string   `json:"killSwitch,omitempty"`
	AutoConnect *bool    `json:"autoConnect,omitempty"`
	OnDemand    *bool    `json:"onDemand,omitempty"`
	Trust       []string `json:"trust,omitempty"`
	Untrust     []string `json:"untrust,omitempty"`
	Allow       []uint32 `json:"allow,omitempty"`
	Deny        []uint32 `json:"deny,omitempty"`
}

// UserInfo is the params and the result of user.id (SID set) and user.sid
// (UID set): one entry of the daemon's user table.
type UserInfo struct {
	UID uint32 `json:"uid,omitempty"`
	SID string `json:"sid,omitempty"`
}

// NetworkCurrent is the result of network.current: the ID of the network
// the machine is on (netmon.NetworkID), "none" without a network, or
// "unknown" when its gateway cannot be identified. Neither of the last two
// can be trusted.
type NetworkCurrent struct {
	ID string `json:"id"`
}

// TunnelStatus is one element of the tunnel.status result. The fields after
// LastHandshake were added later and are omitted when empty, so an older
// CLI or daemon reads the answer as before.
//
// Interface, MTU and DNS describe the applied network configuration and are
// set only while the tunnel is connected. DNS is one of the TunnelDNS
// values. FullTunnel says whether the configuration routes everything
// (0.0.0.0/0 or ::/0). KillSwitch is one of the KillSwitch values. Warning,
// when set, is something about the applied configuration that the user
// should act on (shared or overridden DNS, DNS not applied, no reverse-path
// filter); several are joined with "; ".
type TunnelStatus struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	Identity string `json:"identity"`
	// Keys are the tunnel's configured hardware keys (KeyRef), first the
	// main card then its backups, so a disconnected tunnel can name the
	// card it would use. Older daemons leave it empty.
	Keys          []string `json:"keys,omitempty"`
	LastHandshake string   `json:"lastHandshake"`
	Interface     string   `json:"interface,omitempty"`
	MTU           int      `json:"mtu,omitempty"`
	FullTunnel    bool     `json:"fullTunnel,omitempty"`
	DNS           string   `json:"dns,omitempty"`
	KillSwitch    string   `json:"killSwitch,omitempty"`
	Warning       string   `json:"warning,omitempty"`
}

// Equal reports whether s and o are the same status.
func (s TunnelStatus) Equal(o TunnelStatus) bool {
	return s.Name == o.Name && s.State == o.State && s.Identity == o.Identity &&
		slices.Equal(s.Keys, o.Keys) && s.LastHandshake == o.LastHandshake &&
		s.Interface == o.Interface && s.MTU == o.MTU && s.FullTunnel == o.FullTunnel &&
		s.DNS == o.DNS && s.KillSwitch == o.KillSwitch && s.Warning == o.Warning
}

// TunnelStatus.DNS values: how the tunnel's DNS servers take part in name
// resolution.
const (
	DNSStatusPrimary    = "primary"    // they answer every name
	DNSStatusScoped     = "scoped"     // they answer the search domains only
	DNSStatusNone       = "none"       // the tunnel has no DNS servers
	DNSStatusIgnored    = "ignored"    // it has some, but another tunnel's answer (or scoping is unsupported)
	DNSStatusShared     = "shared"     // primary, but other interfaces' servers stay in the list (classic resolvconf)
	DNSStatusOverridden = "overridden" // primary, but servers set by hand take precedence (macOS)
	DNSStatusBusy       = "busy"       // primary wanted, but another tunnel holds it: not applied
)

// TunnelStatus.KillSwitch values.
const (
	KillSwitchStatusOff      = "off"      // not on for this tunnel, or the tunnel is down
	KillSwitchStatusArmed    = "armed"    // connected: only the tunnels' traffic passes
	KillSwitchStatusBlocking = "blocking" // not connected (connecting, card removed, error): everything is blocked
)
