package ipc

// Method names. Direction is part of the name's prefix: agent.* go from the
// per-user agent to the daemon, key.* from the daemon to the agent, and
// tunnel.* from the CLI to the daemon.
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
)

// Error codes carried in Error.Code.
const (
	CodeForbidden   = "forbidden"
	CodeNotFound    = "not_found"
	CodeInternal    = "internal"
	CodeUnavailable = "unavailable"
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
// the standard base64 encoding of a 32-byte X25519 public key.
type KeyRequest struct {
	Ref  string `json:"ref"`
	Peer string `json:"peer,omitempty"`
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

// TunnelAdd is the params of tunnel.add.
type TunnelAdd struct {
	Name   string `json:"name"`
	Config string `json:"config"`
}

// TunnelName is the params of tunnel.remove, tunnel.connect and
// tunnel.disconnect.
type TunnelName struct {
	Name string `json:"name"`
}

// TunnelStatus is one element of the tunnel.status result.
type TunnelStatus struct {
	Name          string `json:"name"`
	State         string `json:"state"`
	Identity      string `json:"identity"`
	LastHandshake string `json:"lastHandshake"`
}
