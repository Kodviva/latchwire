package ipc

import (
	"encoding/json"
	"time"
)

// Methods of the assist feature: a local agent (the MCP server) drives setup
// through the daemon. assist.call goes from the MCP server to the daemon;
// assist.grant, assist.revoke, assist.activity, card.list and card.keygen
// go from the desktop agent to the daemon or, for the card methods, from the
// daemon to the agent; assist.approve and assist.notice go from the daemon
// to the agent.
const (
	MethodAssistCall     = "assist.call"     // mcp -> daemon
	MethodAssistGrant    = "assist.grant"    // desktop agent -> daemon
	MethodAssistRevoke   = "assist.revoke"   // desktop agent -> daemon
	MethodAssistActivity = "assist.activity" // desktop agent -> daemon
	MethodCardList       = "card.list"       // daemon -> agent
	MethodCardKeygen     = "card.keygen"     // daemon -> agent
	MethodAssistApprove  = "assist.approve"  // daemon -> agent
	MethodAssistNotice   = "assist.notice"   // daemon -> agent
)

// CapAssist is the capability an agent reports in AgentRegister.Caps when it
// can show the approval window and run card operations.
const CapAssist = "assist"

// Permission groups of assist access.
const (
	GroupKeys    = "keys"    // create_key
	GroupTunnels = "tunnels" // add_tunnel
	GroupConnect = "connect" // connect, disconnect
)

// Error codes of the assist methods.
const (
	CodeAccessOff = "access_off" // access is off or has expired
	CodeDenied    = "denied"     // the user refused the action
	CodeNoApp     = "no_app"     // no agent can show the approval window
	CodeCancelled = "cancelled"  // the action was cancelled
)

// AssistCall is the params of assist.call: one tool call of an MCP client.
type AssistCall struct {
	Client string          `json:"client"`
	Tool   string          `json:"tool"`
	Args   json.RawMessage `json:"args,omitempty"`
}

// AssistResult is the result of assist.call. Data is the tool's JSON result,
// Summary a one-line description for the activity list.
type AssistResult struct {
	Data    json.RawMessage `json:"data,omitempty"`
	Summary string          `json:"summary,omitempty"`
}

// AssistGrant is the params of assist.grant: opens access for Minutes
// minutes (0 = until the app closes) for the given groups.
type AssistGrant struct {
	Minutes int      `json:"minutes"`
	Groups  []string `json:"groups"`
}

// ActivityEntry is one tool call in the activity list. It never carries a
// PIN, PUK, management key, private key or PSK.
type ActivityEntry struct {
	Time    time.Time `json:"time"`
	Client  string    `json:"client"`
	Tool    string    `json:"tool"`
	Summary string    `json:"summary"`
	Result  string    `json:"result"`
}

// AssistActivity is the result of assist.activity.
type AssistActivity struct {
	Entries []ActivityEntry `json:"entries"`
}

// ApproveRequest is the params of assist.approve. Fresh says the card still
// has its factory PIN and PUK, which the action will change.
type ApproveRequest struct {
	Client  string `json:"client"`
	Tool    string `json:"tool"`
	Summary string `json:"summary"`
	Fresh   bool   `json:"fresh,omitempty"`
}

// ApproveResult is the result of assist.approve.
type ApproveResult struct {
	Allow bool `json:"allow"`
}

// CardEntry is one card in the card.list result. Keys are KeyRef strings;
// Fresh says the PIN is still the factory default.
type CardEntry struct {
	Serial    uint32   `json:"serial"`
	Firmware  string   `json:"firmware"`
	Supported bool     `json:"supported"`
	Fresh     bool     `json:"fresh,omitempty"`
	FreeSlots []uint8  `json:"freeSlots,omitempty"`
	Keys      []string `json:"keys,omitempty"`
}

// CardListResult is the result of card.list.
type CardListResult struct {
	Cards []CardEntry `json:"cards"`
}

// KeygenRequest is the params of card.keygen.
type KeygenRequest struct {
	Serial uint32 `json:"serial"`
	Slot   uint8  `json:"slot"`
}

// KeygenResult is the result of card.keygen: the new key's KeyRef and its
// public key (standard base64).
type KeygenResult struct {
	Ref    string `json:"ref"`
	Public string `json:"public"`
}

// AssistNotice is the params of assist.notice: the guided step the agent
// should show (a desktop.StepID value).
type AssistNotice struct {
	Step string `json:"step"`
}
