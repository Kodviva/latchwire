package ipc

import (
	"bytes"
	"encoding/json"
	"strconv"
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
	MethodAssistAbort    = "assist.abort"    // daemon -> agent
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
// ID names the request for assist.abort.
type ApproveRequest struct {
	ID      string `json:"id,omitempty"`
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
	FreeSlots Slots    `json:"freeSlots,omitempty"`
	Keys      []string `json:"keys,omitempty"`
}

// Slots is a list of PIV slot numbers. On the wire it is a JSON array of
// numbers (a []uint8 would be a base64 string, which agents cannot read).
// Decoding also accepts that old base64 string: an older app may still send it.
type Slots []uint8

// MarshalJSON writes the slots as an array of numbers.
func (s Slots) MarshalJSON() ([]byte, error) {
	b := make([]byte, 0, 4*len(s)+2)
	b = append(b, '[')
	for i, v := range s {
		if i > 0 {
			b = append(b, ',')
		}
		b = strconv.AppendUint(b, uint64(v), 10)
	}
	return append(b, ']'), nil
}

// UnmarshalJSON reads an array of numbers or a base64 string.
func (s *Slots) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if string(b) == "null" {
		*s = nil
		return nil
	}
	if len(b) > 0 && b[0] == '"' {
		var raw []byte // encoding/json decodes a base64 string into []byte
		if err := json.Unmarshal(b, &raw); err != nil {
			return err
		}
		*s = Slots(raw)
		return nil
	}
	var nums []uint8
	if err := json.Unmarshal(b, &nums); err != nil {
		return err
	}
	*s = Slots(nums)
	return nil
}

// CardListResult is the result of card.list.
type CardListResult struct {
	Cards []CardEntry `json:"cards"`
}

// KeygenRequest is the params of card.keygen. ID names the request for
// assist.abort.
type KeygenRequest struct {
	ID     string `json:"id,omitempty"`
	Serial uint32 `json:"serial"`
	Slot   uint8  `json:"slot"`
}

// KeygenResult is the result of card.keygen: the new key's KeyRef and its
// public key (standard base64).
type KeygenResult struct {
	Ref    string `json:"ref"`
	Public string `json:"public"`
}

// AssistAbort is the params of assist.abort: the daemon stopped waiting for
// the assist.approve or card.keygen request ID (timeout, access closed, the
// caller gone), so the app should close its window or give up the key.
type AssistAbort struct {
	ID string `json:"id"`
}

// AssistNotice is the params of assist.notice: the guided step the agent
// should show (a desktop.StepID value).
type AssistNotice struct {
	Step string `json:"step"`
}

// Tools of assist.call. ToolCheck is the access check the MCP server makes
// before it computes a read-only tool (peer_block, server_guide) itself,
// and before it reports bad arguments of create_key or validates add_tunnel's
// form (recorded as "checked").
const (
	ToolCheck         = "check"
	ToolStatus        = "status"
	ToolSetupProgress = "setup_progress"
	ToolPeerBlock     = "peer_block"
	ToolServerGuide   = "server_guide"
	ToolCreateKey     = "create_key"
	ToolAddTunnel     = "add_tunnel"
	ToolConnect       = "connect"
	ToolDisconnect    = "disconnect"
)

// AssistCheckArgs is the Args of the check tool: the read-only tool the
// MCP server is about to compute, or create_key or add_tunnel.
type AssistCheckArgs struct {
	Tool string `json:"tool"`
}

// AssistProgressArgs is the Args of setup_progress. Path is "invited" or
// "owner" (default "owner"); Tunnel, if set, is the tunnel to look at.
type AssistProgressArgs struct {
	Path   string `json:"path,omitempty"`
	Tunnel string `json:"tunnel,omitempty"`
}

// AssistKeyArgs is the Args of create_key. Slot 0 takes the card's first
// free slot.
type AssistKeyArgs struct {
	Serial uint32 `json:"serial"`
	Slot   uint8  `json:"slot,omitempty"`
}

// AssistTunnelArgs is the Args of add_tunnel: the tunnel's name and its
// configuration text.
type AssistTunnelArgs struct {
	Name   string `json:"name"`
	Config string `json:"config"`
}

// AssistStatus is the Data of the status tool. CardsUnavailable says the
// cards could not be listed (the app is not open).
type AssistStatus struct {
	Tunnels          []TunnelStatus `json:"tunnels"`
	Cards            []CardEntry    `json:"cards"`
	CardsUnavailable bool           `json:"cardsUnavailable,omitempty"`
}

// States of a setup step in AssistProgress.
const (
	StepDone    = "done"
	StepPending = "pending"
	StepUnknown = "unknown" // the daemon cannot see whether it was done
)

// AssistStep is one roadmap step (a desktop.StepID value) and its state.
type AssistStep struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

// AssistProgress is the Data of setup_progress: the roadmap of Path, in
// order.
type AssistProgress struct {
	Path   string       `json:"path"`
	Tunnel string       `json:"tunnel,omitempty"`
	Steps  []AssistStep `json:"steps"`
}
