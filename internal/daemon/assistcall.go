package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Kodviva/latchwire/internal/config"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/msg"
)

// Bounds of the card operations an agent tool runs through the app. A list
// is quick; a new key may wait for the person to type the PIN and PUK (and
// secure a factory-fresh card). Variables so tests can shorten them.
var (
	cardListTimeout   = 10 * time.Second
	cardKeygenTimeout = 3 * time.Minute
)

// The roadmap steps (desktop.StepID values; this package cannot import
// internal/desktop, which imports it).
const (
	stepCardReady     = "card_ready"
	stepKeyCreated    = "key_created"
	stepBackupOffered = "backup_offered"
	stepPubkeyShared  = "pubkey_shared"
	stepServerAdded   = "server_added"
	stepServerInfo    = "server_info_entered"
	stepConnected     = "connected"
)

// AssistSteps returns the roadmap of path ("invited" or "owner") as
// desktop.Roadmap has it in guided mode, or nil for another path. The
// desktop package tests that both agree.
func AssistSteps(path string) []string {
	switch path {
	case "invited":
		return []string{stepCardReady, stepKeyCreated, stepBackupOffered, stepPubkeyShared, stepServerInfo, stepConnected}
	case "owner":
		return []string{stepCardReady, stepKeyCreated, stepBackupOffered, stepServerAdded, stepServerInfo, stepConnected}
	}
	return nil
}

var (
	errUnknownTool  = &ipc.Error{Code: ipc.CodeBadRequest, Message: msg.AssistUnknownTool}
	errKeygenResult = &ipc.Error{Code: ipc.CodeInternal, Message: msg.AssistKeygenFailed}
)

// toolGroup returns the permission group of tool ("" for a read-only one)
// and whether the daemon runs it.
func toolGroup(tool string) (string, bool) {
	switch tool {
	case ipc.ToolStatus, ipc.ToolSetupProgress, ipc.ToolPeerBlock, ipc.ToolServerGuide:
		return "", true
	case ipc.ToolCreateKey:
		return ipc.GroupKeys, true
	case ipc.ToolAddTunnel:
		return ipc.GroupTunnels, true
	case ipc.ToolConnect, ipc.ToolDisconnect:
		return ipc.GroupConnect, true
	}
	return "", false
}

// assistCall runs one agent tool for uid behind the access check, the
// approval and the activity log. c is the caller's connection (nil in
// tests). Every call is recorded with a summary the daemon builds itself:
// the arguments are never echoed, so no PSK, PIN or key reaches the log,
// the activity list or the approval window.
func (m *Manager) assistCall(ctx context.Context, c *ipc.Conn, uid uint32, p ipc.AssistCall) (ipc.AssistResult, error) {
	var elevated uint32
	if c != nil {
		m.markAssistCaller(c)
		elevated = c.ElevatedUser()
	}
	name := p.Tool
	checkOnly := false // an access check of add_tunnel, which is not run
	if name == ipc.ToolCheck {
		// The MCP server computes peer_block and server_guide itself and
		// only asks whether it may. Before it validates add_tunnel's form
		// it asks whether access and the tunnels group are on, so that
		// while they are off nothing else is said.
		var a ipc.AssistCheckArgs
		switch {
		case json.Unmarshal(p.Args, &a) != nil:
			name = ""
		case a.Tool == ipc.ToolPeerBlock || a.Tool == ipc.ToolServerGuide:
			name = a.Tool
		case a.Tool == ipc.ToolAddTunnel:
			name, checkOnly = a.Tool, true
		default:
			name = ""
		}
	}
	group, known := toolGroup(name)
	entry := ipc.ActivityEntry{Client: clientName(p.Client), Tool: name}
	if !known {
		entry.Tool = "unknown"
	}
	call := assistCall{m: m, ctx: ctx, uid: uid, elevated: elevated, client: entry.Client, tool: name, group: group}

	var (
		res ipc.AssistResult
		err error
	)
	// Access first, for every tool: while it is off nothing else is said.
	if err = m.assist.allowed(uid, group, m.assist.now()); err == nil {
		switch {
		case !known:
			err = errUnknownTool
		case !checkOnly:
			res, err = call.run(p.Args)
		}
	}
	entry.Summary = printable(res.Summary)
	entry.Result = activityResult(err)
	if checkOnly && err == nil {
		entry.Result = "checked"
	}
	m.assist.record(uid, entry)
	if err != nil {
		return ipc.AssistResult{}, err
	}
	return res, nil
}

// clientName is the MCP client's name as the activity list and the
// approval window show it: printable, at most 64 characters.
func clientName(s string) string {
	s = printable(s)
	if r := []rune(s); len(r) > 64 {
		s = string(r[:64])
	}
	if s == "" {
		return "unknown"
	}
	return s
}

// printable drops from s every rune that is not printable (control and
// format characters such as bidi overrides and zero-width ones, invalid
// UTF-8, separators other than the ASCII space), so text shown to the
// person reads as it is.
func printable(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == unicode.ReplacementChar || !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	return strings.TrimSpace(s)
}

// activityResult is the result column of the activity list for err.
func activityResult(err error) string {
	if err == nil {
		return "done"
	}
	var ie *ipc.Error
	if !errors.As(err, &ie) {
		return "error: " + ipc.CodeInternal
	}
	switch ie.Code {
	case ipc.CodeAccessOff, ipc.CodeDenied, ipc.CodeNoApp, ipc.CodeCancelled:
		return ie.Code
	}
	return "error: " + ie.Code
}

// assistCall is one tool call being run.
type assistCall struct {
	m        *Manager
	ctx      context.Context
	uid      uint32
	elevated uint32
	client   string
	tool     string
	group    string
}

func (a assistCall) run(args json.RawMessage) (ipc.AssistResult, error) {
	switch a.tool {
	case ipc.ToolPeerBlock, ipc.ToolServerGuide:
		return ipc.AssistResult{}, nil // the check passed
	case ipc.ToolStatus:
		return a.status()
	case ipc.ToolSetupProgress:
		return a.setupProgress(args)
	case ipc.ToolCreateKey:
		return a.createKey(args)
	case ipc.ToolAddTunnel:
		return a.addTunnel(args)
	case ipc.ToolConnect:
		return a.connect(args)
	case ipc.ToolDisconnect:
		return a.disconnect(args)
	}
	return ipc.AssistResult{}, errUnknownTool
}

func data(res *ipc.AssistResult, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	res.Data = b
	return nil
}

// cards lists the cards the app sees, within cardListTimeout.
func (a assistCall) cards() ([]ipc.CardEntry, error) {
	ctx, cancel := context.WithTimeout(a.ctx, cardListTimeout)
	defer cancel()
	cards, err := a.m.cardList(ctx, a.uid)
	if err != nil {
		log.Printf("daemon: assist: card.list for uid %d: %v", a.uid, err)
		if a.ctx.Err() != nil {
			return nil, errCancelled
		}
		return nil, userErr(err)
	}
	return cards, nil
}

// approved asks the app to approve the call and checks the call's group
// again afterwards: access may have closed or lost it while the window
// was open.
func (a assistCall) approved(summary string, fresh bool) error {
	r := ipc.ApproveRequest{Client: a.client, Tool: a.tool, Summary: printable(summary), Fresh: fresh}
	if err := a.m.approve(a.ctx, a.uid, r); err != nil {
		return err
	}
	return a.m.assist.allowed(a.uid, a.group, a.m.assist.now())
}

// act runs f, after the approval, under a context that ends with the
// caller's and with access (revoke, a new grant, the owner leaving), and
// says why f failed when either ended.
func (a assistCall) act(f func(ctx context.Context) error) error {
	pctx, release := a.m.assist.pending(a.uid)
	defer release()
	ctx, cancel := context.WithCancel(a.ctx)
	defer cancel()
	// cancel takes no lock: it may run under the assist mutex.
	stop := context.AfterFunc(pctx, cancel)
	defer stop()
	err := f(ctx)
	switch {
	case err == nil:
		return nil
	case pctx.Err() != nil:
		// As for a pending approval: access closing is a refusal.
		return errRevoked
	case a.ctx.Err() != nil:
		return errCancelled
	}
	return err
}

func (a assistCall) status() (ipc.AssistResult, error) {
	var res ipc.AssistResult
	ts, err := a.m.statuses("")
	if err != nil {
		return res, err
	}
	st := ipc.AssistStatus{Tunnels: ts, Cards: []ipc.CardEntry{}}
	if cards, err := a.cards(); err != nil {
		st.CardsUnavailable = true
	} else if cards != nil {
		st.Cards = cards
	}
	return res, data(&res, st)
}

// setupProgress reports the roadmap's steps from facts: a card plugged in,
// a Latchwire key on it, the tunnel defined, a handshake. A step the daemon
// sees is reported as it is, done or pending, whatever came later. A step
// it cannot see (backup_offered, pubkey_shared, server_added, and the card
// steps when the app is not open) is done when a later step it sees is
// done, else unknown.
func (a assistCall) setupProgress(args json.RawMessage) (ipc.AssistResult, error) {
	var res ipc.AssistResult
	var p ipc.AssistProgressArgs
	if len(args) > 0 && string(args) != "null" {
		if err := decode(args, &p); err != nil {
			return res, err
		}
	}
	if p.Path == "" {
		p.Path = "owner"
	}
	steps := AssistSteps(p.Path)
	if steps == nil || (p.Tunnel != "" && !validName(p.Tunnel)) {
		return res, errBadRequest
	}
	if p.Tunnel != "" {
		res.Summary = fmt.Sprintf(msg.AssistSummaryTunnelNameFmt, p.Tunnel)
	}

	seen := map[string]bool{} // the steps the daemon can see
	done := map[string]bool{}
	if cards, err := a.cards(); err == nil {
		seen[stepCardReady], seen[stepKeyCreated] = true, true
		for _, c := range cards {
			done[stepCardReady] = done[stepCardReady] || c.Supported
			done[stepKeyCreated] = done[stepKeyCreated] || (c.Supported && len(c.Keys) > 0)
		}
	}
	ts, err := a.m.statuses(p.Tunnel)
	if err != nil && !errors.Is(err, errNotFound) {
		return res, err
	}
	seen[stepServerInfo], seen[stepConnected] = true, true
	done[stepServerInfo] = len(ts) > 0
	for _, t := range ts {
		done[stepConnected] = done[stepConnected] || t.LastHandshake != ""
	}

	out := ipc.AssistProgress{Path: p.Path, Tunnel: p.Tunnel, Steps: make([]ipc.AssistStep, len(steps))}
	later := false // a later step is done
	for i := len(steps) - 1; i >= 0; i-- {
		id := steps[i]
		state := ipc.StepUnknown
		switch {
		case done[id]:
			state = ipc.StepDone
		case seen[id]:
			state = ipc.StepPending
		case later:
			state = ipc.StepDone
		}
		later = later || (seen[id] && done[id])
		out.Steps[i] = ipc.AssistStep{ID: id, State: state}
	}
	return res, data(&res, out)
}

func (a assistCall) createKey(args json.RawMessage) (ipc.AssistResult, error) {
	var res ipc.AssistResult
	var p ipc.AssistKeyArgs
	if err := decode(args, &p); err != nil {
		return res, err
	}
	if p.Serial == 0 || (p.Slot != 0 && (p.Slot < keyref.MinSlot || p.Slot > keyref.MaxSlot)) {
		return res, errBadRequest
	}
	cards, err := a.cards()
	if err != nil {
		return res, err
	}
	i := slices.IndexFunc(cards, func(c ipc.CardEntry) bool { return c.Serial == p.Serial && c.Supported })
	if i < 0 {
		return res, &ipc.Error{Code: ipc.CodeNotFound, Message: fmt.Sprintf(msg.AssistNoCardFmt, p.Serial)}
	}
	card := cards[i]
	slot := p.Slot
	switch {
	case slot == 0 && len(card.FreeSlots) == 0:
		return res, &ipc.Error{Code: ipc.CodeBadRequest, Message: msg.PIVNoFreeSlot}
	case slot == 0:
		slot = card.FreeSlots[0]
	case !slices.Contains(card.FreeSlots, slot):
		return res, &ipc.Error{Code: ipc.CodeBadRequest, Message: fmt.Sprintf(msg.AssistSlotNotFreeFmt, slot, p.Serial)}
	}
	res.Summary = fmt.Sprintf(msg.AssistSummaryKeyFmt, p.Serial, slot)
	if err := a.approved(res.Summary, card.Fresh); err != nil {
		return res, err
	}
	want := keyref.Ref{Serial: p.Serial, Slot: slot}
	var kr ipc.KeygenResult
	err = a.act(func(ctx context.Context) error {
		kctx, cancel := context.WithTimeout(ctx, cardKeygenTimeout)
		defer cancel()
		var err error
		if kr, err = a.m.cardKeygen(kctx, a.uid, p.Serial, slot); err != nil {
			log.Printf("daemon: assist: card.keygen %s for uid %d: %v", want, a.uid, err)
			return userErr(err)
		}
		return nil
	})
	if err != nil {
		return res, err
	}
	ref, rerr := keyref.Parse(kr.Ref)
	pub, perr := base64.StdEncoding.DecodeString(kr.Public)
	if rerr != nil || ref != want || perr != nil || len(pub) != 32 {
		log.Printf("daemon: assist: card.keygen %s for uid %d: the app's answer does not fit the request", want, a.uid)
		return res, errKeygenResult
	}
	a.m.notify(a.uid, stepKeyCreated)
	return res, data(&res, ipc.KeygenResult{Ref: ref.String(), Public: base64.StdEncoding.EncodeToString(pub)})
}

// tunnelSummary describes cfg without a key: its endpoints, allowed IPs,
// number of servers and whether it has a PSK. Each part is rendered from
// its parsed form; an endpoint whose host is neither an IP address nor a
// plain DNS name is refused, so nothing the agent wrote reaches the
// approval window as it is.
func tunnelSummary(name string, cfg *config.Tunnel) (string, error) {
	var endpoints, networks []string
	psk := false
	for _, p := range cfg.Peers {
		if p.Endpoint != "" {
			e, ok := endpointText(p.Endpoint)
			if !ok {
				return "", &ipc.Error{Code: ipc.CodeBadRequest, Message: fmt.Sprintf(msg.ConfigInvalidValueFmt, "Endpoint")}
			}
			if !slices.Contains(endpoints, e) {
				endpoints = append(endpoints, e)
			}
		}
		for _, n := range p.AllowedIPs {
			if s := n.String(); !slices.Contains(networks, s) {
				networks = append(networks, s)
			}
		}
		psk = psk || p.PresharedKey != nil
	}
	join := func(s []string) string {
		if len(s) == 0 {
			return "-"
		}
		return strings.Join(s, " ")
	}
	has := msg.AssistPSKNo
	if psk {
		has = msg.AssistPSKYes
	}
	return fmt.Sprintf(msg.AssistSummaryTunnelFmt, name, join(endpoints), join(networks), len(cfg.Peers), has), nil
}

// endpointText renders a configured endpoint (host:port) from its parts:
// an IP address without a zone, or a DNS name of letters, digits, hyphens
// and dots, and a port 1-65535.
func endpointText(e string) (string, bool) {
	host, port, err := net.SplitHostPort(e)
	if err != nil {
		return "", false
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return "", false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return "", false
		}
		return netip.AddrPortFrom(addr, uint16(n)).String(), true
	}
	if !dnsName(host) {
		return "", false
	}
	return net.JoinHostPort(strings.ToLower(host), strconv.FormatUint(n, 10)), true
}

// dnsName reports whether s is a DNS name of labels of 1-63 letters,
// digits and hyphens (not at either end), at most 253 characters.
func dnsName(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func (a assistCall) addTunnel(args json.RawMessage) (ipc.AssistResult, error) {
	var res ipc.AssistResult
	var p ipc.AssistTunnelArgs
	if err := decode(args, &p); err != nil {
		return res, err
	}
	if !validName(p.Name) {
		return res, &ipc.Error{Code: ipc.CodeBadRequest, Message: msg.DaemonInvalidName}
	}
	// The rule of tunnel.add: only an administrator adds tunnels.
	if !a.m.admin(a.uid) {
		return res, errAdminOnly
	}
	cfg, err := config.Parse(p.Name, strings.NewReader(p.Config))
	if err != nil {
		// config errors are msg texts and never echo key values
		return res, &ipc.Error{Code: ipc.CodeBadRequest, Message: err.Error()}
	}
	a.m.mu.Lock()
	exists := a.m.tunnels[p.Name] != nil
	a.m.mu.Unlock()
	if exists {
		return res, &ipc.Error{Code: ipc.CodeBadRequest, Message: msg.DaemonTunnelExists}
	}
	if res.Summary, err = tunnelSummary(p.Name, cfg); err != nil {
		return res, err
	}
	if err := a.approved(res.Summary, false); err != nil {
		return res, err
	}
	// The user who granted access owns the tunnel, as with a CLI add.
	if err := a.m.add(p.Name, p.Config, addOwner(a.uid, a.elevated)); err != nil {
		return res, err
	}
	a.m.notify(a.uid, stepServerInfo)
	ts, err := a.m.statuses(p.Name)
	if err != nil {
		return res, err
	}
	return res, data(&res, ts[0])
}

// tunnelArg reads the tunnel name of connect and disconnect, which must
// name an existing tunnel.
func (a assistCall) tunnelArg(args json.RawMessage, res *ipc.AssistResult) (string, error) {
	var p ipc.TunnelName
	if err := decode(args, &p); err != nil {
		return "", err
	}
	if !validName(p.Name) {
		return "", errNotFound
	}
	res.Summary = fmt.Sprintf(msg.AssistSummaryTunnelNameFmt, p.Name)
	if _, err := a.m.statuses(p.Name); err != nil {
		return "", err
	}
	return p.Name, nil
}

// connect brings a tunnel up after the approval with the user's own rights
// (an administrator's agent is no administrator); the PIN is asked the way
// tunnel.connect asks it, never through the agent.
func (a assistCall) connect(args json.RawMessage) (ipc.AssistResult, error) {
	var res ipc.AssistResult
	name, err := a.tunnelArg(args, &res)
	if err != nil {
		return res, err
	}
	if err := a.approved(res.Summary, false); err != nil {
		return res, err
	}
	var st ipc.TunnelStatus
	err = a.act(func(ctx context.Context) error {
		var err error
		st, err = a.m.agentConnect(ctx, a.uid, name)
		return err
	})
	if err != nil {
		return res, err
	}
	return res, data(&res, st)
}

// disconnect takes a tunnel down without an approval: it only ever ends
// access to the network, and it is recorded. The agent has its user's
// rights only, never an administrator's: it takes down a tunnel bound to
// its user, or its user's own failed or pending connect.
func (a assistCall) disconnect(args json.RawMessage) (ipc.AssistResult, error) {
	var res ipc.AssistResult
	name, err := a.tunnelArg(args, &res)
	if err != nil {
		return res, err
	}
	var st ipc.TunnelStatus
	err = a.act(func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		var err error
		st, err = a.m.disconnectAs(a.uid, name, false)
		return err
	})
	if err != nil {
		return res, err
	}
	return res, data(&res, st)
}
