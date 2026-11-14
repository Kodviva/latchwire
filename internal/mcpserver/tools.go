package mcpserver

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/msg"
)

// Tool inputs. Their JSON schemas are inferred from these types; a field
// with omitempty is optional.

type statusIn struct{}

type progressIn struct {
	Path   string `json:"path,omitempty" jsonschema:"the setup path: owner (the user runs the server, the default) or invited (someone else runs it)"`
	Tunnel string `json:"tunnel,omitempty" jsonschema:"the tunnel to look at; leave it out for a new setup"`
}

type peerBlockIn struct {
	PublicKey string `json:"public_key" jsonschema:"the client's WireGuard public key (base64), as create_key or status returned it"`
	Address   string `json:"address" jsonschema:"the client's tunnel IP address, for example 10.8.0.2"`
}

type guideIn struct {
	Kind            string `json:"kind" jsonschema:"the server: opnsense, pfsense, mikrotik, linux or other"`
	PublicKey       string `json:"public_key" jsonschema:"the client's WireGuard public key (base64)"`
	Address         string `json:"address" jsonschema:"the client's tunnel IP address"`
	BackupPublicKey string `json:"backup_public_key,omitempty" jsonschema:"the public key of the backup YubiKey, if there is one"`
	BackupAddress   string `json:"backup_address,omitempty" jsonschema:"the tunnel IP address of the backup YubiKey (a peer of its own on the server)"`
}

type keyIn struct {
	Serial uint32 `json:"serial" jsonschema:"the serial number of the YubiKey, as status lists it"`
	Slot   string `json:"slot,omitempty" jsonschema:"the PIV slot in hexadecimal, 82 to 95; leave it out to take the first free slot"`
}

type serverIn struct {
	Endpoint     string   `json:"endpoint" jsonschema:"the server's host:port"`
	PublicKey    string   `json:"public_key" jsonschema:"the server's WireGuard public key (base64)"`
	AllTraffic   bool     `json:"all_traffic,omitempty" jsonschema:"send all traffic through this server"`
	Networks     []string `json:"networks,omitempty" jsonschema:"the networks reached through this server (CIDR), unless all_traffic is set"`
	PresharedKey string   `json:"preshared_key,omitempty" jsonschema:"the preshared key (base64), if the server uses one; it is never shown back"`
	Keepalive    int      `json:"keepalive,omitempty" jsonschema:"persistent keepalive in seconds, 0 for off"`
}

type backupIn struct {
	KeyRef    string `json:"key_ref" jsonschema:"the backup key's reference, piv://<serial>/<slot>"`
	PublicKey string `json:"public_key" jsonschema:"the backup key's public key (base64)"`
	Address   string `json:"address" jsonschema:"the backup key's tunnel IP address"`
}

type tunnelIn struct {
	Name      string     `json:"name" jsonschema:"the tunnel's name: letters, digits, hyphens and underscores"`
	KeyRef    string     `json:"key_ref" jsonschema:"the key's reference, piv://<serial>/<slot>, as create_key or status returned it"`
	PublicKey string     `json:"public_key" jsonschema:"the key's public key (base64)"`
	Address   string     `json:"address" jsonschema:"the tunnel IP address the server gave this client, for example 10.8.0.2"`
	Backup    *backupIn  `json:"backup,omitempty" jsonschema:"a backup YubiKey for the same tunnel"`
	Servers   []serverIn `json:"servers" jsonschema:"the servers the tunnel connects to"`
	DNS       []string   `json:"dns,omitempty" jsonschema:"DNS servers or search domains"`
	MTU       int        `json:"mtu,omitempty" jsonschema:"the MTU, 1280 to 9000; leave it out for automatic"`
}

type nameIn struct {
	Name string `json:"name" jsonschema:"the tunnel's name"`
}

// Tool outputs computed here.

type peerBlockOut struct {
	PeerBlock string `json:"peer_block"`
}

type guideStepOut struct {
	Text   string   `json:"text"`
	Values []string `json:"values,omitempty"`
}

type guideOut struct {
	Version string         `json:"version,omitempty"`
	Steps   []guideStepOut `json:"steps"`
}

func addTools(s *mcp.Server, d *daemon) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        ipc.ToolStatus,
		Description: "List the Latchwire tunnels (state, keys, last handshake) and the plugged-in YubiKeys (serial, firmware, whether they can hold Latchwire keys, free slots, keys).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ statusIn) (*mcp.CallToolResult, any, error) {
		return d.forward(ctx, req, ipc.ToolStatus, nil, false)
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        ipc.ToolSetupProgress,
		Description: "Show the steps of setting up a tunnel and whether each is done, pending or unknown, from facts: a YubiKey plugged in, a key on it, the tunnel defined, a handshake.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in progressIn) (*mcp.CallToolResult, any, error) {
		return d.forward(ctx, req, ipc.ToolSetupProgress, ipc.AssistProgressArgs{Path: in.Path, Tunnel: in.Tunnel}, false)
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        ipc.ToolPeerBlock,
		Description: "Give the [Peer] block to add on the WireGuard server for a client key and its tunnel IP address.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in peerBlockIn) (*mcp.CallToolResult, any, error) {
		if err := d.check(ctx, req, ipc.ToolPeerBlock); err != nil {
			return nil, nil, err
		}
		key, err := parsePublic("public_key", in.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		addr, err := parseAddr("address", in.Address)
		if err != nil {
			return nil, nil, err
		}
		block := desktop.PeerBlock(msg.English, key, addr)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: block}}}, peerBlockOut{PeerBlock: block}, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        ipc.ToolServerGuide,
		Description: "Give the steps to add the client key (and a backup key) as a peer on a server: opnsense, pfsense, mikrotik, linux or other, with the public keys and addresses filled in.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in guideIn) (*mcp.CallToolResult, any, error) {
		if err := d.check(ctx, req, ipc.ToolServerGuide); err != nil {
			return nil, nil, err
		}
		return serverGuide(in)
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        ipc.ToolCreateKey,
		Description: "Create a new WireGuard key on a YubiKey and return its public key and reference. The user approves it in the Latchwire app and types the PIN there (on a factory-fresh YubiKey also the PUK and a new PIN and PUK); this can take a few minutes.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in keyIn) (*mcp.CallToolResult, any, error) {
		a := ipc.AssistKeyArgs{Serial: in.Serial}
		if in.Slot != "" {
			slot, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(in.Slot), "0x"), 16, 8)
			if err != nil || slot < keyref.MinSlot || slot > keyref.MaxSlot {
				return nil, nil, invalidField("slot")
			}
			a.Slot = uint8(slot)
		}
		return d.forward(ctx, req, ipc.ToolCreateKey, a, true)
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        ipc.ToolAddTunnel,
		Description: "Add a tunnel for a YubiKey key (and optionally a backup YubiKey) to the servers given. Only an administrator's tunnels can be added; the user approves it in the Latchwire app. A preshared key is never shown back.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in tunnelIn) (*mcp.CallToolResult, any, error) {
		// Access and the tunnels group first: while they are off nothing
		// else is said, not even about the form.
		if err := d.check(ctx, req, ipc.ToolAddTunnel); err != nil {
			return nil, nil, err
		}
		conf, err := tunnelConfig(in)
		if err != nil {
			return nil, nil, err
		}
		return d.forward(ctx, req, ipc.ToolAddTunnel, ipc.AssistTunnelArgs{Name: in.Name, Config: conf}, true)
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        ipc.ToolConnect,
		Description: "Connect a tunnel. The user approves it in the Latchwire app and types the YubiKey PIN there, never here; this can take a few minutes.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in nameIn) (*mcp.CallToolResult, any, error) {
		return d.forward(ctx, req, ipc.ToolConnect, ipc.TunnelName{Name: in.Name}, true)
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        ipc.ToolDisconnect,
		Description: "Disconnect a tunnel.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in nameIn) (*mcp.CallToolResult, any, error) {
		return d.forward(ctx, req, ipc.ToolDisconnect, ipc.TunnelName{Name: in.Name}, false)
	})
}

// forward runs a tool on the daemon and returns its data.
func (d *daemon) forward(ctx context.Context, req *mcp.CallToolRequest, tool string, args any, progress bool) (*mcp.CallToolResult, any, error) {
	res, err := d.call(ctx, req, tool, args, progress)
	if err != nil {
		return nil, nil, err
	}
	if len(res.Data) == 0 || string(res.Data) == "null" {
		return nil, map[string]any{}, nil
	}
	return nil, res.Data, nil
}

// check asks the daemon whether tool may run: peer_block and server_guide,
// which are computed here, or add_tunnel before its form is validated.
func (d *daemon) check(ctx context.Context, req *mcp.CallToolRequest, tool string) error {
	_, err := d.call(ctx, req, ipc.ToolCheck, ipc.AssistCheckArgs{Tool: tool}, false)
	return err
}

// invalidField is the error for an argument that does not parse. It names
// the argument only: a value may be a preshared key.
func invalidField(name string) error { return errors.New(name + ": invalid") }

func parsePublic(field, s string) (desktop.Key, error) {
	var k desktop.Key
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != len(k.Public) {
		return k, invalidField(field)
	}
	copy(k.Public[:], b)
	return k, nil
}

func parseKey(prefix, ref, public string) (desktop.Key, error) {
	k, err := parsePublic(prefix+"public_key", public)
	if err != nil {
		return k, err
	}
	if k.Ref, err = keyref.Parse(strings.TrimSpace(ref)); err != nil {
		return k, invalidField(prefix + "key_ref")
	}
	return k, nil
}

// parseAddr reads a tunnel IP address, bare or as a host prefix (/32 or
// /128).
func parseAddr(field, s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil && p.Bits() == p.Addr().BitLen() && p.Addr().Zone() == "" {
		return p.Addr(), nil
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		return a, nil
	}
	return netip.Addr{}, invalidField(field)
}

var serverKinds = []desktop.ServerKind{desktop.ServerOPNsense, desktop.ServerPfSense, desktop.ServerMikroTik, desktop.ServerLinux, desktop.ServerOther}

func serverGuide(in guideIn) (*mcp.CallToolResult, any, error) {
	kind := desktop.ServerKind(strings.ToLower(strings.TrimSpace(in.Kind)))
	known := false
	for _, k := range serverKinds {
		known = known || k == kind
	}
	if !known {
		return nil, nil, invalidField("kind")
	}
	key, err := parsePublic("public_key", in.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	addr, err := parseAddr("address", in.Address)
	if err != nil {
		return nil, nil, err
	}
	keys, addrs := []desktop.Key{key}, []netip.Addr{addr}
	if in.BackupPublicKey != "" || in.BackupAddress != "" {
		bk, err := parsePublic("backup_public_key", in.BackupPublicKey)
		if err != nil {
			return nil, nil, err
		}
		ba, err := parseAddr("backup_address", in.BackupAddress)
		if err != nil {
			return nil, nil, err
		}
		keys, addrs = append(keys, bk), append(addrs, ba)
	}

	version, steps := desktop.GuideText(msg.English, kind, keys, addrs)
	out := guideOut{Version: version, Steps: make([]guideStepOut, len(steps))}
	var b strings.Builder
	if version != "" {
		b.WriteString(version + "\n\n")
	}
	for i, s := range steps {
		out.Steps[i] = guideStepOut{Text: s.Text, Values: s.Values}
		fmt.Fprintf(&b, "%d. %s\n", i+1, s.Text)
		for _, v := range s.Values {
			b.WriteString("   " + v + "\n")
		}
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, out, nil
}

// tunnelConfig renders the add_tunnel arguments as the configuration the
// daemon adds: the server form's text bound to the key (and the backup).
func tunnelConfig(in tunnelIn) (string, error) {
	key, err := parseKey("", in.KeyRef, in.PublicKey)
	if err != nil {
		return "", err
	}
	var backup *desktop.Backup
	if in.Backup != nil {
		bk, err := parseKey("backup.", in.Backup.KeyRef, in.Backup.PublicKey)
		if err != nil {
			return "", err
		}
		ba, err := parseAddr("backup.address", in.Backup.Address)
		if err != nil {
			return "", err
		}
		backup = &desktop.Backup{Key: bk, Address: ba}
	}
	form := desktop.ServerForm{Address: in.Address, DNS: in.DNS, MTU: in.MTU}
	for _, s := range in.Servers {
		form.Peers = append(form.Peers, desktop.ServerPeer{
			Endpoint:     s.Endpoint,
			PublicKey:    s.PublicKey,
			PresharedKey: s.PresharedKey,
			AllTraffic:   s.AllTraffic,
			Networks:     s.Networks,
			Keepalive:    s.Keepalive,
		})
	}
	text, err := form.Conf()
	if err != nil {
		var fe *desktop.FieldError
		if errors.As(err, &fe) {
			return "", invalidField(fieldName(fe.Field))
		}
		return "", errors.New("servers: invalid")
	}
	// Bind's errors are the configuration parser's messages, which name
	// keys and sections, never values.
	return desktop.Bind(text, key, backup)
}

// fieldName is the add_tunnel argument of a server form field.
func fieldName(f string) string {
	f = strings.Replace(f, "peers", "servers", 1)
	f = strings.Replace(f, ".publickey", ".public_key", 1)
	f = strings.Replace(f, ".presharedkey", ".preshared_key", 1)
	return f
}
