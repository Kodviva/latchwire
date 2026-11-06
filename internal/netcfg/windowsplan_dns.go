package netcfg

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"strings"
)

// Windows DNS has two parts. The servers go on the tunnel's interface with
// netsh, which is what applications that read the adapter see. Which server
// answers which name is decided by the Name Resolution Policy Table: a rule
// per interface in the local policy key, written with reg, says that the
// listed names go to the listed servers. Interface metrics alone cannot say
// that, because Windows asks the DNS servers of several interfaces at once.
//
// DNSPrimary has a rule for "." (every name) and a low interface metric.
// DNSScoped has a rule for its search domains and no interface servers: the
// rest of the system keeps its own DNS. A rule's undo outlives the tunnel
// (Persistent): it is a registry key, not part of the adapter. Group policy
// NRPT rules replace the local ones: the checklist covers it.

// Applied.DNS values on Windows.
const (
	DNSOutcomeNRPTPrimary = "nrpt-primary" // every name goes to the tunnel's servers
	DNSOutcomeNRPTScoped  = "nrpt-scoped"  // the search domains go to the tunnel's servers
)

const (
	nrptKey     = `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\`
	tcpipIfaces = `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\`

	// nrptVersion is the rule format and nrptOverride the ConfigOptions
	// value that makes a rule's GenericDNSServers answer its names.
	nrptVersion  = "2"
	nrptOverride = "8"
)

// WindowsInterfaceGUID is the adapter GUID of tunnel name, with braces. It
// is derived from the name so that the same tunnel always gets the same
// adapter and Windows does not collect a new network profile per connect,
// and so that its registry keys can be named before it exists.
func WindowsInterfaceGUID(name string) string {
	s := sha256.Sum256([]byte("latchwire adapter\x00" + name))
	s[6] = s[6]&0x0f | 0x50 // version 5 layout: a name-based GUID
	s[8] = s[8]&0x3f | 0x80
	return fmt.Sprintf("{%x-%x-%x-%x-%x}", s[0:4], s[4:6], s[6:8], s[8:10], s[10:16])
}

// nrptSteps returns the steps that add iface's rule for names and flush the
// resolver's cache.
func nrptSteps(iface string, names []string, servers []netip.Addr) []step {
	key := nrptKey + WindowsInterfaceGUID(iface)
	list := make([]string, len(servers))
	for i, s := range servers {
		list[i] = s.String()
	}
	add := func(value, kind, data string) Step {
		return command(regCmd, "add", key, "/v", value, "/t", kind, "/d", data, "/f")
	}
	return []step{
		{do: add("Version", "REG_DWORD", nrptVersion), undo: persistentUndo(regCmd, "delete", key, "/f")},
		{do: add("Name", "REG_MULTI_SZ", strings.Join(names, `\0`))},
		{do: add("GenericDNSServers", "REG_SZ", strings.Join(list, ";"))},
		{do: add("ConfigOptions", "REG_DWORD", nrptOverride)},
		{do: command("ipconfig", "/flushdns")},
	}
}

// planWindowsInterfaceDNS returns the steps that put the servers on the
// interface, with its metric low enough to be asked first.
func planWindowsInterfaceDNS(iface string, servers []netip.Addr, search []string) []step {
	var out []step
	for _, v4 := range []bool{true, false} {
		index := 0
		for _, s := range servers {
			if s.Is4() != v4 {
				continue
			}
			index++
			name, addr := "name="+iface, "address="+s.String()
			if index == 1 {
				out = append(out,
					step{do: netsh(v4, "set", "interface", "interface="+iface, "metric=1", "store=active")},
					step{
						do:   netsh(v4, "set", "dnsservers", name, "source=static", addr, "register=none", "validate=no"),
						undo: netshUndo(v4, "set", "dnsservers", name, "source=dhcp"),
					})
				continue
			}
			out = append(out, step{do: netsh(v4, "add", "dnsservers", name, addr, fmt.Sprintf("index=%d", index), "validate=no")})
		}
	}
	if len(search) > 0 {
		key := tcpipIfaces + WindowsInterfaceGUID(iface)
		out = append(out, step{
			do:   command(regCmd, "add", key, "/v", "SearchList", "/t", "REG_SZ", "/d", strings.Join(search, ","), "/f"),
			undo: undoOf(regCmd, "delete", key, "/v", "SearchList", "/f"),
		})
	}
	return out
}

// windowsDNS is the Windows dnsPlanner. It reads nothing from the system.
func windowsDNS(_ context.Context, _ Runner, p Plan) ([]step, string, error) {
	if p.DNSRole == DNSNone || len(p.DNS) == 0 {
		return nil, DNSOutcomeNone, nil
	}
	if err := validateDNS(p); err != nil {
		return nil, "", err
	}
	if p.DNSRole == DNSScoped {
		names := make([]string, len(p.DNSSearch))
		for i, d := range p.DNSSearch {
			names[i] = "." + strings.TrimPrefix(d, ".")
		}
		return nrptSteps(p.Iface, names, p.DNS), DNSOutcomeNRPTScoped, nil
	}
	steps := planWindowsInterfaceDNS(p.Iface, p.DNS, p.DNSSearch)
	return append(steps, nrptSteps(p.Iface, []string{"."}, p.DNS)...), DNSOutcomeNRPTPrimary, nil
}
