//go:build amd64 || arm64

package killswitch

import (
	"fmt"
	"net/netip"
	"testing"
	"unsafe"
)

// The expected numbers are the C layouts on 64-bit Windows. A mismatch here
// would corrupt what fwpuclnt.dll reads: nothing else can catch it, since
// these tests are the only check that runs without Windows.
func TestABISizes64(t *testing.T) {
	for _, c := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"GUID", unsafe.Sizeof(wfpGUID{}), 16},
		{"FWP_VALUE0", unsafe.Sizeof(fwpValue0{}), 16},
		{"FWP_BYTE_BLOB", unsafe.Sizeof(fwpByteBlob{}), 16},
		{"FWPM_DISPLAY_DATA0", unsafe.Sizeof(fwpmDisplayData0{}), 16},
		{"FWPM_FILTER_CONDITION0", unsafe.Sizeof(fwpmFilterCondition0{}), 40},
		{"FWPM_ACTION0", unsafe.Sizeof(fwpmAction0{}), 20},
		{"FWPM_FILTER0", unsafe.Sizeof(fwpmFilter0{}), 200},
		{"FWPM_SESSION0", unsafe.Sizeof(fwpmSession0{}), 72},
		{"FWPM_PROVIDER0", unsafe.Sizeof(fwpmProvider0{}), 64},
		{"FWPM_SUBLAYER0", unsafe.Sizeof(fwpmSublayer0{}), 72},
		{"FWPM_FILTER_ENUM_TEMPLATE0", unsafe.Sizeof(fwpmFilterEnumTemplate0{}), 72},
		{"FWP_V4_ADDR_AND_MASK", unsafe.Sizeof(fwpV4AddrAndMask{}), 8},
		{"FWP_V6_ADDR_AND_MASK", unsafe.Sizeof(fwpV6AddrAndMask{}), 17},
	} {
		if c.got != c.want {
			t.Errorf("sizeof(%s) = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestABIOffsets64(t *testing.T) {
	var f fwpmFilter0
	var s fwpmSession0
	var p fwpmProvider0
	var l fwpmSublayer0
	var e fwpmFilterEnumTemplate0
	var c fwpmFilterCondition0
	for _, x := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"filter.displayData", unsafe.Offsetof(f.displayData), 16},
		{"filter.flags", unsafe.Offsetof(f.flags), 32},
		{"filter.providerKey", unsafe.Offsetof(f.providerKey), 40},
		{"filter.providerData", unsafe.Offsetof(f.providerData), 48},
		{"filter.layerKey", unsafe.Offsetof(f.layerKey), 64},
		{"filter.subLayerKey", unsafe.Offsetof(f.subLayerKey), 80},
		{"filter.weight", unsafe.Offsetof(f.weight), 96},
		{"filter.numFilterConditions", unsafe.Offsetof(f.numFilterConditions), 112},
		{"filter.filterCondition", unsafe.Offsetof(f.filterCondition), 120},
		{"filter.action", unsafe.Offsetof(f.action), 128},
		{"filter.providerContext", unsafe.Offsetof(f.providerContext), 152},
		{"filter.reserved", unsafe.Offsetof(f.reserved), 168},
		{"filter.filterID", unsafe.Offsetof(f.filterID), 176},
		{"filter.effectiveWeight", unsafe.Offsetof(f.effectiveWeight), 184},
		{"session.flags", unsafe.Offsetof(s.flags), 32},
		{"session.txnWaitTimeoutInMSec", unsafe.Offsetof(s.txnWaitTimeoutInMSec), 36},
		{"session.processID", unsafe.Offsetof(s.processID), 40},
		{"session.sid", unsafe.Offsetof(s.sid), 48},
		{"session.username", unsafe.Offsetof(s.username), 56},
		{"session.kernelMode", unsafe.Offsetof(s.kernelMode), 64},
		{"provider.providerData", unsafe.Offsetof(p.providerData), 40},
		{"provider.serviceName", unsafe.Offsetof(p.serviceName), 56},
		{"sublayer.providerKey", unsafe.Offsetof(l.providerKey), 40},
		{"sublayer.providerData", unsafe.Offsetof(l.providerData), 48},
		{"sublayer.weight", unsafe.Offsetof(l.weight), 64},
		{"enum.layerKey", unsafe.Offsetof(e.layerKey), 8},
		{"enum.enumType", unsafe.Offsetof(e.enumType), 24},
		{"enum.flags", unsafe.Offsetof(e.flags), 28},
		{"enum.providerContextTemplate", unsafe.Offsetof(e.providerContextTemplate), 32},
		{"enum.numFilterConditions", unsafe.Offsetof(e.numFilterConditions), 40},
		{"enum.filterCondition", unsafe.Offsetof(e.filterCondition), 48},
		{"enum.actionMask", unsafe.Offsetof(e.actionMask), 56},
		{"enum.calloutKey", unsafe.Offsetof(e.calloutKey), 64},
		{"condition.matchType", unsafe.Offsetof(c.matchType), 16},
		{"condition.conditionValue", unsafe.Offsetof(c.conditionValue), 24},
	} {
		if x.got != x.want {
			t.Errorf("offsetof(%s) = %d, want %d", x.name, x.got, x.want)
		}
	}
}

func valuePtr(v *fwpValue0) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&v.value)) }

func noLUID(string) (uint64, error) { return 0, fmt.Errorf("no interfaces here") }

func TestBuildFilterIPv4(t *testing.T) {
	b, err := buildFilter(wfpFilter{name: "x", layer: layerConnect4, permit: true, hard: true, conds: []wfpCond{
		cond(fieldProtocol, protoUDP), cond(fieldRemotePort, 51820),
		{field: fieldRemoteAddr, prefix: netip.MustParsePrefix("198.51.100.7/32")},
		{field: fieldLocalAddr, prefix: netip.MustParsePrefix("10.0.0.0/8")},
	}}, noLUID)
	if err != nil {
		t.Fatal(err)
	}
	f := b.filter
	if f.action.typ != 0x1002 || f.flags != 8 || f.weight.typ != fwpUint8 || f.weight.value != 15 {
		t.Fatalf("%+v", f)
	}
	if f.layerKey != wfpLayerKeys[layerConnect4] || f.subLayerKey != wfpSublayerKey || f.providerKey == nil || *f.providerKey != wfpProviderKey {
		t.Fatalf("%+v", f)
	}
	if f.numFilterConditions != 4 || f.filterCondition != &b.conds[0] {
		t.Fatalf("%+v", f)
	}
	if c := b.conds[0]; c.conditionValue.typ != fwpUint8 || c.conditionValue.value != 17 || c.matchType != fwpMatchEqual {
		t.Fatalf("%+v", c)
	}
	if c := b.conds[1]; c.conditionValue.typ != fwpUint16 || c.conditionValue.value != 51820 {
		t.Fatalf("%+v", c)
	}
	c := b.conds[2]
	if c.conditionValue.typ != fwpV4AddrMask {
		t.Fatalf("%+v", c)
	}
	// Host order: 198.51.100.7 is 0xC6336407 as a number on any machine.
	if a := (*fwpV4AddrAndMask)(valuePtr(&c.conditionValue)); a.addr != 0xC6336407 || a.mask != 0xffffffff {
		t.Fatalf("%#x %#x", a.addr, a.mask)
	}
	if a := (*fwpV4AddrAndMask)(valuePtr(&b.conds[3].conditionValue)); a.addr != 0x0A000000 || a.mask != 0xff000000 {
		t.Fatalf("%#x %#x", a.addr, a.mask)
	}
}

func TestBuildFilterIPv6(t *testing.T) {
	b, err := buildFilter(wfpFilter{name: "x", layer: layerRecv6, conds: []wfpCond{
		{field: fieldRemoteAddr, prefix: netip.MustParsePrefix("fe80::/10")},
	}}, noLUID)
	if err != nil {
		t.Fatal(err)
	}
	if b.filter.action.typ != 0x1001 || b.filter.flags != 0 || b.filter.weight.value != 0 {
		t.Fatalf("%+v", b.filter)
	}
	a := (*fwpV6AddrAndMask)(valuePtr(&b.conds[0].conditionValue))
	if a.prefixLength != 10 || a.addr[0] != 0xfe || a.addr[1] != 0x80 {
		t.Fatalf("%+v", a)
	}
}

func TestBuildFilterInterfaceAndLoopback(t *testing.T) {
	b, err := buildFilter(wfpFilter{name: "x", layer: layerConnect4, permit: true, conds: []wfpCond{
		{field: fieldInterface, iface: "wg0"}, {field: fieldLoopback},
	}}, func(string) (uint64, error) { return 0x1234, nil })
	if err != nil {
		t.Fatal(err)
	}
	c := b.conds[0]
	if c.conditionValue.typ != fwpUint64 || *(*uint64)(valuePtr(&c.conditionValue)) != 0x1234 {
		t.Fatalf("%+v", c)
	}
	if c := b.conds[1]; c.matchType != fwpMatchFlagsAllSet || c.conditionValue.typ != fwpUint32 || c.conditionValue.value != 1 {
		t.Fatalf("%+v", c)
	}
}

func TestBuildFilterBlockHasNoConditions(t *testing.T) {
	b, err := buildFilter(wfpFilter{name: "block", layer: layerRecv4}, noLUID)
	if err != nil {
		t.Fatal(err)
	}
	if b.filter.filterCondition != nil || b.filter.numFilterConditions != 0 {
		t.Fatalf("%+v", b.filter)
	}
}

func TestBuildFilterInterfaceGone(t *testing.T) {
	if _, err := buildFilter(wfpFilter{conds: []wfpCond{{field: fieldInterface, iface: "wg0"}}}, noLUID); err == nil {
		t.Fatal("no error")
	}
}

func TestEveryFilterBuilds(t *testing.T) {
	for _, f := range mustFilters(t, wfpTestState()) {
		if _, err := buildFilter(f, func(string) (uint64, error) { return 1, nil }); err != nil {
			t.Fatalf("%s: %v", f.name, err)
		}
	}
}

func TestWFPKeysFilled(t *testing.T) {
	for _, l := range wfpLayers {
		if wfpLayerKeys[l] == (wfpGUID{}) {
			t.Fatal(l)
		}
	}
	for _, f := range []wfpField{fieldProtocol, fieldRemoteAddr, fieldLocalAddr, fieldRemotePort, fieldLocalPort, fieldInterface, fieldLoopback} {
		if wfpFieldKeys[f] == (wfpGUID{}) {
			t.Fatal(f)
		}
	}
}
