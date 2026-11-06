package killswitch

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
	"unsafe"
)

// The structures below are the C structures of fwpmtypes.h and fwptypes.h,
// for 64-bit Windows; wfpabi_test.go pins their sizes and offsets. They live
// outside the _windows files so that a filter's translation is tested on
// every system: only the calls into fwpuclnt.dll are not.

// wfpGUID has the layout of windows.GUID.
type wfpGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// Identifiers of Latchwire's objects, made for this purpose.
var (
	wfpProviderKey = wfpGUID{0x5c0a8d1e, 0x7b3f, 0x4f62, [8]byte{0x9a, 0x41, 0x2e, 0x6d, 0xc7, 0x18, 0xb3, 0x05}}
	wfpSublayerKey = wfpGUID{0xe3917f24, 0x1c6a, 0x4d08, [8]byte{0xb5, 0x7e, 0x90, 0x3a, 0x6f, 0x42, 0xd1, 0x8c}}
)

// Layer and condition identifiers of fwpmu.h.
var (
	wfpLayerKeys = map[wfpLayer]wfpGUID{
		layerConnect4: {0xc38d57d1, 0x05a7, 0x4c33, [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}},
		layerConnect6: {0x4a72393b, 0x319f, 0x44bc, [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}},
		layerRecv4:    {0xe1cd9fe7, 0xf4b5, 0x4273, [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}},
		layerRecv6:    {0xa3b42c97, 0x9f04, 0x4672, [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f}},
	}
	wfpFieldKeys = map[wfpField]wfpGUID{
		fieldProtocol:   {0x3971ef2b, 0x623e, 0x4f9a, [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}},
		fieldRemoteAddr: {0xb235ae9a, 0x1d64, 0x49b8, [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}},
		fieldLocalAddr:  {0xd9ee00de, 0xc1ef, 0x4617, [8]byte{0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57}},
		fieldRemotePort: {0xc35a604d, 0xd22b, 0x4e1a, [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}},
		fieldLocalPort:  {0x0c1ba1af, 0x5765, 0x453f, [8]byte{0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b}},
		fieldInterface:  {0x4cd62a49, 0x59c3, 0x4969, [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4}},
		fieldLoopback:   {0x632ce23b, 0x5167, 0x435c, [8]byte{0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c}},
	}
)

// Values of fwptypes.h and fwpmtypes.h.
const (
	fwpEmpty      = 0
	fwpUint8      = 1
	fwpUint16     = 2
	fwpUint32     = 3
	fwpUint64     = 4
	fwpV4AddrMask = 0x100
	fwpV6AddrMask = 0x101

	fwpMatchEqual       = 0
	fwpMatchFlagsAllSet = 6

	fwpActionTerminating = 0x1000
	fwpActionBlock       = 0x1 | fwpActionTerminating
	fwpActionPermit      = 0x2 | fwpActionTerminating

	fwpConditionFlagIsLoopback = 0x1

	fwpmFilterFlagClearActionRight = 0x8

	fwpFilterEnumOverlapping = 1

	wfpWeightPermit = 15
	wfpWeightBlock  = 0
)

type fwpValue0 struct {
	typ uint32
	_   uint32
	// value is the union of FWP_VALUE0: a small number itself, or a pointer
	// to the value. A uintptr: a small number must never sit in a pointer
	// the garbage collector sees. wfpBuilt.keep holds what it points at.
	value uintptr
}

type fwpByteBlob struct {
	size uint32
	data *uint8
}

type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

type fwpmFilterCondition0 struct {
	fieldKey       wfpGUID
	matchType      uint32
	conditionValue fwpValue0
}

type fwpmAction0 struct {
	typ        uint32
	filterType wfpGUID
}

type fwpmFilter0 struct {
	filterKey           wfpGUID
	displayData         fwpmDisplayData0
	flags               uint32
	providerKey         *wfpGUID
	providerData        fwpByteBlob
	layerKey            wfpGUID
	subLayerKey         wfpGUID
	weight              fwpValue0
	numFilterConditions uint32
	filterCondition     *fwpmFilterCondition0
	action              fwpmAction0
	providerContext     [2]uint64
	reserved            *wfpGUID
	filterID            uint64
	effectiveWeight     fwpValue0
}

type fwpmSession0 struct {
	sessionKey           wfpGUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processID            uint32
	sid                  uintptr
	username             *uint16
	kernelMode           int32
}

type fwpmProvider0 struct {
	providerKey  wfpGUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerData fwpByteBlob
	serviceName  *uint16
}

type fwpmSublayer0 struct {
	subLayerKey  wfpGUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerKey  *wfpGUID
	providerData fwpByteBlob
	weight       uint16
}

type fwpmFilterEnumTemplate0 struct {
	providerKey             *wfpGUID
	layerKey                wfpGUID
	enumType                uint32
	flags                   uint32
	providerContextTemplate uintptr
	numFilterConditions     uint32
	filterCondition         uintptr
	actionMask              uint32
	calloutKey              *wfpGUID
}

type fwpV4AddrAndMask struct {
	addr, mask uint32
}

type fwpV6AddrAndMask struct {
	addr         [16]byte
	prefixLength uint8
}

// wfpUTF16 returns s as a NUL-terminated UTF-16 string.
func wfpUTF16(s string) *uint16 {
	u := append(utf16.Encode([]rune(s)), 0)
	return &u[0]
}

func wfpDisplay(name string) fwpmDisplayData0 {
	return fwpmDisplayData0{name: wfpUTF16("Latchwire kill switch: " + name)}
}

// wfpBuilt is one filter for FwpmFilterAdd0 and what its values point at,
// which must stay reachable for as long as the filter is in use.
type wfpBuilt struct {
	filter *fwpmFilter0
	conds  []fwpmFilterCondition0
	keep   []any
}

// buildFilter translates f. luid returns an interface's LUID.
func buildFilter(f wfpFilter, luid func(string) (uint64, error)) (*wfpBuilt, error) {
	b := &wfpBuilt{}
	for _, c := range f.conds {
		fc := fwpmFilterCondition0{fieldKey: wfpFieldKeys[c.field], matchType: fwpMatchEqual}
		switch c.field {
		case fieldProtocol:
			fc.conditionValue = fwpValue0{typ: fwpUint8, value: uintptr(c.value)}
		case fieldRemotePort, fieldLocalPort:
			fc.conditionValue = fwpValue0{typ: fwpUint16, value: uintptr(c.value)}
		case fieldLoopback:
			fc.matchType = fwpMatchFlagsAllSet
			fc.conditionValue = fwpValue0{typ: fwpUint32, value: fwpConditionFlagIsLoopback}
		case fieldInterface:
			id, err := luid(c.iface)
			if err != nil {
				return nil, fmt.Errorf("killswitch: interface %q: %w", c.iface, err)
			}
			p := new(uint64)
			*p = id
			b.keep = append(b.keep, p)
			fc.conditionValue = fwpValue0{typ: fwpUint64, value: uintptr(unsafe.Pointer(p))}
		case fieldRemoteAddr, fieldLocalAddr:
			if !c.prefix.IsValid() {
				return nil, errors.New("killswitch: filter without an address")
			}
			a := c.prefix.Addr()
			if a.Is4() {
				// Host order, as FWP_V4_ADDR_AND_MASK wants it.
				s := a.As4()
				p := &fwpV4AddrAndMask{addr: binary.BigEndian.Uint32(s[:]), mask: wfpMask4(c.prefix.Bits())}
				b.keep = append(b.keep, p)
				fc.conditionValue = fwpValue0{typ: fwpV4AddrMask, value: uintptr(unsafe.Pointer(p))}
			} else {
				p := &fwpV6AddrAndMask{addr: a.As16(), prefixLength: uint8(c.prefix.Bits())}
				b.keep = append(b.keep, p)
				fc.conditionValue = fwpValue0{typ: fwpV6AddrMask, value: uintptr(unsafe.Pointer(p))}
			}
		default:
			return nil, fmt.Errorf("killswitch: unknown filter field %d", c.field)
		}
		b.conds = append(b.conds, fc)
	}
	out := &fwpmFilter0{
		displayData:         wfpDisplay(f.name),
		providerKey:         &wfpProviderKey,
		layerKey:            wfpLayerKeys[f.layer],
		subLayerKey:         wfpSublayerKey,
		numFilterConditions: uint32(len(b.conds)),
		weight:              fwpValue0{typ: fwpUint8, value: wfpWeightBlock},
		action:              fwpmAction0{typ: fwpActionBlock},
	}
	if len(b.conds) > 0 {
		out.filterCondition = &b.conds[0]
	}
	if f.permit {
		out.weight.value = wfpWeightPermit
		out.action.typ = fwpActionPermit
	}
	if f.hard {
		out.flags = fwpmFilterFlagClearActionRight
	}
	b.filter = out
	return b, nil
}

// wfpMask4 is the netmask of a prefix length, in host order.
func wfpMask4(bits int) uint32 {
	if bits == 0 {
		return 0
	}
	return ^uint32(0) << (32 - bits)
}
