package killswitch

import (
	"context"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Kodviva/latchwire/internal/netcfg"
)

var (
	fwpuclnt = windows.NewLazySystemDLL("fwpuclnt.dll")
	iphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procEngineOpen      = fwpuclnt.NewProc("FwpmEngineOpen0")
	procEngineClose     = fwpuclnt.NewProc("FwpmEngineClose0")
	procTxnBegin        = fwpuclnt.NewProc("FwpmTransactionBegin0")
	procTxnCommit       = fwpuclnt.NewProc("FwpmTransactionCommit0")
	procTxnAbort        = fwpuclnt.NewProc("FwpmTransactionAbort0")
	procProviderAdd     = fwpuclnt.NewProc("FwpmProviderAdd0")
	procSubLayerAdd     = fwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFilterAdd       = fwpuclnt.NewProc("FwpmFilterAdd0")
	procFilterDelete    = fwpuclnt.NewProc("FwpmFilterDeleteById0")
	procFilterEnumOpen  = fwpuclnt.NewProc("FwpmFilterCreateEnumHandle0")
	procFilterEnum      = fwpuclnt.NewProc("FwpmFilterEnum0")
	procFilterEnumClose = fwpuclnt.NewProc("FwpmFilterDestroyEnumHandle0")
	procFreeMemory      = fwpuclnt.NewProc("FwpmFreeMemory0")

	procAliasToLuid = iphlpapi.NewProc("ConvertInterfaceAliasToLuid")
)

const (
	rpcAuthnDefault      = 0xffffffff
	fwpErrAlreadyExists  = 0x80320009
	fwpErrProviderAbsent = 0x80320005
	wfpTxnWaitMillis     = 15000
	wfpEnumBatch         = 512
	wfpSublayerMaxWeight = 0xffff
)

func init() {
	netcfg.RegisterBuiltin(wfpClearCmd, func(context.Context, []string) ([]byte, error) {
		return nil, fwpuEngine{}.clear()
	})
}

// newPlatform returns the WFP kill switch. It runs nothing: a filtering
// engine that is not running shows at the first Set, which then fails, and
// a tunnel that needs the kill switch is refused.
func newPlatform(_ netcfg.Runner, j *netcfg.Journal) (Firewall, error) {
	return newWFP(fwpuEngine{}, j), nil
}

// wfpCall checks a function that returns a Win32 or FWP error code.
func wfpCall(what string, r1 uintptr) error {
	if uint32(r1) != 0 {
		return fmt.Errorf("%s: %w", what, windows.Errno(uint32(r1)))
	}
	return nil
}

// fwpuEngine is the wfpEngine of fwpuclnt.dll. Each operation has its own
// session, none of them dynamic: a dynamic session would take the filters
// with it when it closes.
type fwpuEngine struct{}

func wfpOpen() (windows.Handle, error) {
	session := &fwpmSession0{txnWaitTimeoutInMSec: wfpTxnWaitMillis}
	var h windows.Handle
	r, _, _ := procEngineOpen.Call(0, rpcAuthnDefault, 0, uintptr(unsafe.Pointer(session)), uintptr(unsafe.Pointer(&h)))
	runtime.KeepAlive(session)
	return h, wfpCall("FwpmEngineOpen0", r)
}

func wfpClose(h windows.Handle) { procEngineClose.Call(uintptr(h)) }

// wfpTxn runs fn in one transaction, which is rolled back if fn fails.
func wfpTxn(h windows.Handle, fn func() error) error {
	r, _, _ := procTxnBegin.Call(uintptr(h), 0)
	if err := wfpCall("FwpmTransactionBegin0", r); err != nil {
		return err
	}
	if err := fn(); err != nil {
		procTxnAbort.Call(uintptr(h))
		return err
	}
	r, _, _ = procTxnCommit.Call(uintptr(h))
	return wfpCall("FwpmTransactionCommit0", r)
}

// wfpEnsureObjects adds the provider and the sublayer unless they exist.
// Neither is persistent, like the filters.
func wfpEnsureObjects(h windows.Handle) error {
	provider := &fwpmProvider0{providerKey: wfpProviderKey, displayData: wfpDisplay("provider")}
	r, _, _ := procProviderAdd.Call(uintptr(h), uintptr(unsafe.Pointer(provider)), 0)
	runtime.KeepAlive(provider)
	if uint32(r) != fwpErrAlreadyExists {
		if err := wfpCall("FwpmProviderAdd0", r); err != nil {
			return err
		}
	}
	sublayer := &fwpmSublayer0{subLayerKey: wfpSublayerKey, displayData: wfpDisplay("sublayer"), providerKey: &wfpProviderKey, weight: wfpSublayerMaxWeight}
	r, _, _ = procSubLayerAdd.Call(uintptr(h), uintptr(unsafe.Pointer(sublayer)), 0)
	runtime.KeepAlive(sublayer)
	if uint32(r) != fwpErrAlreadyExists {
		return wfpCall("FwpmSubLayerAdd0", r)
	}
	return nil
}

// wfpFilterIDs lists the IDs of Latchwire's filters on every layer. The
// provider is gone after a reboot or an engine restart, and then there are
// no filters of it either.
func wfpFilterIDs(h windows.Handle) ([]uint64, error) {
	var ids []uint64
	for _, l := range wfpLayers {
		tmpl := &fwpmFilterEnumTemplate0{
			providerKey: &wfpProviderKey,
			layerKey:    wfpLayerKeys[l],
			enumType:    fwpFilterEnumOverlapping,
			actionMask:  0xffffffff,
		}
		var enum windows.Handle
		r, _, _ := procFilterEnumOpen.Call(uintptr(h), uintptr(unsafe.Pointer(tmpl)), uintptr(unsafe.Pointer(&enum)))
		runtime.KeepAlive(tmpl)
		if uint32(r) == fwpErrProviderAbsent {
			return nil, nil
		}
		if err := wfpCall("FwpmFilterCreateEnumHandle0", r); err != nil {
			return nil, err
		}
		found, err := wfpReadEnum(h, enum)
		procFilterEnumClose.Call(uintptr(h), uintptr(enum))
		if err != nil {
			return nil, err
		}
		ids = append(ids, found...)
	}
	return ids, nil
}

func wfpReadEnum(h, enum windows.Handle) ([]uint64, error) {
	var ids []uint64
	for {
		var entries **fwpmFilter0
		var n uint32
		r, _, _ := procFilterEnum.Call(uintptr(h), uintptr(enum), wfpEnumBatch, uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&n)))
		if err := wfpCall("FwpmFilterEnum0", r); err != nil {
			return nil, err
		}
		if n > 0 {
			for _, f := range unsafe.Slice(entries, n) {
				ids = append(ids, f.filterID)
			}
		}
		if entries != nil {
			procFreeMemory.Call(uintptr(unsafe.Pointer(&entries)))
		}
		if n < wfpEnumBatch {
			return ids, nil
		}
	}
}

func wfpDeleteAll(h windows.Handle, ids []uint64) error {
	for _, id := range ids {
		r, _, _ := procFilterDelete.Call(uintptr(h), uintptr(id))
		if err := wfpCall("FwpmFilterDeleteById0", r); err != nil {
			return err
		}
	}
	return nil
}

// ifaceLUID finds an interface by its alias, the name it was created with.
func ifaceLUID(alias string) (uint64, error) {
	name, err := windows.UTF16PtrFromString(alias)
	if err != nil {
		return 0, err
	}
	var luid uint64
	r, _, _ := procAliasToLuid.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&luid)))
	return luid, wfpCall("ConvertInterfaceAliasToLuid", r)
}

func (fwpuEngine) apply(filters []wfpFilter) error {
	built := make([]*wfpBuilt, len(filters))
	for i, f := range filters {
		b, err := buildFilter(f, ifaceLUID)
		if err != nil {
			return err
		}
		built[i] = b
	}
	h, err := wfpOpen()
	if err != nil {
		return err
	}
	defer wfpClose(h)
	old, err := wfpFilterIDs(h)
	if err != nil {
		return err
	}
	err = wfpTxn(h, func() error {
		if err := wfpEnsureObjects(h); err != nil {
			return err
		}
		if err := wfpDeleteAll(h, old); err != nil {
			return err
		}
		for i, b := range built {
			var id uint64
			r, _, _ := procFilterAdd.Call(uintptr(h), uintptr(unsafe.Pointer(b.filter)), 0, uintptr(unsafe.Pointer(&id)))
			if err := wfpCall("FwpmFilterAdd0", r); err != nil {
				return fmt.Errorf("filter %q: %w", filters[i].name, err)
			}
		}
		return nil
	})
	runtime.KeepAlive(built)
	return err
}

func (fwpuEngine) clear() error {
	h, err := wfpOpen()
	if err != nil {
		return err
	}
	defer wfpClose(h)
	ids, err := wfpFilterIDs(h)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	return wfpTxn(h, func() error { return wfpDeleteAll(h, ids) })
}

func (fwpuEngine) count() (int, error) {
	h, err := wfpOpen()
	if err != nil {
		return 0, err
	}
	defer wfpClose(h)
	ids, err := wfpFilterIDs(h)
	return len(ids), err
}
