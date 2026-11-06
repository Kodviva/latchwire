package netmon

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procNotifyRouteChange2 = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("NotifyRouteChange2")

// Offsets of the interface index in the rows the callbacks receive
// (netioapi.h, 64-bit).
const (
	ifIndexInIPInterfaceRow = 16 // MIB_IPINTERFACE_ROW: Family, InterfaceLuid, InterfaceIndex
	ifIndexInUnicastRow     = 40 // MIB_UNICASTIPADDRESS_ROW: SOCKADDR_INET, InterfaceLuid, InterfaceIndex
	ifIndexInRouteRow       = 8  // MIB_IPFORWARD_ROW2: InterfaceLuid, InterfaceIndex
)

// source turns IP helper callbacks into Next calls. Windows calls back on
// its own threads, so a callback only drops the interface index in a
// channel; a full channel loses nothing, because the Event that follows
// means "re-read the state" whatever the message said.
type source struct {
	indexes chan int
	cache   *ifaceCache // used by Next only

	once    sync.Once
	handles []windows.Handle
}

// current is the source the callbacks feed. windows.NewCallback makes
// callbacks that are never freed, so there are only these three, and the
// process watches through one source at a time.
var (
	current   sync.Mutex
	active    *source
	callbacks = sync.OnceValue(func() [3]uintptr {
		return [3]uintptr{
			windows.NewCallback(func(_ uintptr, row unsafe.Pointer, _ uint32) uintptr { return notify(row, ifIndexInIPInterfaceRow) }),
			windows.NewCallback(func(_ uintptr, row unsafe.Pointer, _ uint32) uintptr { return notify(row, ifIndexInUnicastRow) }),
			windows.NewCallback(func(_ uintptr, row unsafe.Pointer, _ uint32) uintptr { return notify(row, ifIndexInRouteRow) }),
		}
	})
)

func notify(row unsafe.Pointer, offset uintptr) uintptr {
	index := 0
	if row != nil {
		index = int(*(*uint32)(unsafe.Add(row, offset)))
	}
	current.Lock()
	s := active
	current.Unlock()
	if s != nil {
		select {
		case s.indexes <- index:
		default:
		}
	}
	return 0
}

// NewSource subscribes to changes of interfaces, addresses and routes of
// both families. It only listens: it needs no privileges and changes
// nothing. The returned Source is also an io.Closer.
func NewSource() (Source, error) {
	s := &source{indexes: make(chan int, 64), cache: newIfaceCache()}
	current.Lock()
	active = s
	current.Unlock()
	cb := callbacks()
	var h windows.Handle
	if err := windows.NotifyIpInterfaceChange(windows.AF_UNSPEC, cb[0], nil, false, &h); err != nil {
		s.Close()
		return nil, fmt.Errorf("netmon: NotifyIpInterfaceChange: %w", err)
	}
	s.handles = append(s.handles, h)
	if err := windows.NotifyUnicastIpAddressChange(windows.AF_UNSPEC, cb[1], nil, false, &h); err != nil {
		s.Close()
		return nil, fmt.Errorf("netmon: NotifyUnicastIpAddressChange: %w", err)
	}
	s.handles = append(s.handles, h)
	r, _, _ := procNotifyRouteChange2.Call(windows.AF_UNSPEC, cb[2], 0, 0, uintptr(unsafe.Pointer(&h)))
	if r != 0 {
		s.Close()
		return nil, fmt.Errorf("netmon: NotifyRouteChange2: %w", windows.Errno(r))
	}
	s.handles = append(s.handles, h)
	return s, nil
}

// Next returns the name of the interface of the next notification.
func (s *source) Next(ctx context.Context) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case i := <-s.indexes:
		s.cache.begin()
		return s.cache.name(i, true), nil
	}
}

// Close ends the subscriptions. CancelMibChangeNotify2 waits for a callback
// that is running, so none comes after it.
func (s *source) Close() error {
	var errs []error
	s.once.Do(func() {
		for _, h := range s.handles {
			if err := windows.CancelMibChangeNotify2(h); err != nil {
				errs = append(errs, err)
			}
		}
		current.Lock()
		if active == s {
			active = nil
		}
		current.Unlock()
	})
	return errors.Join(errs...)
}
