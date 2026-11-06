package killswitch

import (
	"context"
	"fmt"
	"sync"

	"github.com/Kodviva/latchwire/internal/netcfg"
)

// wfpClearCmd is the journal's undo of the filters: not a program but a
// name the Windows runner answers itself (netcfg.RegisterBuiltin).
const wfpClearCmd = "latchwire-wfp-clear"

// wfpEngine puts filters in place. apply replaces all of Latchwire's filters
// in one transaction, so that there is never a moment without them; clear
// removes them; count says how many are there. None of them needs the
// others' state: a filter left by an earlier run is replaced like any other.
type wfpEngine interface {
	apply(filters []wfpFilter) error
	clear() error
	count() (int, error)
}

func wfpClearStep() netcfg.Step {
	return netcfg.Step{Name: wfpClearCmd, Persistent: true}
}

// wfpFirewall is the Windows kill switch.
//
// The filters are added outside any dynamic session and without the
// persistent flag: they stay when the process dies, as nft and pf rules do,
// and go when the filtering engine restarts or Windows reboots. The journal
// survives a reboot on Windows, so the daemon's start restores the block
// then (Manager.startKillSwitch), and Verify notices an engine restart.
type wfpFirewall struct {
	eng wfpEngine
	j   *netcfg.Journal // nil: nothing is journaled

	mu   sync.Mutex
	want int // filters the last Set put in place
}

func newWFP(eng wfpEngine, j *netcfg.Journal) *wfpFirewall {
	return &wfpFirewall{eng: eng, j: j}
}

// Set replaces the filters (s.Block) or removes them. As with nft, the
// removal is journaled before the filters go in and forgotten only once it
// ran; a failed run leaves it journaled.
func (f *wfpFirewall) Set(_ context.Context, s State) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !s.Block {
		if err := f.eng.clear(); err != nil {
			return fmt.Errorf("killswitch: removing the WFP filters: %w", err)
		}
		f.want = 0
		if f.j != nil {
			return f.j.Forget(JournalOwner)
		}
		return nil
	}
	filters, err := wfpFilters(s)
	if err != nil {
		return err
	}
	if f.j != nil {
		if err := f.j.Record(JournalOwner, []netcfg.Step{wfpClearStep()}); err != nil {
			return err
		}
	}
	if err := f.eng.apply(filters); err != nil {
		return fmt.Errorf("killswitch: adding the WFP filters: %w", err)
	}
	f.want = len(filters)
	return nil
}

// Verify checks that every filter is still there: restarting the filtering
// engine or deleting filters by hand removes them without a word.
func (f *wfpFirewall) Verify(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.eng.count()
	if err != nil {
		return false, fmt.Errorf("killswitch: reading the WFP filters: %w", err)
	}
	return n == f.want, nil
}
