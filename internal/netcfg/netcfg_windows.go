package netcfg

// New returns the Windows Configurer. Every change is journaled in j (which
// may be nil to disable journaling) before r runs it.
func New(r Runner, j *Journal) Configurer {
	return newWindows(r, j)
}

// commandDirs are searched for the commands ExecRunner runs: System32 only,
// from the system rather than the environment.
var commandDirs = []string{systemDir()}
