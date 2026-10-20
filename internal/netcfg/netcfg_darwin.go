package netcfg

// New returns the macOS Configurer; run executes one command (see Exec).
func New(run func(name string, args ...string) error) Configurer {
	return newDarwin(run)
}

// commandDirs are searched, in order, for the commands Exec runs. A fixed
// list keeps the privileged daemon independent of PATH.
var commandDirs = []string{"/sbin", "/usr/sbin"}
