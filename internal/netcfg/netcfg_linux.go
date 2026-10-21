package netcfg

// New returns the Linux Configurer. Every change is journaled in j (which may
// be nil to disable journaling) before r runs it.
func New(r Runner, j *Journal) Configurer {
	return newLinux(r, j)
}

// commandDirs are searched, in order, for the commands ExecRunner runs. A
// fixed list keeps the privileged daemon independent of PATH.
var commandDirs = []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"}
