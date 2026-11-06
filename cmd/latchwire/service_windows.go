package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/Kodviva/latchwire/internal/daemon"
	"github.com/Kodviva/latchwire/internal/datadir"
	"github.com/Kodviva/latchwire/internal/msg"
)

const (
	serviceName = "Latchwire"

	usage            = msg.CLIUsage + "\n" + msg.CLIUsageWindows
	daemonMustBeRoot = msg.DaemonMustBeElevated
	daemonNotRunning = msg.CLIDaemonNotRunningWindows

	// serviceWait bounds waiting for the service to stop.
	serviceWait = 30 * time.Second
)

// effectiveUID is env.geteuid: 0 stands for an elevated process, Windows's
// counterpart of root (LocalSystem counts as elevated).
func effectiveUID() int {
	if windows.GetCurrentProcessToken().IsElevated() {
		return 0
	}
	return 1
}

func addPlatformCommands(cmds map[string]command) {
	cmds["service"] = command{msg.ServiceSynopsis, cmdService}
}

// runAsService runs the daemon as the service when the service manager
// started this process.
func runAsService() (code int, ok bool) {
	if is, err := svc.IsWindowsService(); err != nil || !is {
		return 0, false
	}
	if el, err := eventlog.Open(serviceName); err == nil {
		defer el.Close()
		log.SetFlags(0)
		log.SetOutput(eventWriter{el})
	}
	s := &service{run: func(ctx context.Context) error { return daemon.NewManager(daemon.Options{}).Serve(ctx) }}
	if err := svc.Run(serviceName, s); err != nil {
		log.Printf("service: %v", err)
		return exitError, true
	}
	return s.code, true
}

// eventWriter sends log lines to the event log. No log line carries a key
// or a PIN.
type eventWriter struct{ el *eventlog.Log }

func (w eventWriter) Write(p []byte) (int, error) { return len(p), w.el.Info(1, string(p)) }

// service is the Windows service: the daemon, with its context ended by the
// service manager's stop. A stop is a clean shutdown: tunnels go down and
// the kill switch is lifted, as on a systemd stop.
type service struct {
	run  func(ctx context.Context) error
	code int
}

func (s *service) Execute(_ []string, reqs <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			return s.finish(err, status)
		case r := <-reqs:
			switch r.Cmd {
			case svc.Interrogate:
				status <- r.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				return s.finish(<-done, status)
			}
		}
	}
}

// finish reports how the daemon ended. A failure makes the service manager
// apply the recovery action.
func (s *service) finish(err error, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StopPending}
	if err == nil || errors.Is(err, context.Canceled) {
		return false, 0
	}
	log.Printf("daemon: %v", err)
	s.code = exitError
	return false, 1
}

func cmdService(_ context.Context, e *env, args []string) error {
	if err := wantArgs(msg.ServiceSynopsis, args, 1); err != nil {
		return err
	}
	if e.geteuid() != 0 {
		return errors.New(msg.DaemonMustBeElevated)
	}
	switch args[0] {
	case "install":
		if err := installService(); err != nil {
			return err
		}
		fmt.Fprintf(e.stdout, msg.ServiceInstalledFmt+"\n", serviceName)
	case "uninstall":
		if err := removeService(); err != nil {
			return err
		}
		fmt.Fprintf(e.stdout, msg.ServiceRemovedFmt+"\n", serviceName)
	default:
		return usageErr(msg.ServiceSynopsis, "%s", args[0])
	}
	return nil
}

// installService creates the service as LocalSystem, restarted when it
// fails, and starts it. The data directory is claimed first, so nobody can
// create it before the service's first start.
func installService() error {
	if err := datadir.Secure(); err != nil {
		return err
	}
	exe, err := serviceExecutable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName:  msg.ServiceDisplayName,
		Description:  msg.ServiceDescription,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		Dependencies: []string{"Nsi", "TcpIp", "BFE"},
	}, "daemon")
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Minute},
	}, uint32((24*time.Hour)/time.Second)); err != nil {
		s.Delete()
		return err
	}
	// A daemon that fails reports a stop with an error code, not a crash;
	// without this the service manager would leave it stopped.
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		s.Delete()
		return err
	}
	if err := eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		s.Delete()
		return err
	}
	return s.Start()
}

// serviceExecutable returns this program's path, resolved, if it may become
// a service. The service runs this very file as SYSTEM and loads wintun.dll
// from beside it, so whoever can write that folder would own the machine:
// only Program Files, which only administrators can write by default, is
// accepted.
func serviceExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return "", err
	}
	for _, id := range []*windows.KNOWNFOLDERID{windows.FOLDERID_ProgramFiles, windows.FOLDERID_ProgramFilesX86} {
		if dir, err := windows.KnownFolderPath(id, 0); err == nil && insideWindowsDir(exe, dir) {
			return exe, nil
		}
	}
	return "", fmt.Errorf(msg.ServiceLocationFmt, exe)
}

// removeService stops the service, which takes its tunnels down and lifts
// the kill switch, and removes it. The data directory stays: it holds the
// tunnels.
func removeService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			return err
		}
		deadline := time.Now().Add(serviceWait)
		for st.State != svc.Stopped {
			if time.Now().After(deadline) {
				return errors.New("timed out waiting for the service to stop")
			}
			time.Sleep(200 * time.Millisecond)
			if st, err = s.Query(); err != nil {
				return err
			}
		}
	}
	if err := s.Delete(); err != nil {
		return err
	}
	if err := eventlog.Remove(serviceName); err != nil {
		log.Printf("service: removing the event source: %v", err)
	}
	return nil
}
