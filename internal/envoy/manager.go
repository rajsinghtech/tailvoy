package envoy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"syscall"
)

// Manager manages an Envoy subprocess lifecycle including start, signal
// forwarding, and graceful shutdown.
type Manager struct {
	envoyBin string
	logger   *slog.Logger
	cmd      *exec.Cmd
}

// NewManager creates a Manager that will use the discovered envoy binary.
func NewManager(logger *slog.Logger) *Manager {
	return &Manager{
		envoyBin: findEnvoyBinary(),
		logger:   logger,
	}
}

// Start launches the Envoy process with the given arguments. Stdout and stderr
// are passed through to the parent process. The child is placed in its own
// process group so signals can be delivered precisely.
func (m *Manager) Start(ctx context.Context, args []string) error {
	if m.cmd != nil {
		return errors.New("envoy: already started")
	}

	m.cmd = exec.CommandContext(ctx, m.envoyBin, args...)
	m.cmd.Stdout = os.Stdout
	m.cmd.Stderr = os.Stderr
	m.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	m.logger.Info("starting envoy", "bin", m.envoyBin, "args", args)
	if err := m.cmd.Start(); err != nil {
		m.cmd = nil
		return fmt.Errorf("envoy start: %w", err)
	}
	return nil
}

// Wait blocks until the Envoy process exits and returns its exit error.
func (m *Manager) Wait() error {
	if m.cmd == nil {
		return errors.New("envoy: not started")
	}
	return m.cmd.Wait()
}

// Signal sends the given OS signal to the Envoy process.
func (m *Manager) Signal(sig os.Signal) error {
	if m.cmd == nil || m.cmd.Process == nil {
		return errors.New("envoy: not running")
	}
	return m.cmd.Process.Signal(sig)
}

// Stop sends SIGTERM to Envoy and waits for it to exit.
func (m *Manager) Stop() error {
	if err := m.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("envoy stop: %w", err)
	}
	return m.Wait()
}

// findEnvoyBinary locates the envoy binary by checking ENVOY_BIN, then PATH,
// then common install locations. Returns "envoy" as a fallback so exec will
// produce a clear error if it's truly absent.
func findEnvoyBinary() string {
	if bin := os.Getenv("ENVOY_BIN"); bin != "" {
		return bin
	}
	if path, err := exec.LookPath("envoy"); err == nil {
		return path
	}
	for _, p := range []string{
		"/usr/local/bin/envoy",
		"/usr/bin/envoy",
		"/opt/envoy/bin/envoy",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "envoy"
}

// ParseArgs splits a combined argument slice into tailvoy args and envoy args
// using "--" as the separator. Everything before "--" goes to tailvoy;
// everything after goes to envoy. If there is no separator, all args are
// treated as tailvoy args.
func ParseArgs(args []string) (tailvoyArgs, envoyArgs []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}
