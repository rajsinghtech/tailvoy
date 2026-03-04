package envoy

import (
	"reflect"
	"testing"
)

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name      string
		input     []string
		wantTV    []string
		wantEnvoy []string
	}{
		{
			name:      "no separator",
			input:     []string{"-config", "foo.yaml"},
			wantTV:    []string{"-config", "foo.yaml"},
			wantEnvoy: nil,
		},
		{
			name:      "with separator",
			input:     []string{"-config", "foo.yaml", "--", "-c", "/etc/envoy.yaml"},
			wantTV:    []string{"-config", "foo.yaml"},
			wantEnvoy: []string{"-c", "/etc/envoy.yaml"},
		},
		{
			name:      "only envoy args",
			input:     []string{"--", "-c", "/etc/envoy.yaml", "--log-level", "debug"},
			wantTV:    []string{},
			wantEnvoy: []string{"-c", "/etc/envoy.yaml", "--log-level", "debug"},
		},
		{
			name:      "empty input",
			input:     []string{},
			wantTV:    []string{},
			wantEnvoy: nil,
		},
		{
			name:      "separator only",
			input:     []string{"--"},
			wantTV:    []string{},
			wantEnvoy: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTV, gotEnvoy := ParseArgs(tt.input)
			if !reflect.DeepEqual(gotTV, tt.wantTV) {
				t.Errorf("tailvoyArgs = %v, want %v", gotTV, tt.wantTV)
			}
			if !reflect.DeepEqual(gotEnvoy, tt.wantEnvoy) {
				t.Errorf("envoyArgs = %v, want %v", gotEnvoy, tt.wantEnvoy)
			}
		})
	}
}

func TestFindEnvoyBinary(t *testing.T) {
	// Verify it returns a non-empty string and doesn't panic.
	bin := findEnvoyBinary()
	if bin == "" {
		t.Fatal("findEnvoyBinary returned empty string")
	}
	t.Logf("findEnvoyBinary = %q", bin)
}

func TestFindEnvoyBinaryEnvOverride(t *testing.T) {
	t.Setenv("ENVOY_BIN", "/custom/path/envoy")
	bin := findEnvoyBinary()
	if bin != "/custom/path/envoy" {
		t.Errorf("findEnvoyBinary = %q, want %q", bin, "/custom/path/envoy")
	}
}

func TestNewManager(t *testing.T) {
	t.Setenv("ENVOY_BIN", "/usr/local/bin/envoy")
	m := NewManager(nil)
	if m.envoyBin != "/usr/local/bin/envoy" {
		t.Errorf("envoyBin = %q, want %q", m.envoyBin, "/usr/local/bin/envoy")
	}
}

func TestSignalNotStarted(t *testing.T) {
	m := &Manager{}
	if err := m.Signal(nil); err == nil {
		t.Error("expected error signaling unstarted manager")
	}
}

func TestWaitNotStarted(t *testing.T) {
	m := &Manager{}
	if err := m.Wait(); err == nil {
		t.Error("expected error waiting on unstarted manager")
	}
}
