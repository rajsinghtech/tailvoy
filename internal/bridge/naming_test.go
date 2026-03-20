package bridge

import "testing"

func TestServiceName(t *testing.T) {
	tests := []struct {
		name   string
		fqdn   string
		prefix string
		want   string
	}{
		{
			name: "simple",
			fqdn: "web-1.tail1234.ts.net",
			want: "svc:web-1-tail1234-ts-net",
		},
		{
			name:   "with prefix",
			fqdn:   "web-1.tail1234.ts.net",
			prefix: "tailnet1-",
			want:   "svc:tailnet1-web-1-tail1234-ts-net",
		},
		{
			name: "trailing dot stripped",
			fqdn: "web-1.tail1234.ts.net.",
			want: "svc:web-1-tail1234-ts-net",
		},
		{
			name: "empty prefix",
			fqdn: "db.tail5678.ts.net",
			want: "svc:db-tail5678-ts-net",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ServiceName(tt.fqdn, tt.prefix)
			if got != tt.want {
				t.Errorf("ServiceName(%q, %q) = %q, want %q", tt.fqdn, tt.prefix, got, tt.want)
			}
		})
	}
}

func TestServiceName_Truncation(t *testing.T) {
	// Long FQDN to trigger truncation after prefix
	longFQDN := "abcdefghijklmnopqrstuvwxyz-abcdefghijklmnopqrstuvwxyz.tail1234.ts.net"
	name := ServiceName(longFQDN, "px-")
	if name[:4] != "svc:" {
		t.Errorf("missing svc: prefix: %q", name)
	}
	label := name[4:]
	if len(label) > 63 {
		t.Errorf("label too long: %d chars: %q", len(label), label)
	}
	// Must end with 7-char hex hash
	if label[len(label)-8] != '-' {
		t.Errorf("expected hash separator: %q", label)
	}
}

func TestServiceName_NoTruncationAtBoundary(t *testing.T) {
	fqdn := "a.b.c.d" // short enough
	name := ServiceName(fqdn, "")
	label := name[4:]
	if len(label) > 63 {
		t.Errorf("unexpected truncation: %q", label)
	}
}
