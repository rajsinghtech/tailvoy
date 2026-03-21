package bridge

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

const maxLabel = 63

// ServiceName generates a VIP service name from a machine FQDN and optional prefix.
// Format: svc:{prefix}{sanitized-fqdn}, truncated with hash if >63 chars after svc:.
func ServiceName(fqdn, prefix string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	sanitized := strings.ReplaceAll(fqdn, ".", "-")
	label := prefix + sanitized

	if len(label) > maxLabel {
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(fqdn)))[:7]
		label = label[:maxLabel-8] + "-" + hash
	}
	return "svc:" + label
}

// DNSServiceName generates the VIP service name for a bridge direction's DNS server.
func DNSServiceName(fromName, toName string) string {
	return "svc:" + fromName + "-to-" + toName + "-bridge-dns"
}
