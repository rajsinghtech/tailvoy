package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9053"
	}
	pc, err := net.ListenPacket("udp", ":"+port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = pc.Close() }()
	fmt.Printf("udp-echo listening on :%s\n", port)

	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read: %v\n", err)
			continue
		}
		resp := fmt.Appendf(nil, "echo: %s", buf[:n])
		if _, err := pc.WriteTo(resp, addr); err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
		}
	}
}
