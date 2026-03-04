package main

import (
	"fmt"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "50051"
	}
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}

	srv := grpc.NewServer()
	hsrv := health.NewServer()
	hsrv.SetServingStatus("", healthgrpc.HealthCheckResponse_SERVING)
	hsrv.SetServingStatus("echo", healthgrpc.HealthCheckResponse_SERVING)
	healthgrpc.RegisterHealthServer(srv, hsrv)
	reflection.Register(srv)

	fmt.Printf("grpc-echo listening on :%s\n", port)
	if err := srv.Serve(ln); err != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		os.Exit(1)
	}
}
