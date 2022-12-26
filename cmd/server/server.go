package main

import (
	"google.golang.org/grpc"
	"log"
	"net"
	netvuln_v1 "nmap/netvuln"
	"nmap/pkg"
)

func main() {

	lis, err := net.Listen("tcp", ":9000")
	if err != nil {
		log.Fatalf("Failed to listen on port 9000: %v", err)
	}
	s := pkg.Server{}
	grpcServer := grpc.NewServer()
	netvuln_v1.RegisterNetVulnServiceServer(grpcServer, &s)
	if errList := grpcServer.Serve(lis); errList != nil {
		log.Fatalf("Failed to listen GRPC on port 9000: %v", errList)
	}

}
