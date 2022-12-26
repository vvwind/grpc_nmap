package main

import (
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log"
	netvuln_v1 "nmap/netvuln"
)

func main() {
	var conn *grpc.ClientConn
	var err error
	conn, err = grpc.Dial(":9000", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("could not connect: %s", err)
	}
	defer conn.Close()

	c := netvuln_v1.NewNetVulnServiceClient(conn)

	rqst := netvuln_v1.CheckVulnRequest{}
	rqst.Targets = []string{"ricaperrone.com.br", "sosh61.citycheb.ru"}
	rqst.TcpPort = []int32{22, 80, 443}

	response, errRpc := c.CheckVuln(context.Background(), &rqst)
	if errRpc != nil {
		log.Fatalf("Error when calling CheckVuln: %s", errRpc)
	}
	log.Printf("Response from the server: %s", response.Results)
}
