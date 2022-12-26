package pkg

import (
	"context"
	"errors"
	"log"
	"nmap/netvuln"
)

type Server struct {
}

func (s *Server) CheckVuln(ctx context.Context, request *netvuln_v1.CheckVulnRequest) (*netvuln_v1.CheckVulnResponse, error) {
	response := netvuln_v1.CheckVulnResponse{}

	errResponse := errors.New("")
	errResponse = nil

	response.Results, errResponse = CheckVulners(request.Targets, request.TcpPort)
	if errResponse != nil {
		log.Fatalf("Error getting results: %v", errResponse)
	}
	return &response, nil
}
