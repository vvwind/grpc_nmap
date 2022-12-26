package pkg

import "testing"

func TestEmptyHost(t *testing.T) {
	host_addrs := []string{}
	ports := []int32{22, 80}
	_, caseErr := CheckVulners(host_addrs, ports)
	if caseErr == nil {
		t.Errorf("Wanted to got error, got %v", nil)
	}
}

func TestEmptyPorts(t *testing.T) {
	host_addrs := []string{"ricaperrone.com.br"}
	ports := []int32{}
	_, caseErr := CheckVulners(host_addrs, ports)
	if caseErr == nil {
		t.Errorf("Wanted to got error, got %v", nil)
	}
}

func TestSkippedHost(t *testing.T) {
	host_addrs := []string{"ricaperrone.com.br", "", "sosh61.citycheb.ru", "     "}
	ports := []int32{22, 80, 443}
	_, caseErr := CheckVulners(host_addrs, ports)
	if caseErr != nil {
		t.Errorf("Wanted to got nil error, got %v", caseErr)
	}
}

func TestWrongHost(t *testing.T) {
	host_addrs := []string{"echelon.com.br.junior"}
	ports := []int32{22, 80, 443}
	_, caseErr := CheckVulners(host_addrs, ports)
	if caseErr != nil {
		t.Errorf("Wanted to crash")
	}
}
func TestWrongPort(t *testing.T) {
	host_addrs := []string{"sosh61.citycheb.ru"}
	ports := []int32{22, 8000, -4438}
	_, caseErr := CheckVulners(host_addrs, ports)
	if caseErr == nil {
		t.Errorf("Wanted to got error, got %v", nil)
	}
}
