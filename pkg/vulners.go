package pkg

import (
	"context"
	"errors"
	"fmt"
	"github.com/Ullaakut/nmap"
	"log"
	netvuln_v1 "nmap/netvuln"
	"strconv"
	"strings"
	"time"
)

func portToStr(tcp_ports []int32) (string, error) {
	ports_string := ""
	for i, v := range tcp_ports {
		if v < 0 || v > 1023 {
			return ports_string, errors.New("Wrong port!")
		}
		ports_string += fmt.Sprintf("%v", v)
		if i != len(tcp_ports)-1 {
			ports_string += ","
		}
	}
	if len(ports_string) == 0 {
		return ports_string, errors.New("Empty port list")
	}
	return ports_string, nil
}

func CheckVulners(host_addrs []string, tcp_ports []int32) ([]*netvuln_v1.TargetResult, error) {
	targetResults := []*netvuln_v1.TargetResult{}

	if len(host_addrs) == 0 {
		return targetResults, errors.New("No host adresses were provided!")
	}

	ports_string, ports_err := portToStr(tcp_ports)
	if ports_err != nil {
		return targetResults, ports_err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	for _, v := range host_addrs {
		if len(strings.TrimSpace(v)) == 0 {
			continue
		}
		scanner, err := nmap.NewScanner(
			nmap.WithTargets(v),
			nmap.WithCustomArguments("-sV"),
			nmap.WithScripts("vulners"),
			nmap.WithCustomArguments("-v"),
			nmap.WithContext(ctx),
			nmap.WithPorts(ports_string),
		)
		if err != nil {
			log.Fatalf("unable to create nmap scanner: %v", err)
		}
		result, warnings, err := scanner.Run()
		if err != nil {
			log.Fatalf("unable to run nmap scan: %v", err)
		}

		if warnings != nil {
			log.Printf("Warnings: \n %v", warnings)
		}

		for _, host := range result.Hosts {
			if len(host.Ports) == 0 || len(host.Addresses) == 0 {
				continue
			}
			smallTarget := netvuln_v1.TargetResult{}
			servicesArr := []*netvuln_v1.Service{}
			smallTarget.Target = fmt.Sprintf("%s", host.Addresses[0])
			fmt.Printf("Host %q:\n", host.Addresses[0])

			for _, port := range host.Ports {
				serviceMessage := netvuln_v1.Service{}
				vuln := netvuln_v1.Vulnerability{}
				serviceMessage.Name = port.Service.Name
				serviceMessage.Version = port.Service.Version
				serviceMessage.TcpPort = int32(port.ID)
				vulns := []*netvuln_v1.Vulnerability{}
				fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
				for _, v := range port.Scripts {
					if v.ID == "vulners" {
						res1 := strings.Split(v.Output, "\n")
						for in, val := range res1 {
							words := strings.Fields(val)
							if in == 0 || in == 1 {
								continue
							}
							cvss, parseErr := strconv.ParseFloat(words[1], 32)
							if parseErr != nil {
								log.Printf("Cant parse %v \n", parseErr)
							}
							identifierString := words[0]
							vuln.CvssScore = float32(cvss)
							vuln.Identifier = identifierString
							vulns = append(vulns, &vuln)

						}
					}

				}
				serviceMessage.Vulns = vulns

				servicesArr = append(servicesArr, &serviceMessage)

			}

			smallTarget.Services = servicesArr
			targetResults = append(targetResults, &smallTarget)

		}
		fmt.Printf("Nmap done: %d hosts up scanned in %3f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
	}

	return targetResults, nil
}
