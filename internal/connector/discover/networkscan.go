package discover

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/mysocketio/mysocketctl-go/internal/api/models"
	"github.com/mysocketio/mysocketctl-go/internal/connector/config"
)

const maxWorkers = 200
const timeoutTCP = time.Duration(1000 * time.Millisecond)

type scanjob struct {
	port     uint16
	ip       string
	duration time.Duration
}

var _ Discover = (*NetworkFinder)(nil)

type NetworkFinder struct{}

func (s *NetworkFinder) Name() string {
	return reflect.TypeOf(s).Elem().Name()
}

func (s *NetworkFinder) SkipRun(ctx context.Context, cfg config.Config, state DiscoverState) bool {
	return false
}

func (s *NetworkFinder) Find(ctx context.Context, cfg config.Config, state DiscoverState) ([]models.Socket, error) {
	time.Sleep(10 * time.Second)
	sockets := []models.Socket{}

	for _, group := range cfg.NetworkPlugin {

		// We can have multiple networks defined, each with their own list of interfaces and subnets/
		// We need to loop through each network. For now in sequence, but we could do in parallel later
		for _, network := range group.Networks {

			subnetsToScan := network.Subnets

			// Now see if we have any network interfaces and determine the subnets for those
			networkInterfaces := network.Interfaces
			b := getSubnetsForInterface(networkInterfaces)

			// Apppend the two subnet lists
			subnetsToScan = append(subnetsToScan, b...)

			// These are the ports we need to scan
			portsToScan := network.Ports

			ipAddressesToScan := subnetToIps(subnetsToScan)

			if portsToScan != nil && len(portsToScan) > 0 && ipAddressesToScan != nil && len(ipAddressesToScan) > 0 {

				// channel for jobs
				jobs := make(chan scanjob)
				// start workers
				wg := &sync.WaitGroup{}
				wg.Add(maxWorkers)
				for i := 1; i <= maxWorkers; i++ {
					go func(i int) {
						defer wg.Done()
						for j := range jobs {
							scan_result := scanPort(i, j)
							if scan_result {
								// Set the name, in the form of host-1-2-3-4-443
								socketName := fmt.Sprintf("%s-%d-%s", j.ip, j.port, cfg.Connector.Name)
								socketName = strings.Replace(socketName, " ", "-", -1)
								socketName = strings.Replace(socketName, ".", "-", -1)
								socketName = strings.Replace(socketName, "_", "-", -1)

								// Create the socket

								socket := models.Socket{}

								socket.Name = socketName
								socket.PrivateSocket = group.PrivateSocket
								if socket.PrivateSocket {
									socket.Dnsname = socket.Name
								}

								socket.TargetHostname = j.ip
								socket.TargetPort = int(j.port)

								socket.PolicyGroup = group.Group

								socket.AllowedEmailAddresses = group.AllowedEmailAddresses
								socket.AllowedEmailDomains = group.AllowedEmailDomains

								sockets = append(sockets, socket)
							}
						}
					}(i)
				}
				for ipAddress := range ipAddressesToScan {
					for p := range portsToScan {
						// Create scanning job
						job := scanjob{
							port:     portsToScan[p],
							ip:       ipAddressesToScan[ipAddress],
							duration: timeoutTCP,
						}
						// Fire off scnan job
						jobs <- job
					}
				}
				close(jobs)

				// wait for workers to complete
				wg.Wait()

			}
		}
	}
	return sockets, nil
}

func getSubnetsForInterface(networkInterfaces []string) []string {
	subnets := []string{}

	for ifName := range networkInterfaces {
		ifn, err := net.InterfaceByName(networkInterfaces[ifName])
		if err != nil {
			log.Println("Error: interface not found: ", networkInterfaces[ifName])
			continue
		}
		addrs, _ := ifn.Addrs()
		// Now loop though the addresses
		for _, addr := range addrs {
			// determine the network address
			_, subnetAddress, _ := net.ParseCIDR(addr.String())

			// For now only v4 addresses are supported
			if strings.Contains(subnetAddress.String(), ".") {
				// This means it's IPv4
				subnets = append(subnets, subnetAddress.String())
			} else if strings.Contains(subnetAddress.String(), ":") {
				// This means it's IPv6
				continue
			}
		}
	}

	return subnets
}

func subnetToIps(subnets []string) []string {
	ipcache := make(map[uint32]bool)
	allIPAddresses := []string{}

	for _, subnet := range subnets {
		_, ipv4Net, err := net.ParseCIDR(subnet)
		if err != nil {
			log.Println(err)
			continue
		}

		// convert IPNet struct mask and address to uint32
		// network is BigEndian
		mask := binary.BigEndian.Uint32(ipv4Net.Mask)
		start := binary.BigEndian.Uint32(ipv4Net.IP)
		// find the final address
		finish := (start & mask) | (mask ^ 0xffffffff)

		//remove network and broadcast addresses, if not /32 / 128
		// That happens when start and finsh are the same
		if start != finish {
			start++
			finish--
		}

		//fmt.Println(start, finish, mask)
		// Now we have the start and finish addresses, we can scan them
		// loop through addresses as uint32
		for i := start; i <= finish; i++ {

			// Check if we already have this IP in the cache
			// If we do, skip it.. could be overlapping CIDRS
			if _, ok := ipcache[i]; ok {
				//fmt.Println("Skipping IP ", i)
				continue
			} else {
				// Add this IP to the cache
				ipcache[i] = true

				// convert back to net.IP
				ip := make(net.IP, 4)
				binary.BigEndian.PutUint32(ip, i)
				allIPAddresses = append(allIPAddresses, ip.String())
			}

		}

	}
	return allIPAddresses
}

func scanPort(port int, target scanjob) bool {

	targetHostPort := fmt.Sprintf("%s:%d", target.ip, target.port)
	//fmt.Printf("[+] Scanning %s\n", targetHostPort)
	d := net.Dialer{Timeout: timeoutTCP}

	_, err := d.Dial("tcp", targetHostPort)
	if err != nil {
		errstr, _ := err.(*net.OpError)
		if strings.Contains(errstr.Err.Error(), "too many open files") {
			//log.Println(">> Too many open files")
			return false

		} else if strings.Contains(errstr.Err.Error(), "timeout") {
			//log.Println(">> timeout")
			return false

		} else if strings.Contains(errstr.Err.Error(), "refused") {
			//log.Println(">> refused")
			return false

		} else {
			//log.Println(">> ", targetHostPort, errstr.Err.Error())
			return false
		}
	} else {
		//fmt.Printf("[+] Port %s/TCP is open\n", targetHostPort)
		return true
	}
}
