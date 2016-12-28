// ufwLogReader reads all file in its arguments and displays the IP addresses and the amount of requests each IP address made to ports.
package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"sync"
)

/* Example of a UFW log file (split by identifier/value):
   Dec 27 13:54:32
   ubuntu-16.04
   kernel: [  725.361432]
   [UFW BLOCK]
   IN=eth0		(Network Interface)
   OUT=
   MAC=			(MAC address)
   SRC=127.0.0.1        (Source IP)
   DST=127.0.0.1        (Destination IP)
   LEN=40		(Length of the packet)
   TOS=0x00
   PREC=0x00
   TTL=243		(Time To Live)
   ID=50779
   PROTO=TCP		(protocol)
   SPT=18776            (Sourece Port)
   DPT=6789             (Destination Port)
   WINDOW=5840
   RES=0x00
   SYN URGP=0

   Example of its output:

   	IP: 127.0.0.2	Amount of requests: 2

		Port Number	Amount
		23		2

	IP: 127.0.0.1	Amount of requests: 10

		Port Number	Amount
		22		8
		23		2


	Total amount of requests: 12
	Most requestsed port: 22
*/

// ipPortMapStruct contains the amount of requests from the specified IP
// address. The ports map contain the amount of requests for every port
// from the specified IP address.
type ipPortMapStruct struct {
	amountOfRequests int
	ports            map[string]int
}

// ipPortMapMap holds a RWMutex to be goroutine save when multiple log files
// are provided. ipPortMapMap contains pointers to ipPortMapStructs.
type ipPortMapMap struct {
	sync.RWMutex
	ipPortMapMap map[string]*ipPortMapStruct
}

// Placeholder is a port was found but no IP address.
const iPAdressNotFound = "unknown"

func main() {
	ipPortMapMap := newIPPortMapMap()
	files := os.Args[1:]
	var waitGroup sync.WaitGroup

	if len(files) > 0 {
		for _, filename := range files {
			file, err := os.Open(filename)
			if err != nil {
				log.Fatal(err)
			}

			ipPattern := regexp.MustCompile(`SRC=(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})`)
			portPattern := regexp.MustCompile(`DPT=(\d{1,5})`)
			waitGroup.Add(1)
			go scanFile(file, ipPortMapMap, ipPattern, portPattern, &waitGroup)
		}
	} else {
		fmt.Println("No file arguments were given.")
	}

	waitGroup.Wait()

	totalRequests := 0
	mostRequestedPort := make(map[string]int)

	for ipAddress := range ipPortMapMap.ipPortMapMap {
		if ipPortMapMap.ipPortMapMap[ipAddress].amountOfRequests > 1 {
			fmt.Printf("IP: %s\tAmount of requests: %d\n\n", ipAddress, ipPortMapMap.ipPortMapMap[ipAddress].amountOfRequests)
			fmt.Printf("\tPort Number\tAmount\n")

			for portNumber, amount := range ipPortMapMap.ipPortMapMap[ipAddress].ports {
				fmt.Printf("\t%s\t\t%d\n", portNumber, amount)
				mostRequestedPort[portNumber] += amount
			}

			totalRequests += ipPortMapMap.ipPortMapMap[ipAddress].amountOfRequests
		}
	}
	fmt.Printf("\n\nTotal amount of requests: %d\n", totalRequests)
	fmt.Printf("Most requestsed port: %s\n", getMostRequestedPort(mostRequestedPort))

}

// scanFile scans a file for IP addresses and port numbers.
func scanFile(file *os.File, ipPortMapMap *ipPortMapMap, ipPattern *regexp.Regexp, portPattern *regexp.Regexp, wg *sync.WaitGroup) {
	scanner := bufio.NewScanner(file)
	defer wg.Done()
	for scanner.Scan() {
		ipAddress := ipPattern.FindStringSubmatch(scanner.Text())
		portNumber := portPattern.FindStringSubmatch(scanner.Text())
		if ipAddress != nil && portNumber != nil {
			ipAddressString := ipAddress[1]
			portNumberString := portNumber[1]

			ipPortMapMap.Lock()
			if ipPortMapMap.ipPortMapMap[ipAddressString] != nil {
				ipPortMapMap.ipPortMapMap[ipAddressString].amountOfRequests++
				ipPortMapMap.ipPortMapMap[ipAddressString].ports[portNumberString]++
			} else {
				ipPortMapMap.ipPortMapMap[ipAddressString] = newIPPortMapStruct()
			}
			ipPortMapMap.Unlock()
		} else if portNumber != nil {
			portNumberString := portNumber[1]
			ipPortMapMap.ipPortMapMap[iPAdressNotFound].ports[portNumberString]++
		} else {
			continue
		}
	}
}

// newIPPortMapMap initializes the ipPortMapMap in the ipPortMapMap struct.
func newIPPortMapMap() *ipPortMapMap {
	ipPortMapMap := new(ipPortMapMap)
	ipPortMapMap.ipPortMapMap = make(map[string]*ipPortMapStruct)
	return ipPortMapMap
}

// newIPPortMapStruct initializes the ports map in the ipPortMapStruct.
func newIPPortMapStruct() *ipPortMapStruct {
	ipPortMapStruct := new(ipPortMapStruct)
	ipPortMapStruct.ports = make(map[string]int)
	return ipPortMapStruct
}

// getMostRequestedPort loops through the mostRequestedPortMap to find to
// most requested port that has been blocked by ufw.
func getMostRequestedPort(mostRequestedPortMap map[string]int) string {
	var mostRequestedportNumber string
	highestNumberOfRequests := 0
	for portNumber, numberOfRequests := range mostRequestedPortMap {
		if numberOfRequests > highestNumberOfRequests {
			mostRequestedportNumber = portNumber
			highestNumberOfRequests = numberOfRequests
		}
	}
	return mostRequestedportNumber
}
