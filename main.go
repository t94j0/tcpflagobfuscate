package main

import (
	"./tcpflagobfuscate"
)

func main() {
	flag := "flag{test123}"
	flags := tcpflagobfuscate.ParseStringToTCPFlags(flag)

	srcIP := "127.0.0.1"
	dstIP := "127.0.0.1"
	srcPort := 1234
	dstPort := 12345
	payloadString := "whatever"

	for _, x := range flags {
		tcpflagobfuscate.SendPacket(srcIP, dstIP, srcPort, dstPort, payloadString, x)
	}
}
