package main

import (
	"fmt"

	"github.com/google/gopacket"

	//"github.com/google/gopacket/examples/util"
	"log"
	"net"
	"strings"

	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)

// TCPFlag contains the TCP flags to use for the request
type TCPFlag struct {
	NS  bool
	CWR bool
	ECE bool
	URG bool
	ACK bool
	PSH bool
	RST bool
	SYN bool

	// Last
	FIN bool
}

// TCPFlags is an array of TCPFlag
type TCPFlags []TCPFlag

// New creates a new TCPFlags object given a string
func New(str string) TCPFlags {
	flags := make([]TCPFlag, 0)

	var binary string
	bytestring := []byte(str)
	for _, b := range bytestring {
		bits := fmt.Sprintf("% 09b", b)
		binary += string(bits)
	}

	bits := strings.Split(binary, " ")

	flag := TCPFlag{}
	for _, b := range bits {
		for i, ib := range b {
			if ib == 49 {
				switch i {
				case 0:
					flag.NS = true
				case 1:
					flag.CWR = true
				case 2:
					flag.ECE = true
				case 3:
					flag.URG = true
				case 4:
					flag.ACK = true
				case 5:
					flag.PSH = true
				case 6:
					flag.RST = true
				case 7:
					flag.SYN = true
				}
			} else {
				switch i {
				case 0:
					flag.NS = false
				case 1:
					flag.CWR = false
				case 2:
					flag.ECE = false
				case 3:
					flag.URG = false
				case 4:
					flag.ACK = false
				case 5:
					flag.PSH = false
				case 6:
					flag.RST = false
				case 7:
					flag.SYN = false
				}
			}
		}
		flags = append(flags, flag)
	}

	return TCPFlags(flags)
}

func (flags TCPFlags) Send(srcIP, dstIP string, srcPort, dstPort int, payload string) error {
	for _, x := range flags {
		if err := sendPacket(srcIP, dstIP, srcPort, dstPort, payload, x); err != nil {
			return err
		}
	}

	return nil
}

func sendPacket(srcIPstr string, dstIPstr string, sport int, dport int, payloadstr string, flag TCPFlag) error {
	var srcIP, dstIP net.IP

	// Logic here is a bit awkward
	srcIP = net.ParseIP(srcIPstr)
	if srcIP == nil {
		log.Printf("Non-IP Target: %q\n", srcIPstr)
	}
	srcIP = srcIP.To4()
	if srcIP == nil {
		log.Printf("Non-IPv4 Target: %q\n", srcIPstr)
	}

	dstIP = net.ParseIP(dstIPstr)
	if dstIP == nil {
		log.Printf("Non-IP Target: %q\n", dstIPstr)
	}
	dstIP = dstIP.To4()
	if dstIP == nil {
		log.Printf("Non-IPv4 Target: %q\n", dstIPstr)
	}

	ip := layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	srcport := layers.TCPPort(sport)
	dstport := layers.TCPPort(dport)

	tcp := layers.TCP{
		SrcPort: srcport,
		DstPort: dstport,
		Window:  1505,
		Urgent:  0,
		Seq:     11050,
		Ack:     0,
		ACK:     flag.ACK,
		SYN:     flag.SYN,
		FIN:     flag.FIN,
		RST:     flag.RST,
		URG:     flag.URG,
		ECE:     flag.ECE,
		CWR:     flag.CWR,
		NS:      flag.NS,
		PSH:     flag.PSH,
	}

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	tcp.SetNetworkLayerForChecksum(&ip)

	ipHeaderBuf := gopacket.NewSerializeBuffer()
	err := ip.SerializeTo(ipHeaderBuf, opts)
	if err != nil {
		return err
	}
	ipHeader, err := ipv4.ParseHeader(ipHeaderBuf.Bytes())
	if err != nil {
		return err
	}

	tcpPayloadBuf := gopacket.NewSerializeBuffer()
	payload := gopacket.Payload([]byte(payloadstr))
	if err := gopacket.SerializeLayers(tcpPayloadBuf, opts, &tcp, payload); err != nil {
		return err
	}

	var rawConn *ipv4.RawConn
	packetConn, err := net.ListenPacket("ip4:tcp", dstIPstr)
	if err != nil {
		return err
	}
	rawConn, err = ipv4.NewRawConn(packetConn)
	if err != nil {
		return err
	}

	if err := rawConn.WriteTo(ipHeader, tcpPayloadBuf.Bytes(), nil); err != nil {
		return err
	}
	return nil
}
