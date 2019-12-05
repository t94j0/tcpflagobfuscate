package tcpflagobfuscate

import (
	"fmt"
	"github.com/google/gopacket"
	//"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
	"log"
	"net"
	"strings"
)

// TCP Header Flags
type TCPFlags struct {
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

// Creates a slice of TCPFlags with the encoded string
func ParseStringToTCPFlags(str string) (flags []TCPFlags) {
	var binary string
	bytestring := []byte(str)
	for _, b := range bytestring {
		bits := fmt.Sprintf("% 09b", b)
		binary += string(bits)
	}

	bits := strings.Split(binary, " ")
	flag := TCPFlags{}
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
	return flags
}

func SendPacket(srcIPstr string, dstIPstr string, sport int, dport int, payloadstr string, flags TCPFlags) {
	var srcIP, dstIP net.IP

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
		ACK:     flags.ACK,
		SYN:     flags.SYN,
		FIN:     flags.FIN,
		RST:     flags.RST,
		URG:     flags.URG,
		ECE:     flags.ECE,
		CWR:     flags.CWR,
		NS:      flags.NS,
		PSH:     flags.PSH,
	}

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	tcp.SetNetworkLayerForChecksum(&ip)

	ipHeaderBuf := gopacket.NewSerializeBuffer()
	err := ip.SerializeTo(ipHeaderBuf, opts)
	if err != nil {
		panic(err)
	}
	ipHeader, err := ipv4.ParseHeader(ipHeaderBuf.Bytes())
	if err != nil {
		panic(err)
	}

	tcpPayloadBuf := gopacket.NewSerializeBuffer()
	payload := gopacket.Payload([]byte(payloadstr))
	err = gopacket.SerializeLayers(tcpPayloadBuf, opts, &tcp, payload)
	if err != nil {
		panic(err)
	}

	var packetConn net.PacketConn
	var rawConn *ipv4.RawConn
	packetConn, err = net.ListenPacket("ip4:tcp", dstIPstr)
	if err != nil {
		panic(err)
	}
	rawConn, err = ipv4.NewRawConn(packetConn)
	if err != nil {
		panic(err)
	}

	err = rawConn.WriteTo(ipHeader, tcpPayloadBuf.Bytes(), nil)
}
