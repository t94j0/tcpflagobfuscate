package main

const Flag = "flag{test123}"

func main() {
	flags := New(Flag)

	srcIP := "127.0.0.1"
	dstIP := "127.0.0.1"
	srcPort := 1234
	dstPort := 12345
	payload := "whatever"

	if err := flags.Send(srcIP, dstIP, srcPort, dstPort, payload); err != nil {
		panic(err)
	}
}
