package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/netp2p/netp2p/internal/packet"
)

func main() {
	listen := flag.String("packet-listen", "127.0.0.1:51820", "local netp2pd UDP packet endpoint")
	source := flag.String("source", "", "overlay source IPv4")
	target := flag.String("target", "", "overlay target IPv4")
	timeout := flag.Duration("timeout", 3*time.Second, "reply timeout")
	flag.Parse()
	if *source == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "--source and --target are required")
		os.Exit(2)
	}
	connection, err := net.DialTimeout("udp", *listen, time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect packet endpoint:", err)
		os.Exit(1)
	}
	defer connection.Close()
	requestPacket, err := packet.BuildEchoRequest(net.ParseIP(*source), net.ParseIP(*target), 0x1234, 1, []byte("netp2p-probe"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "build probe:", err)
		os.Exit(1)
	}
	frame, err := packet.EncodeFrame(requestPacket)
	if err != nil {
		fmt.Fprintln(os.Stderr, "encode probe:", err)
		os.Exit(1)
	}
	if _, err := connection.Write(frame); err != nil {
		fmt.Fprintln(os.Stderr, "send probe:", err)
		os.Exit(1)
	}
	connection.SetReadDeadline(time.Now().Add(*timeout))
	buffer := make([]byte, 65535)
	read, err := connection.Read(buffer)
	if err != nil {
		output, _ := json.Marshal(map[string]any{"ok": false, "error": err.Error()})
		fmt.Println(string(output))
		os.Exit(1)
	}
	reply, err := packet.DecodeFrame(buffer[:read])
	if err != nil {
		output, _ := json.Marshal(map[string]any{"ok": false, "error": err.Error()})
		fmt.Println(string(output))
		os.Exit(1)
	}
	ipPacket := packet.IPv4Packet(reply)
	if err := ipPacket.Validate(); err != nil {
		output, _ := json.Marshal(map[string]any{"ok": false, "error": err.Error()})
		fmt.Println(string(output))
		os.Exit(1)
	}
	icmp := packet.ICMPMessage(reply[ipPacket.HeaderLength():])
	if icmp.Type() != packet.ICMPTypeEchoReply {
		output, _ := json.Marshal(map[string]any{"ok": false, "error": "unexpected echo request"})
		fmt.Println(string(output))
		os.Exit(1)
	}
	output, _ := json.Marshal(map[string]any{"ok": true, "target": *target})
	fmt.Println(string(output))
}
