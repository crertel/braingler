// Package wol sends Wake-on-LAN magic packets.
//
// A magic packet is 6 bytes of 0xFF followed by the target MAC repeated 16
// times, sent as a UDP broadcast (typically port 9). Most NICs listen for it
// at link level while powered off.
package wol

import (
	"fmt"
	"net"
)

// Port is the conventional UDP port for WoL. The NIC doesn't actually care
// about the port — it pattern-matches on the payload — but most senders use 9.
const Port = 9

// Wake sends a magic packet for mac to the UDP broadcast address bcast.
func Wake(mac net.HardwareAddr, bcast net.IP) error {
	if len(mac) != 6 {
		return fmt.Errorf("wol: MAC must be 6 bytes (got %d)", len(mac))
	}
	if bcast.To4() == nil {
		return fmt.Errorf("wol: broadcast must be IPv4 (got %v)", bcast)
	}

	packet := make([]byte, 0, 6+16*6)
	for range 6 {
		packet = append(packet, 0xFF)
	}
	for range 16 {
		packet = append(packet, mac...)
	}

	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: bcast, Port: Port})
	if err != nil {
		return fmt.Errorf("wol: dial: %w", err)
	}
	defer conn.Close()

	if _, err := conn.Write(packet); err != nil {
		return fmt.Errorf("wol: write: %w", err)
	}
	return nil
}
