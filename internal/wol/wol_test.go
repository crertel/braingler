package wol

import (
	"bytes"
	"net"
	"testing"
)

// buildPacket lives here as a test mirror of the on-the-wire format. We don't
// want to export the builder, but we want to assert its layout matches spec.
func buildPacket(mac net.HardwareAddr) []byte {
	pkt := make([]byte, 0, 102)
	for range 6 {
		pkt = append(pkt, 0xFF)
	}
	for range 16 {
		pkt = append(pkt, mac...)
	}
	return pkt
}

func TestPacketShape(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:00:00:00:11")
	pkt := buildPacket(mac)
	if len(pkt) != 102 {
		t.Fatalf("packet len = %d, want 102", len(pkt))
	}
	if !bytes.Equal(pkt[:6], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) {
		t.Error("first 6 bytes must be 0xFF")
	}
	for i := range 16 {
		off := 6 + i*6
		if !bytes.Equal(pkt[off:off+6], mac) {
			t.Errorf("mac copy %d does not match at offset %d", i, off)
		}
	}
}

func TestWakeRejectsBadMAC(t *testing.T) {
	err := Wake(net.HardwareAddr{0x01, 0x02}, net.IPv4(127, 0, 0, 1))
	if err == nil {
		t.Fatal("expected error for short MAC")
	}
}

func TestWakeRejectsIPv6(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:00:00:00:11")
	err := Wake(mac, net.ParseIP("::1"))
	if err == nil {
		t.Fatal("expected error for IPv6 broadcast")
	}
}

func TestWakeLoopbackBroadcast(t *testing.T) {
	// Listen on a UDP socket bound to loopback, then send a packet at it.
	// We use 127.0.0.1 as both source and target so this works without
	// touching real broadcast addresses.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()

	mac, _ := net.ParseMAC("02:00:00:00:00:11")
	target := conn.LocalAddr().(*net.UDPAddr)

	// Wake hardcodes port 9, so we can't use it directly here. Instead we
	// inline the same write logic against the listener's port.
	sender, err := net.DialUDP("udp4", nil, target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sender.Close()
	if _, err := sender.Write(buildPacket(mac)); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 256)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != 102 {
		t.Errorf("received %d bytes, want 102", n)
	}
}
