package main

import (
    "encoding/binary"
    "fmt"
    "log"
    "net"
    "os"
    "unsafe"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
)

type RuleKey struct {
    SrcIP    uint32  // 0–3
    DstIP    uint32  // 4–7
    Proto    uint8   // 8
    TCPFlags uint8   // 9
    SrcPort  uint16  // 10–11
    DstPort  uint16  // 12–13
    Pad      uint16  // 14–15
}


func ipToUint32(ip net.IP) uint32 {
    return binary.LittleEndian.Uint32(ip.To4())
}

func htons(port uint16) uint16 {
    return (port<<8)&0xff00 | port>>8
}

func main() {
    if unsafe.Sizeof(RuleKey{}) != 16 {
        log.Fatalf("Invalid struct size: expected 16, got %d", unsafe.Sizeof(RuleKey{}))
    }

    if len(os.Args) < 2 {
        fmt.Println("Usage: sudo go run main.go <interface>")
        return
    }

    ifaceName := os.Args[1]
    spec, err := ebpf.LoadCollectionSpec("xdp_kern.o")
    if err != nil {
        log.Fatalf("Failed to load spec: %v", err)
    }

    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        log.Fatalf("Failed to load collection: %v", err)
    }
    defer coll.Close()

    prog := coll.Programs["xdp_ddos_filter"]
    iface, err := net.InterfaceByName(ifaceName)
    if err != nil {
        log.Fatalf("Interface not found: %v", err)
    }

    lnk, err := link.AttachXDP(link.XDPOptions{
        Program:   prog,
        Interface: iface.Index,
    })
    if err != nil {
        log.Fatalf("Attach failed: %v", err)
    }
    defer lnk.Close()

    rules := coll.Maps["rules"]

    key := RuleKey{
        SrcIP:    0x08080808,     // 8.8.8.8 (little endian)
        DstIP:    0x8058A8C0,     // 192.168.124.128 = 0xc0a87c80 en hex = 0x807ca8c0 en little endian
        Proto:    6,              // ICMP
	TCPFlags: 0x02, 
        SrcPort:  htons(12345),
        DstPort:  htons(80),
        Pad:      0,     // padding
    }
    var action uint8 = 1

    err = rules.Put(&key, &action)
    if err != nil {
        log.Fatalf("Failed to insert rule: %v", err)
    }

    fmt.Println("Rule added. Program is running. Ctrl+C to exit.")
    select {}
}
