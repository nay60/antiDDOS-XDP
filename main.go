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
    SrcIP    uint32
    DstIP    uint32
    Proto    uint8
    TCPFlags uint8
    SrcPort  uint16
    DstPort  uint16
    Pad      uint16
}

func htons(port uint16) uint16 {
    return (port << 8) | (port >> 8)
}

func ipToUint32(ip net.IP) uint32 {
    return binary.LittleEndian.Uint32(ip.To4())
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

    err = rules.Pin("/sys/fs/bpf/rules")
    if err != nil && !os.IsExist(err) {
        log.Fatalf("Échec du pin de la map: %v", err)
    }

    action := uint8(1)

    // ➕ Liste des règles à ajouter
    ruleSet := []RuleKey{

    }

    for _, rule := range ruleSet {
        if err := rules.Put(&rule, &action); err != nil {
            log.Printf("❌ Erreur insertion règle %+v: %v", rule, err)
        } else {
            fmt.Printf("✅ Règle ajoutée : %+v\n", rule)
        }
    }

    fmt.Println("Toutes les règles ont été ajoutées. Le programme tourne. Ctrl+C pour quitter.")
    select {}
}
