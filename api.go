
package main

import (
    "encoding/json"
    "github.com/cilium/ebpf"
    "fmt"
    "log"
    "net/http"
    "encoding/binary"
    "net"
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

type RuleView struct {
    SrcIP    string `json:"src_ip"`
    DstIP    string `json:"dst_ip"`
    Proto    uint8  `json:"proto"`
    TCPFlags uint8  `json:"tcp_flags"`
    SrcPort  uint16 `json:"src_port"`
    DstPort  uint16 `json:"dst_port"`
}

func intToIP(ip uint32) net.IP {
    b := make([]byte, 4)
    binary.LittleEndian.PutUint32(b, ip)
    return net.IP(b)
}

func htons(port uint16) uint16 {
    return (port << 8) | (port >> 8)
}

func ntohs(val uint16) uint16 {
    return (val<<8)&0xff00 | val>>8
}

func main() {
    // Route /rules : GET pour lister, POST pour ajouter
    http.HandleFunc("/rules", func(w http.ResponseWriter, r *http.Request) {
        switch r.Method {
        case http.MethodGet:
            handleListRules(w, r)
        case http.MethodPost:
            handleAddRule(w, r)
        case http.MethodDelete:
            handleDeleteRule(w, r)
        default:
            http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
        }
    })


    // Route / pour servir l'interface web
    fs := http.FileServer(http.Dir("./html"))
    http.Handle("/", fs)

    fmt.Println("✅ Serveur lancé sur : http://localhost:8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}


func handleListRules(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
        return
    }

    rulesMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/rules", nil)
    if err != nil {
        http.Error(w, "Impossible d'ouvrir la map eBPF: "+err.Error(), http.StatusInternalServerError)
        return
    }
    defer rulesMap.Close()

    var entries []RuleView
    var key RuleKey
    var value uint8

    it := rulesMap.Iterate()
    for it.Next(&key, &value) {
        entries = append(entries, RuleView{
            SrcIP:    intToIP(key.SrcIP).String(),
            DstIP:    intToIP(key.DstIP).String(),
            Proto:    key.Proto,
            TCPFlags: key.TCPFlags,
            SrcPort:  ntohs(key.SrcPort),
            DstPort:  ntohs(key.DstPort),
        })
    }



    if err := it.Err(); err != nil {
        http.Error(w, "Erreur lecture map: "+err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(entries)
}


func handleAddRule(w http.ResponseWriter, r *http.Request) {
    var input RuleView

    if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
        http.Error(w, "JSON invalide : "+err.Error(), http.StatusBadRequest)
        return
    }

    key := RuleKey{
        SrcIP:    binary.LittleEndian.Uint32(net.ParseIP(input.SrcIP).To4()),
        DstIP:    binary.LittleEndian.Uint32(net.ParseIP(input.DstIP).To4()),
        Proto:    input.Proto,
        TCPFlags: input.TCPFlags,
        SrcPort:  htons(input.SrcPort),
        DstPort:  htons(input.DstPort),
        Pad:      0,
    }

    rulesMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/rules", nil)
    if err != nil {
        http.Error(w, "Échec ouverture map: "+err.Error(), http.StatusInternalServerError)
        return
    }
    defer rulesMap.Close()

    action := uint8(1)
    if err := rulesMap.Put(&key, &action); err != nil {
        http.Error(w, "Erreur ajout règle: "+err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusCreated)
    w.Write([]byte("✅ Règle ajoutée"))
}


func handleDeleteRule(w http.ResponseWriter, r *http.Request) {
    var input RuleView

    if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
        http.Error(w, "JSON invalide : "+err.Error(), http.StatusBadRequest)
        return
    }

    key := RuleKey{
        SrcIP:    binary.LittleEndian.Uint32(net.ParseIP(input.SrcIP).To4()),
        DstIP:    binary.LittleEndian.Uint32(net.ParseIP(input.DstIP).To4()),
        Proto:    input.Proto,
        TCPFlags: input.TCPFlags,
        SrcPort:  htons(input.SrcPort),
        DstPort:  htons(input.DstPort),
        Pad:      0,
    }

    rulesMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/rules", nil)
    if err != nil {
        http.Error(w, "Erreur ouverture map: "+err.Error(), http.StatusInternalServerError)
        return
    }
    defer rulesMap.Close()

    if err := rulesMap.Delete(&key); err != nil {
        http.Error(w, "Erreur suppression règle: "+err.Error(), http.StatusInternalServerError)
        return
    }

    w.Write([]byte("✅ Règle supprimée"))
}
