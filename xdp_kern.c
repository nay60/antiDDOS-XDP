#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>



#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define ETH_P_IP 0x0800

struct rule_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u8  proto;
    __u8  tcp_flags;
    __u16 src_port;
    __u16 dst_port;
    __u16 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct rule_key);
    __type(value, __u8);
} rules SEC(".maps");


SEC("xdp")
int xdp_ddos_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    bpf_printk("XDP RUN: proto=%d\\n", iph->protocol);

    struct rule_key key = {};
    key.src_ip = iph->saddr;
    key.dst_ip = iph->daddr;
    key.proto = iph->protocol;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void*)iph + iph->ihl * 4;
        if ((void*)(tcp + 1) > data_end)
            return XDP_PASS;
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
        key.tcp_flags = *((__u8 *)tcp + 13);
	bpf_printk("KEY BUILT: %x -> %x proto=%d sport=%d dport=%d flags=0x%x\\n",
        	key.src_ip, key.dst_ip, key.proto,
        	bpf_ntohs(key.src_port), bpf_ntohs(key.dst_port), key.tcp_flags);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void*)iph + iph->ihl * 4;
        if ((void*)(udp + 1) > data_end)
            return XDP_PASS;
        key.src_port = udp->source;
        key.dst_port = udp->dest;
    }

   // __u8 *action = bpf_map_lookup_elem(&rules, &key);
   // if (action && *action == 1)
       // return XDP_DROP;
    __u8 *action = bpf_map_lookup_elem(&rules, &key);
    if (action && *action == 1) {
        bpf_printk("MAP DROP: %x -> %x\\n", key.src_ip, key.dst_ip);
        return XDP_DROP;
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
