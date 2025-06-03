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


struct flood_counter {
    __u64 last_seen_ns;
    __u32 pkt_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct flood_counter);
} udp_flood SEC(".maps");

struct syn_flood_key {
    __u32 src_ip;
};

struct syn_flood_value {
    __u64 timestamp;
    __u32 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct syn_flood_key);
    __type(value, struct syn_flood_value);
} syn_flood SEC(".maps");

struct icmp_flood_key {
    __u32 src_ip;
};

struct icmp_flood_value {
    __u64 timestamp;
    __u32 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct icmp_flood_key);
    __type(value, struct icmp_flood_value);
} icmp_flood SEC(".maps");

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
        bpf_printk("KEY BUILT: %x -> %x proto=%d sport=%d dport=%d flags=0x%x\n",
            key.src_ip, key.dst_ip, key.proto,
            bpf_ntohs(key.src_port), bpf_ntohs(key.dst_port), key.tcp_flags);
	if (key.tcp_flags & 0x02) {  // flag SYN
            struct syn_flood_key syn_key = {.src_ip = iph->saddr};
            struct syn_flood_value *syn_val;
            __u64 now = bpf_ktime_get_ns();
            __u64 window = 1000000000; // 1 seconde

            syn_val = bpf_map_lookup_elem(&syn_flood, &syn_key);
            if (!syn_val) {
                struct syn_flood_value new_val = {.timestamp = now, .count = 1};
                bpf_map_update_elem(&syn_flood, &syn_key, &new_val, BPF_ANY);
            } else {
                if (now - syn_val->timestamp <= window) {
                    syn_val->count++;
                    if (syn_val->count > 500) {
                        bpf_printk("DROP SYN FLOOD src_ip=%x count=%d\n", iph->saddr, syn_val->count);
                        return XDP_DROP;
                    }
                } else {
                    syn_val->timestamp = now;
                    syn_val->count = 1;
                }
            }
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void*)iph + iph->ihl * 4;
        if ((void*)(udp + 1) > data_end)
            return XDP_PASS;
        key.src_port = udp->source;
        key.dst_port = udp->dest;

	 __u32 src_ip = iph->saddr;
        __u64 now = bpf_ktime_get_ns();

        struct flood_counter *fc = bpf_map_lookup_elem(&udp_flood, &src_ip);
        struct flood_counter new_fc = {};

        if (fc) {
            if (now - fc->last_seen_ns < 1000000000) {  // < 1s
                fc->pkt_count += 1;
                if (fc->pkt_count > 500) {
                    bpf_printk("DROP UDP FLOOD src_ip=%x count=%d\n", src_ip, fc->pkt_count);
                    return XDP_DROP;
                }
            } else {
                fc->last_seen_ns = now;
                fc->pkt_count = 1;
            }
        } else {
            new_fc.last_seen_ns = now;
            new_fc.pkt_count = 1;
            bpf_map_update_elem(&udp_flood, &src_ip, &new_fc, BPF_ANY);
        }
    } else if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (void*)iph + iph->ihl * 4;
        if ((void*)(icmp + 1) > data_end)
            return XDP_ABORTED;

        key.tcp_flags = 0; // ICMP has no flags
        key.src_port = 0; // ICMP does not use ports
        key.dst_port = 0;

        __u32 src_ip = iph->saddr;
        __u64 now = bpf_ktime_get_ns();

        struct icmp_flood_key icmp_key = {.src_ip = src_ip};
        struct icmp_flood_value *icmp_val;
        icmp_val = bpf_map_lookup_elem(&icmp_flood, &icmp_key);
        if (!icmp_val) {
            struct icmp_flood_value new_val = {.timestamp = now, .count = 1};
            bpf_map_update_elem(&icmp_flood, &icmp_key, &new_val, BPF_ANY);
        } else {
            if (now - icmp_val->timestamp <= 1000000000) { // 1 second window
                icmp_val->count++;
                if (icmp_val->count > 500) {
                    bpf_printk("DROP ICMP FLOOD src_ip=%x count=%d\n", src_ip, icmp_val->count);
                    return XDP_DROP;
                }
            } else {
                icmp_val->timestamp = now;
                icmp_val->count = 1;
            }
        }
    }

    // Lookup exact match
    __u8 *action = bpf_map_lookup_elem(&rules, &key);
    if (action && *action == 1) {
        bpf_printk("MAP DROP: exact match\n");
        return XDP_DROP;
    }

    // Wildcard match: ignore ports
    key.src_port = 0;
    key.dst_port = 0;
    key.tcp_flags = 0;
    action = bpf_map_lookup_elem(&rules, &key);
    if (action && *action == 1) {
        bpf_printk("MAP DROP: wildcard match\n");
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
