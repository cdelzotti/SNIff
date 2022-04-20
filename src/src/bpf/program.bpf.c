// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "../../../vmlinux/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "program.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Create a per CPU hash map to store the connection state
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct connection_map_key));
    __uint(value_size, sizeof(struct SNI_map_key));
    __uint(max_entries, 4096*64);
} connections SEC(".maps");

// Create a per CPU hash map to map the SNI to a packet size counter
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(key_size, sizeof(struct SNI_map_key));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 4096*64);
} sni_sizes SEC(".maps");

static void register_packet_size(struct connection_map_key *connection, __u64 *packet_size){
    struct SNI_map_key *value = bpf_map_lookup_elem(&connections, connection);
    if (value) {
        /* Found connection in map */
        __u32 *packets_size = bpf_map_lookup_elem(&sni_sizes, value);
             if (packets_size) {
                (*packets_size) += *packet_size;
            } else {
                if (packet_size) {
                    bpf_map_update_elem(&sni_sizes, value, packet_size, BPF_NOEXIST);
                }
                // bpf_map_update_elem(&sni_sizes, value, packet_size, BPF_NOEXIST);
            }
    } else {
        /* Connection not found, must be registered as unknown */
        /* Create generic key used to regiter unkown packets */
        struct SNI_map_key key;
        for (int i = 0; i < SNI_MAX_LEN; ++i) {
            key.SNI[i] = '*';
        }
        key.SNI[SNI_MAX_LEN - 1] = '\0';
        __u32 *packets_size = bpf_map_lookup_elem(&sni_sizes, &key);
        if (packets_size) {
            (*packets_size) += *packet_size;
        } else {
            bpf_map_update_elem(&sni_sizes, &key, packet_size, BPF_NOEXIST);
        }

    }
}

static bool parse_SNI(struct SNI_map_key *sni, void* tls_start, void* data_end) {
    /* Parse payload */
    struct tlshdr *tlshdr = tls_start;
    if ((void*)tlshdr + sizeof(tlshdr) > data_end) {
        return TC_ACT_OK;
    }
    /* Check that packet contains a TLS handshake client hello*/
    if (tlshdr->content_type != TLS_HANDSHAKE_FLAG || tlshdr->handshake_type != TLS_HANDSHAKE_CLIENT_HELLO){
        // __u64 packet_size = skb->len;
        // register_packet_size(&connection_description, &packet_size);
        // return TC_ACT_OK;
        return false;
    }
    /* Skip useless bytes */
    unsigned char *pointer = (void *)tlshdr + sizeof(struct tlshdr) + TLS_HANDSHAKE_CH_OFFSET;
    if ((void*)pointer + sizeof(unsigned char) > data_end) {
        return false;
    }
   pointer += sizeof(unsigned char) + *pointer;
   uint16_t *ciph_len = (void *)pointer;
   if ((void*)ciph_len + sizeof(uint16_t) > data_end) {
        return false;
    }
   uint16_t ciph_len_val = bpf_ntohs(*ciph_len);
    if (ciph_len_val > 512) { // Max size for ciph len, needed to keep the verifier happy
        return false;
    }
   pointer += sizeof(uint16_t) + ciph_len_val;
   if ((void*)pointer + sizeof(unsigned char) > data_end) {
        return false;
    }
   pointer += sizeof(unsigned char) + *pointer + 2; // Skip the extension length

    /* Find SNI */
    uint16_t SNI_len = 0;
    // Set array to 0
    for (int i = 0; i < SNI_MAX_LEN; ++i) {
        sni->SNI[i] = 0;
    }
    sni->SNI[SNI_MAX_LEN - 1] = '\0';
    for (int i = 0; i < 50; ++i) {
        /* Get extension type */
        uint16_t *ext_type = (void *)pointer;
        if ((void*)ext_type + sizeof(uint16_t) > data_end) {
            return false;
        }
        uint16_t ext_type_val = bpf_ntohs(*ext_type);
        /* Get extension length */
        uint16_t *ext_len = (void *)pointer + sizeof(uint16_t);
        if ((void*)ext_len + sizeof(uint16_t) > data_end) {
            return false;
        }
        uint16_t ext_len_val = bpf_ntohs(*ext_len);
        if (ext_len_val > 512) { // Max size for ext len, needed to keep the verifier happy
            break;
        }
        /* Check if we found the SNI */
        pointer += sizeof(uint16_t) + sizeof(uint16_t); // Skip past the extension headers
        if (ext_type_val == TLS_SERVER_NAME_TYPE) {
            pointer += 2; // Skip past the length of the SNI
            unsigned char *server_type = (void *)pointer;
            if ((void*)server_type + sizeof(unsigned char) > data_end) {
                return false;
            }
            if (*server_type != TLS_SERVER_NAME_HOST_TYPE) {
                return false;
            }
            pointer += sizeof(unsigned char);
            uint16_t *sni_len_val = (void *)pointer;
            if ((void*)sni_len_val + sizeof(uint16_t) > data_end) {
                return false;
            }
            SNI_len = bpf_ntohs(*sni_len_val);
            pointer += sizeof(uint16_t);
            for (int i = 0; i < SNI_MAX_LEN - 1; ++i) {
                if (i == SNI_len) {
                    break;
                }
                unsigned char *sni_ = (void *)pointer;
                if ((void*)sni_ + sizeof(unsigned char) > data_end) {
                    return false;
                }
                sni->SNI[i] = *sni_;
                pointer += sizeof(unsigned char);
            }
            break;
        } else {
            /* Skip extension */
            pointer += ext_len_val;
        }
    }
    return true;
}


SEC("xdp")
int xdp_parse_ingress(struct xdp_md *ctx)
{
    // Parse ethernet header
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }
    // Parse IP header
    struct iphdr *iph = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*iph) > data_end) {
        return XDP_PASS;
    }
    // Check if it is a TCP packet
    if (iph->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }
    // Parse TCP header
    struct tcphdr *tcph = data + sizeof(*eth) + sizeof(*iph);
    if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcph) > data_end) {
        return XDP_PASS;
    }
    // Parse TLS header
    void *tls_start;
    unsigned char tcp_size = tcph->doff << 2;
    tls_start = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + tcp_size;
    /* Create connection description */
    struct connection_map_key connection_description = {
        .port_src = bpf_ntohs(tcph->dest),
        .port_dst = bpf_ntohs(tcph->source),
        .ip_dst = iph->saddr,
        .ip_src = iph->daddr,
    };

    /* Parse payload */
    struct SNI_map_key SNI_description;
    if (!parse_SNI(&SNI_description, tls_start, data_end)){
        __u64 packet_len = ctx->data_end - ctx->data;
        register_packet_size(&connection_description,&packet_len);
        return XDP_PASS;
    }
    // /* Create entry in map */
    bpf_map_update_elem(&connections, &connection_description, &SNI_description, BPF_NOEXIST);
    return XDP_PASS;
}

SEC("tc")
int tx_example(struct __sk_buff *skb){
    /* Pull nonlinear part of SKB */
    bpf_skb_pull_data(skb, skb->len);
    void *data_end = (void *)(long) skb->data_end;
    void *data = (void *)(long) skb->data;
    /* Parse ethernet headers */
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;
    /* Check that packet contains IP */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    /* Parse IP headers */
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return TC_ACT_OK;
    /* Check that packet contains TCP */
    void *tls_start;
    uint32_t port_src, port_dst;
    if (ip->protocol == IPPROTO_TCP){
        /* Parse TCP headers */
        struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if ((void*)tcp + sizeof(struct tcphdr) > data_end)
            return TC_ACT_OK;
        port_dst = bpf_ntohs(tcp->dest);
        port_src = bpf_ntohs(tcp->source);
        /* Skipp TCP options */
        unsigned char tcp_size = tcp->doff << 2;
        tls_start = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + tcp_size;
    } else if (ip->protocol == IPPROTO_UDP){
        /* TODO : Parsing QUIC packets */
        /* Meanwhile, drop it to force TCP */
        struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if ((void*)udp + sizeof(struct udphdr) > data_end)
            return TC_ACT_OK;
        port_dst = bpf_ntohs(udp->dest);
        port_src = bpf_ntohs(udp->source);
        if (port_dst == 443 || port_src == 443)
            return TC_ACT_SHOT;
        return TC_ACT_OK;
    } else {
        return TC_ACT_OK;
    }
    /* Create connection description */
    struct connection_map_key connection_description = {
        .port_src = port_src,
        .port_dst = port_dst,
        .ip_dst = ip->daddr,
        .ip_src = ip->saddr,
    };
    /* Parse payload */
    struct SNI_map_key SNI_description;
    if (!parse_SNI(&SNI_description, tls_start, data_end)){
        __u64 packet_len = skb->len;
        register_packet_size(&connection_description,&packet_len);
        return TC_ACT_OK;
    }
    // /* Create entry in map */
    bpf_map_update_elem(&connections, &connection_description, &SNI_description, BPF_NOEXIST);
    return TC_ACT_OK;
}

