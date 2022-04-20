/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */

#ifndef __BPF_H
#define __BPF_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

#define SNI_MAX_LEN 30
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TLS_HANDSHAKE_FLAG 0x16
#define ETH_P_IP 0x0800
#define TLS_HANDSHAKE_CLIENT_HELLO  0x01
#define TLS_HANDSHAKE_CH_OFFSET  37
#define TLS_SERVER_NAME_TYPE  0x00
#define TLS_SERVER_NAME_HOST_TYPE  0x00

struct rb_data {
    uint32_t ip_src;
    uint32_t ip_dst;
    uint16_t port_src;
    uint16_t port_dst;
    unsigned char SNI[SNI_MAX_LEN];
    uint16_t SNI_len;
};

struct connection_map_key {
    uint32_t ip_src;
    uint32_t ip_dst;
    uint16_t port_src;
    uint16_t port_dst;
};

struct SNI_map_key {
    unsigned char SNI[SNI_MAX_LEN];
};

struct tlshdr {
    unsigned char content_type;
    unsigned char version[2];
    unsigned char length[2];
    unsigned char handshake_type;
};

#endif /* __BPF_H */
