//
// Created by elkins on 1/28/22.
//
#include "bpf/libbpf.h"
#include "boilerplate.h"

#ifndef SNI_SNIFFER_BPF_H
#define SNI_SNIFFER_BPF_H


using namespace boilerplate;

namespace bpf {
    extern struct bpf_tc_hook *tc_hook;
    extern struct bpf_tc_opts *tc_opts;
    extern struct boilerplate::env *env;
    int attach_program();
    int detach_program();
    int handle_event(void *ctx, void *data, size_t data_sz);
}

#endif //SNI_SNIFFER_BPF_H
