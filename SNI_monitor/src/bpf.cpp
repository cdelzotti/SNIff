//
// Created by elkins on 1/28/22.
//

#include "bpf.h"
#include "boilerplate.h"
#include "program.skel.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "./bpf/program.bpf.h"
#include <linux/if_link.h>

using namespace boilerplate;

namespace bpf {
    struct boilerplate::env *env;
    bpf_tc_hook *tc_hook = nullptr;
    bpf_tc_opts *tc_opts = nullptr;

    int attach_program(){
        int err;
        /*Attach TC*/
        int fd = bpf_program__fd(boilerplate::skel->progs.tx_example);
        tc_hook = (struct bpf_tc_hook *) calloc(1, sizeof(struct bpf_tc_hook));
        *tc_hook = (struct bpf_tc_hook) {
                .sz = sizeof(struct bpf_tc_hook),
                .ifindex = env->interface,
                .attach_point = BPF_TC_EGRESS,
        };
        err = bpf_tc_hook_create(tc_hook);
        if (err) {
            fprintf(stderr, "Failed to attach TC to interface\n");
            return err;
        }
        tc_opts = (struct bpf_tc_opts *) calloc(1, sizeof(struct bpf_tc_opts));
        *tc_opts = (struct bpf_tc_opts) {
                .sz = sizeof(struct bpf_tc_opts),
                .prog_fd = fd,
        };
        err = bpf_tc_attach(tc_hook, tc_opts);
        if (err) {
            fprintf(stderr, "Failed to attach TC to interface\n");
            return err;
        }
        // /* Attach XDP */
        fd = bpf_program__fd(skel->progs.xdp_parse_ingress);
        err = bpf_set_link_xdp_fd(env->interface, fd, XDP_FLAGS_SKB_MODE);
        if (err) {
            fprintf(stderr, "Failed to attach XDP to interface\n");
            return err;
        }

        return err;
    }

    int detach_program(){
        int err;
        tc_opts->prog_fd = -1;
        err = bpf_tc_detach(tc_hook, tc_opts);
        tc_hook->attach_point = static_cast<bpf_tc_attach_point>(BPF_TC_INGRESS|BPF_TC_EGRESS);
        err = bpf_tc_hook_destroy(tc_hook);
        if (err) {
            fprintf(stderr, "Failed to destroy TC hook: %s\n", strerror(errno));
            return 1;
        }
        free(tc_opts);
        free(tc_hook);
        return 0;
    }
}