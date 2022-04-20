//
// Created by elkins on 1/28/22.
//
#include <argp.h>
#include <string>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <string>


#ifndef SNI_SNIFFER_BOILERPLATE_H
#define SNI_SNIFFER_BOILERPLATE_H

struct program_bpf;

namespace boilerplate {

    error_t parse_arg(int key, char *arg, struct argp_state *state);

    struct env {
        int interface;
        int interval;
        std::string outputfile;
    };
    extern const std::string argp_program_version;
    extern const std::string argp_program_bug_address;
    extern const char *argp_program_doc;
    extern const struct argp_option opts[];
    extern const struct argp argp;
    extern bool exiting;
    extern struct program_bpf *skel;

    int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args);

    void bump_memlock_rlimit();

    void sig_handler(int sig);

    int load_program();

    int unload_program();

}


#endif //SNI_SNIFFER_BOILERPLATE_H
