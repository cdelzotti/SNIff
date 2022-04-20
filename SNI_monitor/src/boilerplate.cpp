//
// Created by elkins on 1/28/22.
//

#include "boilerplate.h"
#include "program.skel.h"

namespace boilerplate {
    bool exiting = false;
    const std::string argp_program_version = "SNIff 0.1";
    const std::string argp_program_bug_address = "elk1ns@outlook.fr";
    const char *argp_program_doc = "A simple BPF-based SNI sniffer";
    const struct argp_option opts[] = {
            {"interface", 'i', "INT", 0, "The interface index to attach to (See numbers in ouput of the `ip link` command)"},
            {"interval", 't', "INT", 0, "The sampling interval (in seconds)"},
            {"output", 'o', "FILE", 0, "The output file"},
            {"version",  'V', NULL,          0, "Print version and exit"},
            {0},
    };
    const struct argp argp = {
            .options = opts,
            .parser = parse_arg,
            .doc = argp_program_doc,
    };
    struct program_bpf *skel = nullptr;

    int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
        if (level == LIBBPF_DEBUG)
            return 0;
        return vfprintf(stderr, format, args);
    }

    error_t parse_arg(int key, char *arg, struct argp_state *state) {
        struct env *env = (struct env *) state->input;
        switch (key) {
           case 'i':
                errno = 0;
                env->interface = strtol(arg, NULL, 10);
                if (errno || env->interface <= 0) {
                    fprintf(stderr, "Invalid interface index: %s\n", arg);
                    argp_usage(state);
                }
                break;
            case 't':
                errno = 0;
                env->interval = strtol(arg, NULL, 10);
                if (errno || env->interval <= 0) {
                    fprintf(stderr, "Invalid interval: %s\n", arg);
                    argp_usage(state);
                }
                break;
            case 'o':
                env->outputfile = arg;
                break;
            case ARGP_KEY_ARG:
                argp_usage(state);
                break;
            default:
                return ARGP_ERR_UNKNOWN;
        }
        return 0;
    }

    void bump_memlock_rlimit() {
        struct rlimit rlim_new = {
                .rlim_cur	= RLIM_INFINITY,
                .rlim_max	= RLIM_INFINITY,
        };
        if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
            fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
            exit(1);
        }
    }

    void sig_handler(int sig) {
        exiting = true;
    }

    int load_program(){
        int err;
        /* Load and verify BPF application */
        skel = program_bpf__open();
        if (!skel) {
            fprintf(stderr, "Failed to open and load BPF skeleton\n");
            return 1;
        }

        /* Load & verify BPF programs */
        err = program_bpf__load(skel);
        if (err) {
            fprintf(stderr, "Failed to load and verify BPF skeleton\n");
            return err;
        }
        return 0;
    }

    int unload_program () {
        program_bpf__destroy(skel);
        return 0;
    }
}