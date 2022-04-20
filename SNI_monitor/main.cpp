#include <iostream>
#include <ctime>
#include <fstream>
#include <unistd.h>
#include <argp.h>
#include "src/boilerplate.h"
#include "src/bpf.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "program.skel.h"
#include <csignal>
#include "src/bpf/program.bpf.h"

using namespace boilerplate;
using namespace bpf;

void cleanup(struct ring_buffer *rb) {
    if (rb != NULL) {
    ring_buffer__free(rb);
    }
    bpf::detach_program();
    boilerplate::unload_program();
}

void get_keys(int fd,int *num_keys, struct SNI_map_key *array_key) {
    struct SNI_map_key prev_key = {};
    struct SNI_map_key key;
    int i = 0;
    while(bpf_map_get_next_key(fd, &prev_key, &key) == 0) {
        array_key[i] = key;
        prev_key=key;
        i++;
    }
    *num_keys = i;
    return;
}

void mixed_print(std::string *str, bool write_to_file, std::ofstream &file) {
    if (write_to_file) {
        file << *str;
    } else {
        std::cout << *str;
    }
}


void gather_map_value(int fd, struct boilerplate::env *env)
{
    // Open file to write strings later
    std::ofstream outfile;
    bool write_to_file = false;
    if (env->outputfile != "") {
        write_to_file = true;
        // Open file to append
        outfile.open(env->outputfile, std::ofstream::out | std::ofstream::app);
        if (!outfile.is_open()) {
            std::cerr << "Could not open output file, write in stdout instead" << std::endl;
            write_to_file = false;
        }
    } else {
        printf("No output file specified, write to stdout\n");
    }

	/* For percpu maps, userspace gets a value per possible CPU */
	unsigned int nr_cpus = libbpf_num_possible_cpus();
    int num_keys = 0;
    struct SNI_map_key keys[256];
    get_keys(fd,&num_keys, keys);
    // Convert char* to std::string
    std::string s;
    // Add timestamp
    s += "Timestamp: ";
    s += std::to_string(std::time(0));
    s += "\nSNI:\n";
    for (int i = 0; i < num_keys; i++)
    {
        struct SNI_map_key key = keys[i];
        __u64 values[nr_cpus];
        __u64 total_value = 0;
        bpf_map_lookup_elem(fd, &key, values);
        // Gather map values for each CPU and sum them up
        for (int i = 0; i < nr_cpus; i++) {
            total_value  += values[i];
            values[i] = 0;
        }
        // Delete the map entry
        bpf_map_delete_elem(fd, &key);
        // Print unsigned char to string
        s += (char *) keys[i].SNI;
        s += " : ";
        s += std::to_string(total_value);
        s += "\n";
    }
    s += "\n";
    mixed_print(&s, write_to_file, outfile);
    return;
}

int main(int argc, char **argv) {
    // Parse arguments
    struct boilerplate::env env;
    env.interface = 0;
    env.interval = 1;
    env.outputfile = "";
    int err = argp_parse(&boilerplate::argp, argc, argv, 0, 0, &env);
    if (err) {
        printf("Error parsing arguments\n");
        cleanup(NULL);
    }
    bpf::env = &env;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);
    /* Bump RLIMIT_MEMLOCK to create BPF maps */
    boilerplate::bump_memlock_rlimit();
    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, boilerplate::sig_handler);
    signal(SIGTERM, boilerplate::sig_handler);
    /* Load BPF program */
    boilerplate::load_program();
    /* Attach BPF program */
    bpf::attach_program();

    /* Retrieve MAP */
    int sni_map_fd = bpf_map__fd(boilerplate::skel->maps.sni_sizes);
    if (sni_map_fd < 0) {
        err = -1;
        fprintf(stderr, "Failed to get map fd\n");
        cleanup(NULL);
    }

    /* Process events */
    boilerplate::exiting = false;
    __int64_t sleep_time = env.interval * 1000000;
    while (!boilerplate::exiting) {
        usleep(sleep_time);
        gather_map_value(sni_map_fd, &env);
    }
    gather_map_value(sni_map_fd, &env);

    /* Clean up */
    cleanup(NULL);

    return 0;
}
