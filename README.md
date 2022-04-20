# SNIff

SNIff is a simple eBPF-based sniffer that goes trough both incomming and outgoing traffic to look for TLS SNI fields. Once a SNI is catched, the connection is tagged (based on the 4-tuple) and every following packets will be counted as traffic for the tagged domain.

## How to Build

```bash
# Pull libbpf submodule
git submodule update --init --recursive
cd src/
cmake . -BBuild
cd Build
make
```

## How to run

```bash
./sniff -i I -t T -o output.txt
```

* **I** : the ifindex
* **T** : the sampling interval (in seconds)

### Example

```bash
./sniff -i 2 -t 10 -o output.txt
```

This will sniff traffic on interface 2 and print results each 10 seconds