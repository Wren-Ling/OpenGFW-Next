# PCAP regression samples

This directory stores the manifest for the OpenGFW PCAP replay regression suite.
Real packet captures are intentionally not committed to the repository because
they can contain addresses, hostnames, tokens, tenant identity, and payload
metadata from private networks.

## How to build the local sample set

Capture traffic only from systems you own or are explicitly authorized to test.
Prefer an isolated lab VM, short time windows, and a small snap length that keeps
the protocol metadata OpenGFW needs without retaining unnecessary payload bytes:

```sh
sudo tcpdump -i ogfw-mon0 -s 256 -w testdata/pcap/hysteria2-quic-auth-lab.pcap 'host 192.0.2.10'
```

Before copying a sample into this directory, sanitize it with your approved
workflow. A typical flow is:

1. Trim the capture to the smallest window that reproduces the rule hit.
2. Remove unrelated packets from other VMs or tenants.
3. Rewrite IP addresses and MAC addresses with documentation/test ranges.
4. Remove private hostnames, credentials, tokens, and application payloads.
5. Replay the sanitized sample and update `samples.yaml` with observed rules and score bounds.

Useful tools include `editcap`, `mergecap`, `tcpdump`, `tcprewrite`, and any
internal DLP/sanitization pipeline required by your environment. Keep raw
captures outside this repository; `.gitignore` excludes common capture formats
and local staging directories by default.

## Running replay tests

The default manifest path for `go test ./...` is `testdata/pcap/samples.yaml` at
the repository root. If a listed PCAP is missing, its subtest is skipped instead
of failed, so CI can run without private captures.

```sh
PATH="/usr/local/go/bin:$PATH" GOCACHE="$PWD/.gocache" go test ./...
```

To use a different local manifest, pass an absolute path so package test working
directories do not matter:

```sh
OPENGFW_PCAP_MANIFEST="$PWD/testdata/pcap/samples.yaml" go test ./cmd -run TestExampleRulesWithPCAPManifest -v
```
