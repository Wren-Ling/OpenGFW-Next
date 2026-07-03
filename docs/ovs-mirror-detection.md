# OVS mirror VPN/proxy detection

This mode is intended for a Linux hypervisor that uses Open vSwitch. It captures
mirrored traffic from a monitor interface and reuses OpenGFW analyzers for
logging. It is passive: verdicts are ignored, so it will not block packets.

## Capture path

```text
VM tap/vnet port -> OVS bridge -> mirror -> ogfw-mon0 -> OpenGFW afpacket IO
```

Create an internal monitor port:

```sh
ovs-vsctl add-port br0 ogfw-mon0 -- set Interface ogfw-mon0 type=internal
ip link set ogfw-mon0 up
```

Mirror one VM port:

```sh
ovs-vsctl \
  -- --id=@mon get Port ogfw-mon0 \
  -- --id=@vm get Port vnet0 \
  -- --id=@m create Mirror name=ogfw-vnet0 select-src-port=@vm select-dst-port=@vm output-port=@mon \
  -- set Bridge br0 mirrors=@m
```

Mirror all bridge traffic instead:

```sh
ovs-vsctl \
  -- --id=@mon get Port ogfw-mon0 \
  -- --id=@m create Mirror name=ogfw-all select-all=true output-port=@mon \
  -- set Bridge br0 mirrors=@m
```

Run OpenGFW in JSON log mode:

```sh
sudo ./OpenGFW \
  --config examples/ovs-mirror-config.yaml \
  --log-format json \
  examples/ovs-vpn-detect-rules.yaml
```

## AF_PACKET throughput

By default, AF_PACKET uses the existing raw packet socket backend with a large
receive buffer. This keeps older deployments compatible. For higher PPS Linux
hosts, enable the TPACKET_V3 mmap ring backend with `ring: true`:

```yaml
io:
  mode: afpacket
  interface: ogfw-mon0
  frameSize: 0
  blockSize: 0
  numBlocks: 0
  pollTimeout: 0s
  ring: false
  fanoutGroup: null
  fanoutType: hash
```

`ring: false` keeps the raw socket path. `ring: true` sets `PACKET_VERSION` to
`TPACKET_V3`, configures `PACKET_RX_RING`, mmaps the ring, polls for block
wakeups, copies packet bytes out of each block before releasing it back to the
kernel, and reads `PACKET_STATISTICS` for kernel packet/drop counters. `blockSize`
must be page-size aligned, `frameSize` must be 16-byte aligned, and `blockSize`
must be divisible by `frameSize`; invalid ring sizing fails at startup instead
of silently falling back.

Leaving `frameSize`, `blockSize`, `numBlocks`, and `pollTimeout` as zero selects
backend-specific defaults. The raw socket backend keeps the older large read
buffer defaults. The TPACKET_V3 backend uses a high-PPS-oriented starting point:
`frameSize: 2048`, `blockSize: 4194304`, `numBlocks: 64`, and
`pollTimeout: 50ms` (`retire_blk_tov`). At startup, OpenGFW logs the derived
frame count, total ring bytes, retire timeout, and warnings when sizing is likely
to be weak for high PPS capture.

For sustained high PPS mirrors, tune in this order:

- Keep `frameSize` small for ordinary MTU traffic. Use `2048` or `4096`; reserve
  `65536` for jumbo/snaplen-heavy diagnostics because it drastically reduces
  frames per block.
- Increase `blockSize` and `numBlocks` before changing rules. Aim for at least
  128 MiB of ring memory on busy hosts, and more for bursty VM fleets.
- Keep `pollTimeout`/`retire_blk_tov` near `10ms` to `50ms`. Larger values can
  raise latency and hold partially filled blocks too long; tiny values increase
  wakeups and CPU overhead.
- Enable `metrics.enabled: true` and watch packet drops while testing. If drops
  appear, first raise ring memory, then add fanout workers or reduce analyzer
  load.

`fanoutGroup` enables Linux `PACKET_FANOUT` for deployments that intentionally
run multiple OpenGFW packet sockets against the same mirror interface. Set the
same `fanoutGroup` and `fanoutType` on every participant. Supported fanout types
are `hash`, `lb`, `cpu`, `rollover`, `rnd`, and `qm`. Leave `fanoutGroup: null`
for the normal single-process deployment.

Use fanout only when you run multiple OpenGFW processes or packet sockets on the
same capture interface. `hash` keeps a flow on the same consumer and is the
recommended first choice for stream analyzers. `cpu` can work well with IRQ/RPS
and process CPU affinity, while `lb` may split packets from one flow across
workers and should be tested carefully with stream-oriented rules.

CPU placement matters at high PPS. Pin the NIC or mirror interface IRQs, OpenGFW
processes, and any fanout group members to predictable CPUs with tools such as
`taskset`, `systemd` `CPUAffinity=`, RPS/XPS sysfs settings, or your host
orchestrator. Avoid sharing the capture CPUs with heavy VM vCPUs when measuring
drop rates.

Run the optional local stress harness on Linux after enabling mirror traffic:

```sh
sudo env \
  OPENGFW_AFPACKET_STRESS_IFACE=ogfw-mon0 \
  OPENGFW_AFPACKET_STRESS_DURATION=30s \
  OPENGFW_AFPACKET_STRESS_MAX_DROP_RATE=0.001 \
  PATH="/usr/local/go/bin:$PATH" \
  GOCACHE="$PWD/.gocache" \
  go test ./io -run TestAFPacketRingBackendLocalStress -v
```

The stress test is skipped unless `OPENGFW_AFPACKET_STRESS_IFACE` is set, and is
skipped on non-Linux hosts. Optional overrides are
`OPENGFW_AFPACKET_STRESS_FRAME_SIZE`, `OPENGFW_AFPACKET_STRESS_BLOCK_SIZE`,
`OPENGFW_AFPACKET_STRESS_NUM_BLOCKS`, and
`OPENGFW_AFPACKET_STRESS_RETIRE_BLK_TOV`.

## Linux systemd deployment

The repository includes production-oriented examples for a Linux OVS host:

- `examples/systemd/opengfw-ovs-detect.service`
- `examples/scripts/setup-ovs-mirror.sh`
- `examples/scripts/cleanup-ovs-mirror.sh`
- `examples/scripts/install-linux.sh`

Build and install the service files:

```sh
PATH="/usr/local/go/bin:$PATH" go build -o OpenGFW .
sudo examples/scripts/install-linux.sh --binary ./OpenGFW
```

The installer copies:

- `/usr/local/bin/OpenGFW`
- `/etc/opengfw/config.yaml`
- `/etc/opengfw/rules.yaml`
- `/etc/opengfw/examples/vm-inventory.yaml`
- `/etc/opengfw/examples/scripts/setup-ovs-mirror.sh`
- `/etc/opengfw/examples/scripts/cleanup-ovs-mirror.sh`
- `/etc/systemd/system/opengfw-ovs-detect.service`

The systemd unit runs:

```sh
/usr/local/bin/OpenGFW --config /etc/opengfw/config.yaml --log-format json /etc/opengfw/rules.yaml
```

AF_PACKET capture needs `CAP_NET_RAW`. The sample service runs as root and
keeps `CAP_NET_RAW` in its capability set. If you change it to a non-root user,
grant equivalent capture permission, for example with a service capability
override or `setcap cap_net_raw+ep /usr/local/bin/OpenGFW`.

Libvirt identity enrichment is optional. If `identity.libvirt.enabled` is true,
the service user must be able to run `virsh` and read the configured libvirt
URI, usually by running as root or by granting access to the libvirt socket
such as membership in the `libvirt` group. Prefer read-only libvirt access where
your host policy supports it.

Optional OVS quarantine is still disabled by default in `/etc/opengfw/config.yaml`.
If you enable `response.ovs.enabled`, the service user must also be allowed to
run `ovs-ofctl` against the target bridge. Running the sample service as root is
the simplest option; a non-root deployment must have permission to access the
OVS control sockets and any required OpenFlow tooling. If your host policy
requires extra Linux capabilities for OVS control-plane changes, add them with a
systemd override after you deliberately enable `response.ovs.enabled`.

Create a mirror for one VM/tap port:

```sh
sudo /etc/opengfw/examples/scripts/setup-ovs-mirror.sh setup -b br0 -p vnet0 -i ogfw-mon0
```

Mirror the whole bridge instead:

```sh
sudo /etc/opengfw/examples/scripts/setup-ovs-mirror.sh setup -b br0 --all -i ogfw-mon0 -n opengfw-all
```

Start and enable the service:

```sh
sudo systemctl enable --now opengfw-ovs-detect.service
sudo systemctl status opengfw-ovs-detect.service
```

View logs:

```sh
sudo journalctl -u opengfw-ovs-detect.service -f
sudo journalctl -u opengfw-ovs-detect.service -o json | jq 'select(.msg == "ruleset log")'
```

If `metrics.enabled: true` is set, check Prometheus metrics locally:

```sh
curl -fsS http://127.0.0.1:9090/metrics
```

Stop the service:

```sh
sudo systemctl stop opengfw-ovs-detect.service
sudo systemctl disable opengfw-ovs-detect.service
```

Remove the mirror created by the setup script:

```sh
sudo /etc/opengfw/examples/scripts/cleanup-ovs-mirror.sh -b br0 -p vnet0 -i ogfw-mon0
```

Remove both the mirror and the internal monitor port:

```sh
sudo /etc/opengfw/examples/scripts/cleanup-ovs-mirror.sh -b br0 -p vnet0 -i ogfw-mon0 --delete-monitor
```

If the mirror was created with `--all`, pass the same mirror name or `--all`:

```sh
sudo /etc/opengfw/examples/scripts/cleanup-ovs-mirror.sh -b br0 --all -i ogfw-mon0 -n opengfw-all
```

Clear OpenGFW quarantine flows if OVS response was enabled:

```sh
sudo OpenGFW ovs-quarantine clear --bridge br0 --cookie 0x4f474657
```

Filter rule hits:

```sh
jq 'select(.msg == "ruleset log")'
```

Rules can carry an optional severity. Missing severity defaults to `info`.

```yaml
- name: vpn-wireguard
  log: true
  severity: high
  expr: wireguard.message_type != nil
```

Each rule hit includes metadata when the capture backend can provide it:

```json
{
  "meta": {
    "capture.io": "afpacket",
    "capture.interface": "ogfw-mon0",
    "l2.src": "52:54:00:00:00:01",
    "l2.dst": "aa:bb:cc:dd:ee:ff",
    "l2.type": "IPv4"
  }
}
```

You can use that metadata inside rules:

```yaml
- name: vm-specific-wireguard
  log: true
  expr: (meta["l2.src"] == "52:54:00:00:00:01" || meta["l2.dst"] == "52:54:00:00:00:01") && wireguard.message_type != nil
```

For bidirectional mirrors, outbound packets usually carry the VM MAC as
`l2.src`, while inbound packets usually carry it as `l2.dst`.

Send rule hits to a webhook by setting `alert.webhookUrl`:

```yaml
alert:
  webhookUrl: "http://127.0.0.1:9000/opengfw-alert"
  queueSize: 1024
  timeout: 3s
  headers:
    Authorization: "Bearer change-me"
```

## Allowlists

Use `allowlist` for approved VMs, maintenance networks, known-good rules, or
approved VPN/proxy destinations. A matched rule hit is suppressed before risk
aggregation and before OVS response, so it cannot contribute to a risk threshold
or install quarantine flows.

```yaml
allowlist:
  enabled: true
  vmIds:
    - vm-100
  vmNames:
    - build-agent-01
  macs:
    - "52:54:00:00:00:01"
  ips:
    - "192.0.2.10"
  cidrs:
    - "192.0.2.0/24"
  rules:
    - tls-ech-observed
  domains:
    - approved-vpn.example.com
  logSuppressed: true
  webhookSuppressed: false
```

Matching checks VM identity metadata (`vm.id`, `vm.name`, `vm.mac`), observed
L2 MACs (`l2.src`, `l2.dst`), source/destination IPs, rule names, TLS/QUIC SNI,
and DNS question names. MAC and domain matching is case-insensitive. Domain
entries match the exact domain and its subdomains, so `example.com` also matches
`api.example.com`.

Suppressed hits are not sent to webhooks by default. Set
`webhookSuppressed: true` only when your webhook receiver is used as an audit
sink and can distinguish events with `"suppressed": true`. Keep
`logSuppressed: true` when tuning rules so local JSON logs retain an audit trail
with `allowlist.reason` and `allowlist.value`.

## Prometheus metrics

Metrics are disabled by default. Enable the lightweight HTTP endpoint when you
want Prometheus to scrape local counters:

```yaml
metrics:
  enabled: true
  listen: 127.0.0.1:9090
  path: /metrics
  packetStatsInterval: 30s
  packetDropWarnRate: 0.01
```

The endpoint exposes Prometheus text format and is served from a separate HTTP
goroutine. Packet workers only update in-memory counters.

Available metrics:

- `opengfw_rule_hits_total{rule,severity}`
- `opengfw_alert_dropped_total`
- `opengfw_allowlist_suppressed_total{reason}`
- `opengfw_response_applied_total{type}`
- `opengfw_response_failed_total{type}`
- `opengfw_streams_total{proto}`
- `opengfw_packet_kernel_packets_total`
- `opengfw_packet_kernel_drops_total`
- `opengfw_packet_kernel_drop_rate`
- `opengfw_packet_read_errors_total`
- `opengfw_packet_ring_losing_blocks_total`
- `opengfw_risk_buckets`
- `opengfw_risk_events_total{severity}`

The packet kernel counters come from packet IO implementations that can expose
kernel statistics. For AF_PACKET raw sockets and TPACKET_V3 rings this includes
`PACKET_STATISTICS` packet/drop data. `opengfw_packet_kernel_drop_rate` is the
cumulative ratio `drops / (packets + drops)`. TPACKET_V3 also exposes
`opengfw_packet_ring_losing_blocks_total`, counted when a ring block reaches
userspace with `TP_STATUS_LOSING`. `opengfw_packet_read_errors_total` counts
non-timeout read errors observed by the packet IO layer. Legacy
`opengfw_packetio_*` aliases are still emitted for existing dashboards.

OpenGFW samples packet IO stats every `metrics.packetStatsInterval` and emits a
warn log if the per-sample drop ratio exceeds `metrics.packetDropWarnRate` or if
any TPACKET_V3 losing blocks are observed. The monitor runs even when the HTTP
metrics endpoint is disabled, so warning logs remain available on minimal hosts.

`opengfw_allowlist_suppressed_total{reason}` increments when an allowlist entry
suppresses a rule hit before alert/risk/response processing. The `reason` label
is one of the matched allowlist dimensions, such as `vm.id`, `vm.name`,
`vm.mac`, `l2.src`, `l2.dst`, `ip`, `cidr`, `rule`, or `domain`.

`opengfw_risk_buckets` is a gauge of active risk aggregation buckets after
window pruning. `opengfw_risk_events_total{severity}` increments when a risk
threshold crossing emits an aggregated risk event.

Example Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: opengfw
    static_configs:
      - targets:
          - 127.0.0.1:9090
    metrics_path: /metrics
```

## VM identity inventory

Set `identity.inventory` to map observed MAC/IP addresses to VM identity:

```yaml
identity:
  inventory: examples/vm-inventory.yaml
```

Inventory files can use `entries:`:

```yaml
entries:
  - id: vm-100
    name: build-agent-01
    tenant: engineering
    macs:
      - "52:54:00:00:00:01"
    ips:
      - "192.0.2.10"
    interfaces:
      - ogfw-mon0
    vlans:
      - "100"
    labels:
      owner: ci
```

They can also be a plain array for smaller deployments:

```yaml
- id: vm-101
  name: test-desktop-01
  macs:
    - "52-54-00-00-00-02"
  ips:
    - "192.0.2.11/32"
```

MAC matching checks both `l2.src` and `l2.dst`. MAC addresses are normalized
before comparison, so `52:54:00:00:00:02`, `52-54-00-00-00-02`,
`5254.0000.0002`, and `525400000002` all refer to the same VM. IP entries can
be single addresses or CIDRs. `interfaces` and `vlans` are constraints: if set,
the observed `capture.interface` and `vlan.id` must match before the VM identity
is attached.

OpenGFW can also refresh VM identities from libvirt without adding CGO
dependencies. The provider calls `virsh list --all --name` and then
`virsh dumpxml <name>` for each domain, parsing VM name, UUID, and interface
MACs from the XML. Static inventory entries are merged first and therefore take
priority over libvirt entries when the same MAC/IP could match both.

```yaml
identity:
  inventory: examples/vm-inventory.yaml
  libvirt:
    enabled: true
    uri: qemu:///system
    refreshInterval: 1m
```

The OpenGFW process user must be able to run `virsh` against the selected
libvirt URI. On many Linux hosts this means running as root or adding the service
user to the `libvirt` group, then restarting the service/session. Verify access
before starting OpenGFW:

```sh
virsh --connect qemu:///system list --all --name
virsh --connect qemu:///system dumpxml vm-100
```

For systemd deployments, a dedicated user commonly needs both access to
`/var/run/libvirt/libvirt-sock` and the `virsh` binary in `PATH`. If your libvirt
socket policy is stricter, prefer granting read-only libvirt access rather than
running the whole packet pipeline with unnecessary privileges.

When a stream matches an entry, OpenGFW adds metadata such as:

```json
{
  "meta": {
    "vm.id": "vm-100",
    "vm.name": "build-agent-01",
    "vm.tenant": "engineering",
    "vm.label.owner": "ci",
    "identity.source": "inventory",
    "identity.match": "l2.src"
  }
}
```

For libvirt-derived entries, `identity.source` is `libvirt`, `vm.id` is the
domain UUID, `vm.name` is the domain name, and `vm.mac` is the matched interface
MAC. Libvirt refreshes replace an internal inventory snapshot atomically, so
packet workers keep using the last good snapshot while `virsh` is running.

Webhook events include the same severity:

```json
{
  "rule": "vpn-wireguard",
  "severity": "high",
  "src": "192.0.2.10:51820",
  "dst": "198.51.100.10:51820"
}
```

Rules can then target a VM directly:

```yaml
- name: build-agent-wireguard
  log: true
  expr: meta["vm.name"] == "build-agent-01" && wireguard.message_type != nil
```

## JA3/JA4 fingerprints

The sample rules use configurable fingerprint lookups instead of hard-coded
hash strings. TLS ClientHello exposes `tls.req.ja3_hash` and `tls.req.ja4`;
QUIC ClientHello exposes `quic.req.ja3_hash` and `quic.req.ja4`.

```yaml
- name: tls-suspicious-ja3
  log: true
  severity: medium
  expr: suspicious_ja3(tls.req.ja3_hash)

- name: tls-suspicious-ja4
  log: true
  severity: medium
  expr: suspicious_ja4(tls.req.ja4)

- name: quic-suspicious-ja3
  log: true
  severity: medium
  expr: suspicious_quic_ja3(quic.req.ja3_hash)

- name: quic-suspicious-ja4
  log: true
  severity: medium
  expr: suspicious_quic_ja4(quic.req.ja4)
```

Maintain the hash lists in `fingerprints`. Empty lists are safe and simply make
the fingerprint rules not match. Fingerprints can be kept inline for small labs,
but the example configuration loads external files so local datasets can be
reviewed and updated without editing the main config.

```yaml
fingerprints:
  ja3:
    files:
      - fingerprints/ja3.yaml
    suspicious:
      - hash: "replace-with-local-tls-ja3-md5"
        name: "mihomo-utls-lab"
        severity: medium
        tags: ["mihomo", "utls", "lab"]
  ja4:
    files:
      - fingerprints/ja4.yaml
    suspicious: []
  quicJa3:
    files:
      - fingerprints/quic-ja3.yaml
    suspicious: []
  quicJa4:
    files:
      - fingerprints/quic-ja4.yaml
    suspicious: []
```

Each external file can contain a top-level `suspicious` list, or a full
`fingerprints.<set>.suspicious` tree. Relative paths are resolved relative to the
main config file. The installed example creates empty files under
`fingerprints/`.

Do not copy public placeholder fingerprints blindly into production. Do not use
hashes from examples, blog posts, issue trackers, or public malware/proxy lists
unless you have reproduced and validated them locally. JA3 and JA4 values vary by
client, library, version, OS, uTLS profile, and evasion strategy. Capture known
good and known suspicious samples from your own environment, validate them
against normal VM workloads, then add only fingerprints that are useful in your
local risk model. The `name`, `severity`, and `tags` fields are for human
maintenance; the builtin functions match on `hash`.

JA4 canonicalizes TLS/QUIC ClientHello details into an `a_b_c` fingerprint and
is often more stable than raw extension order. OpenGFW keeps the existing JA3
fields unchanged and emits JA4 beside them. Treat JA4 as a correlation signal,
not final proof of proxy use; pair it with SNI/DNS, ALPN, ECH, flow behavior,
destination reputation, VM identity, and allowlists.

To sample fingerprints from a controlled mihomo/xray lab, run the client against
your own server while capturing the VM mirror interface, then extract unique
fingerprints with `tshark`:

```sh
sudo tcpdump -i ogfw-mon0 -s 512 -w mihomo-lab.pcap 'host 192.0.2.10'

examples/scripts/extract-ja-fingerprints.sh \
  -p mihomo-lab.pcap \
  -k ja3 \
  -n mihomo-1.18.8-lab \
  -t mihomo -t lab > examples/fingerprints/ja3.yaml

examples/scripts/extract-ja-fingerprints.sh \
  -p xray-reality-lab.pcap \
  -k ja4 \
  -n xray-reality-lab \
  -t xray -t reality > examples/fingerprints/ja4.yaml
```

Use the same workflow for `quicJa3` and `quicJa4` when QUIC handshakes are
visible and your `tshark` build exposes the corresponding JA fields. Always run
the PCAP replay suite and compare against HTTP/3, game, voice/video, update, and
approved VPN traffic before raising weights or enabling responses.

## Domain keyword lists

The example SNI/DNS rules use `domain_keyword(value, listName)` instead of
embedding regexes in every rule. The lists live in the main config:

```yaml
domainKeywords:
  proxy: [v2ray, xray, clash, mihomo, hysteria, tuic, trojan, shadowsocks, sing-box, reality, shadowtls, anytls, masque]
  vlessReality: [vless, xray, xtls, reality]
  shadowTLSAnyTLS: [shadowtls, anytls, sing-box]
```

Keyword matches are case-insensitive substring checks after trimming a trailing
dot from the observed name. They are operational breadcrumbs, not proof of proxy
use. Keep the lists small, reviewed, and paired with allowlists for approved
domains.

## VM risk aggregation

For noisy or medium-confidence signals, enable `risk` to aggregate multiple rule
hits into a VM-level risk event. Aggregation uses `vm.id` first, then `vm.mac`,
then `ip.src`. This keeps identity-correlated VMs stable across address changes
while still allowing IP-only deployments to produce risk alerts.

```yaml
risk:
  enabled: true
  window: 10m
  thresholds:
    alert: 9
    response: 16
  weights:
    vpn-wireguard: 6
    vpn-openvpn: 6
    proxy-trojan-heuristic: 5
    proxy-fully-encrypted-tcp: 4
    proxy-socks: 4
    tls-ech-observed: 1
    quic-ech-observed: 1
    udp443-long-lived-no-quic-sni: 0
    hysteria2-quic-like-weak-signal: 3
    hysteria2-custom-udp-weak-signal: 1
    tuic-quic-like-weak-signal: 3
    tuic-short-quic-burst-weak-signal: 1
    masque-connect-udp-weak-signal: 1
    tls-suspicious-ja3: 3
    tls-suspicious-ja4: 3
    quic-suspicious-ja3: 3
    quic-suspicious-ja4: 3
    tls-proxy-domain-observed: 2
    tls-vless-reality-domain-weak-signal: 1
    tls-shadowtls-anytls-domain-weak-signal: 1
    dns-udp-proxy-domain-observed: 2
    dns-vless-reality-domain-weak-signal: 1
    dns-shadowtls-anytls-domain-weak-signal: 1
    dns-tcp-proxy-domain-observed: 2
    dns-tcp-vless-reality-domain-weak-signal: 1
    dns-tcp-shadowtls-anytls-domain-weak-signal: 1
```

Rules not listed under `risk.weights` have weight `1`. A weight of `0` disables
that rule for risk scoring while still allowing it to be logged and replayed.
Treat direct protocol markers such as WireGuard and OpenVPN as higher weights,
locally validated JA3/JA4 as medium weights, and modern-proxy behavior or domain
keyword rules as low to medium weights. The default example deliberately gives
the broad `udp443-long-lived-no-quic-sni` helper weight `0`; it is useful replay
context but too similar to normal HTTP/3, games, and voice/video to increase
risk by itself. Keep MASQUE candidates, custom UDP-port Hysteria2 candidates,
short TUIC bursts, ECH-only observations, and broad keyword hits at weight `1`
until local pcaps show they are useful. The default example keeps
Hysteria2/TUIC QUIC-like flow shape at weight `3`, but custom UDP, MASQUE,
REALITY, ShadowTLS, AnyTLS, and domain-keyword weak signals at weight `1`.
When the cumulative score inside
`thresholds.alert`, OpenGFW sends a webhook event with `type: "risk"`:

```json
{
  "type": "risk",
  "rule": "risk",
  "severity": "medium",
  "meta": {
    "vm.id": "vm-100",
    "vm.mac": "52:54:00:00:00:01",
    "risk.key_type": "vm.id",
    "risk.key": "vm-100",
    "risk.score": "9"
  },
  "risk": {
    "keyType": "vm.id",
    "key": "vm-100",
    "score": 9,
    "windowSeconds": 600,
    "alertThreshold": 9,
    "responseThreshold": 16
  }
}
```

Risk alerts are emitted once per threshold crossing. After older hits slide out
of the window and the score falls below the threshold, a later crossing can emit
again.

## Modern Proxy Signal Boundaries

Some protocols expose recognizable cleartext or structural markers to passive
capture. Direct WireGuard handshakes, OpenVPN packet counters, SOCKS handshakes,
and the Trojan length heuristic can be relatively direct signals when the
traffic is visible.

Most modern proxy transports are different. Hysteria2, TUIC, MASQUE,
VLESS/REALITY, ShadowTLS, and AnyTLS are designed to look like QUIC, HTTP/3, or
ordinary TLS. Passive OVS mirror detection cannot prove that a VM is using one
of these protocols from encrypted payloads alone. OpenGFW therefore treats them
as weak risk signals built from observable metadata: UDP flow shape, QUIC/TLS
ClientHello fields, SNI/DNS names, JA3/JA4 entries that you configured, ECH
presence, and VM identity context.

Practical boundaries:

- Hysteria2 and TUIC can often only be hunted as QUIC-like UDP behavior:
  long-lived bidirectional UDP flows, large packet ratios, sparse or missing
  parseable QUIC SNI/ALPN, and locally validated QUIC JA3/JA4 fingerprints.
- MASQUE/CONNECT-UDP cannot be confirmed from passive QUIC payloads because the
  HTTP method and target are encrypted. OpenGFW can only flag HTTP/3-shaped,
  long-lived UDP/443 behavior as a candidate.
- VLESS/REALITY, ShadowTLS, and AnyTLS are TLS camouflage families. Without
  endpoint cooperation, OpenGFW can observe SNI/DNS, ECH, ALPN, JA3/JA4, and flow
  context, but not the inner proxy protocol.
- Domain keyword rules are operational breadcrumbs, not proof. They are most
  useful in labs, unmanaged VM fleets, or when paired with destination
  reputation and allowlists.

Do not use these weak signals alone for blocking. They should feed risk
aggregation and human review unless you have validated them against your own
traffic.

See `docs/proxy-protocol-detection-notes.md` for the protocol-by-protocol
passive detection boundary and the PCAP field model used to tune these rules.

## UDP behavior signal

The `udpflow` analyzer tracks basic per-stream behavior for UDP traffic:

- `udpflow.src_port`
- `udpflow.dst_port`
- `udpflow.packet_count`
- `udpflow.tx_packet_count`
- `udpflow.rx_packet_count`
- `udpflow.tx_packet_ratio`
- `udpflow.rx_packet_ratio`
- `udpflow.first_packet_len`
- `udpflow.second_packet_len`
- `udpflow.third_packet_len`
- `udpflow.fourth_packet_len`
- `udpflow.first_tx_packet_len`
- `udpflow.first_rx_packet_len`
- `udpflow.min_packet_len`
- `udpflow.max_packet_len`
- `udpflow.avg_packet_len`
- `udpflow.tx_bytes`
- `udpflow.rx_bytes`
- `udpflow.total_bytes`
- `udpflow.tx_byte_ratio`
- `udpflow.rx_byte_ratio`
- `udpflow.duration_seconds`
- `udpflow.packet_rate`
- `udpflow.byte_rate`
- `udpflow.long_lived`
- `udpflow.bidirectional`
- `udpflow.balanced_directions`
- `udpflow.tx_dominant`
- `udpflow.rx_dominant`
- `udpflow.direction_change_count`
- `udpflow.max_same_direction_run`
- `udpflow.large_packet_count`
- `udpflow.large_packet_ratio`
- `udpflow.small_packet_count`
- `udpflow.small_packet_ratio`
- `udpflow.len_bucket_empty_count`
- `udpflow.len_bucket_le64_count`
- `udpflow.len_bucket_le128_count`
- `udpflow.len_bucket_le256_count`
- `udpflow.len_bucket_le512_count`
- `udpflow.len_bucket_le1024_count`
- `udpflow.len_bucket_le1200_count`
- `udpflow.len_bucket_gt1200_count`
- `udpflow.len_bucket_empty_ratio`
- `udpflow.len_bucket_le64_ratio`
- `udpflow.len_bucket_le128_ratio`
- `udpflow.len_bucket_le256_ratio`
- `udpflow.len_bucket_le512_ratio`
- `udpflow.len_bucket_le1024_ratio`
- `udpflow.len_bucket_le1200_ratio`
- `udpflow.len_bucket_gt1200_ratio`
- `udpflow.udp443`

The example rules below are intended for Hysteria2/TUIC/QUIC-like and MASQUE
hunting, but they are only behavioral clues:

```yaml
- name: udp443-long-lived-no-quic-sni
  log: true
  severity: medium
  expr: udpflow.udp443 && udpflow.long_lived && udpflow.bidirectional && udpflow.packet_count >= 12 && udpflow.balanced_directions && udpflow.large_packet_ratio >= 0.30 && quic.req.sni == nil

- name: hysteria2-quic-like-weak-signal
  log: true
  severity: medium
  expr: udpflow.udp443 && udpflow.long_lived && udpflow.bidirectional && udpflow.balanced_directions && udpflow.packet_count >= 20 && udpflow.large_packet_count >= 10 && udpflow.large_packet_ratio >= 0.45 && (udpflow.len_bucket_gt1200_ratio >= 0.10 || udpflow.len_bucket_le1200_ratio >= 0.20) && quic.req.sni == nil

- name: hysteria2-custom-udp-weak-signal
  log: true
  severity: low
  expr: udpflow.dst_port >= 1024 && udpflow.dst_port != 443 && udpflow.long_lived && udpflow.bidirectional && udpflow.balanced_directions && udpflow.packet_count >= 30 && udpflow.large_packet_count >= 10 && udpflow.avg_packet_len >= 600 && udpflow.tx_byte_ratio >= 0.10 && udpflow.rx_byte_ratio >= 0.10 && quic.req.sni == nil

- name: tuic-quic-like-weak-signal
  log: true
  severity: medium
  expr: udpflow.udp443 && udpflow.bidirectional && udpflow.balanced_directions && udpflow.packet_count >= 8 && udpflow.first_packet_len >= 1000 && udpflow.large_packet_count >= 4 && udpflow.large_packet_ratio >= 0.40 && (quic.req.alpn == nil || !("h3" in quic.req.alpn))

- name: tuic-short-quic-burst-weak-signal
  log: true
  severity: low
  expr: udpflow.udp443 && udpflow.bidirectional && udpflow.balanced_directions && udpflow.packet_count >= 8 && udpflow.packet_count < 20 && udpflow.first_packet_len >= 1000 && udpflow.large_packet_count >= 4 && quic.req.sni == nil

- name: masque-connect-udp-weak-signal
  log: true
  severity: low
  expr: udpflow.udp443 && udpflow.long_lived && udpflow.bidirectional && udpflow.balanced_directions && udpflow.packet_count >= 20 && udpflow.large_packet_count >= 8 && udpflow.large_packet_ratio >= 0.30 && quic.req.alpn != nil && ("h3" in quic.req.alpn || "h3-29" in quic.req.alpn)
```

Normal HTTP/3, gaming, voice/video, CDN, browser privacy features, and mobile
apps can produce the same flow shape. MASQUE and CONNECT-UDP are especially
difficult because the HTTP request method is encrypted inside QUIC; the rule can
only observe HTTP/3-looking long-lived UDP behavior, not the CONNECT-UDP method
itself. Use these rules as risk-scoring inputs alongside identity, destination
reputation, volume, JA3/JA4 fingerprints, and allowlists for approved services.

For VLESS/REALITY, ShadowTLS, and AnyTLS, passive detection is weaker still:
OpenGFW can observe TLS ClientHello fields, SNI/DNS names, ECH, and configured
JA3/JA4 matches, but it cannot inspect the encrypted tunnel or authenticate the
claimed camouflage site. Add locally validated JA3/JA4 fingerprints and domain
allowlists before using these signals operationally.

The example rules include protocol-family domain weak signals for VLESS/REALITY
and ShadowTLS/AnyTLS. Keep them alert-only and use low to medium risk weights
until you have local evidence that the names are meaningful in your fleet.

## PCAP-driven regression samples

The repository does not ship proxy protocol pcaps. Build your regression set
from traffic captured in an environment you own or are explicitly authorized to
test. Good sample coverage includes normal VM baselines plus known
mihomo/clash/v2ray/xray/sing-box/hysteria2/tuic runs with the exact client and
server versions used in your fleet.

Capture only the minimum traffic needed for detection. Prefer short captures
from isolated test VMs, and avoid storing payloads that are not needed:

```sh
sudo tcpdump -i ogfw-mon0 -s 256 -w hysteria2-auth-lab.pcap 'host 192.0.2.10'
```

Before committing or sharing samples, remove or rewrite sensitive addressing and
metadata. For example, use tools such as `editcap`, `tcprewrite`, or an internal
sanitization workflow to trim time windows, strip unrelated packets, rewrite
addresses/MACs, and verify that no private hostnames, tokens, application data,
or customer traffic remain. Keep raw captures outside the repository.

The manifest-driven test looks for `testdata/pcap/samples.yaml` at the
repository root by default, or the file named by `OPENGFW_PCAP_MANIFEST`. If the
manifest or sample pcaps are missing, the test skips automatically. A manifest
declares expected rule hits, known acceptable extra hits, and the calibrated risk
score band:

```yaml
samples:
  - name: hysteria2-lab
    pcap: hysteria2-auth-lab.pcap
    expectRules:
      - hysteria2-quic-like-weak-signal
    allowedRules:
      - udp443-long-lived-no-quic-sni
      - quic-suspicious-ja4
    expectMinScore: 3
    expectMaxScore: 9
```

`expectRules` must be hit. `allowedRules` may be hit without failing the sample.
Any other rule hit fails the sample until it is either fixed or explicitly added
to `allowedRules`. The replay output logs each sample's rule, severity, hit
count, configured risk weight, contribution, and total risk score.

Run the manifest suite:

```sh
OPENGFW_PCAP_MANIFEST="$PWD/testdata/pcap/samples.yaml" go test ./cmd -run TestExampleRulesWithPCAPManifest -v
```

For quick one-off replay without a manifest, set `OPENGFW_PCAP_SAMPLES` to a
comma-separated list of capture files:

```sh
OPENGFW_PCAP_SAMPLES=/path/hysteria2.pcap,/path/tuic.pcap go test ./cmd -run TestExampleRulesWithOptionalPCAPSamples
```

To make the one-off replay fail unless selected rules fire, set
`OPENGFW_PCAP_EXPECT_RULES` to a comma-separated list of rule names.

```sh
OPENGFW_PCAP_SAMPLES=/path/hysteria2.pcap OPENGFW_PCAP_EXPECT_RULES=hysteria2-quic-like-weak-signal go test ./cmd -run TestExampleRulesWithOptionalPCAPSamples
```

## OVS quarantine

OpenGFW can optionally install temporary OVS drop flows when selected high-confidence
rules match. This is disabled by default.

```yaml
response:
  ovs:
    enabled: true
    bridge: br0
    cookie: "0x4f474657"
    deleteOnStart: false
    minSeverity: high
    rules:
      - vpn-wireguard
      - vpn-openvpn
      - proxy-trojan-heuristic
      - proxy-fully-encrypted-tcp
    hardTimeout: 30m
    cooldown: 5m
    requireIdentity: true
```

Allowlist checks run before both direct rule response and risk-threshold
response. Use them for approved VM identities, known monitoring agents, test
networks, or sanctioned VPN endpoints before enabling quarantine in production.

With `requireIdentity: true`, the response only runs when identity inventory has
produced `meta["vm.mac"]`. For each matched VM, OpenGFW runs:

```sh
ovs-ofctl add-flow br0 'cookie=0x4f474657,priority=50000,hard_timeout=1800,dl_src=<vm-mac>,actions=drop'
ovs-ofctl add-flow br0 'cookie=0x4f474657,priority=50000,hard_timeout=1800,dl_dst=<vm-mac>,actions=drop'
```

Use `hardTimeout` for automatic release, and keep `rules` limited to signals that
you have already validated in your environment. `minSeverity` can be used instead
of, or alongside, explicit rule names. ECH or keyword-based DNS/SNI rules should
normally remain alert-only.

All quarantine flows use the configured `response.ovs.cookie`, which makes them
easy to inspect or clean up without touching unrelated OVS flows. If
`deleteOnStart: true`, OpenGFW runs a best-effort startup cleanup equivalent to:

```sh
ovs-ofctl del-flows br0 'cookie=0x4f474657/-1'
```

Every OVS command is executed with `response.ovs.commandTimeout`. Cleanup or
quarantine command failures are written as warning logs; packet processing keeps
running.

The `ovs-quarantine` command provides a small wrapper around `ovs-ofctl` for
day-2 operations. It does not access OVSDB.

View active quarantine flows:

```sh
OpenGFW ovs-quarantine list --bridge br0 --cookie 0x4f474657
```

Manually release one VM by MAC:

```sh
OpenGFW ovs-quarantine release --bridge br0 --cookie 0x4f474657 --mac 52:54:00:00:00:01
```

Clear all OpenGFW quarantine flows that use the configured cookie:

```sh
OpenGFW ovs-quarantine clear --bridge br0 --cookie 0x4f474657
```

If `response.ovs.openFlow` is set, add the same `-O <version>` option:

```sh
OpenGFW ovs-quarantine list --bridge br0 --cookie 0x4f474657 -O OpenFlow13
```

The equivalent raw `ovs-ofctl` cleanup command is:

```sh
ovs-ofctl del-flows br0 'cookie=0x4f474657/-1'
```

Risk scoring adds a second response path: direct `response.ovs.rules` and
`response.ovs.minSeverity` still work as before, while risk-triggered quarantine
only happens after the VM score crosses `risk.thresholds.response`. This lets you
keep single low/medium-confidence rule hits alert-only and isolate only when
multiple signals cluster on the same VM.

## What this catches

- Direct WireGuard and OpenVPN signatures.
- Trojan length heuristic matches.
- Fully encrypted first-packet TCP heuristics such as Shadowsocks-like traffic.
- SOCKS handshakes that leave the VM.
- TLS/QUIC ECH observations.
- TLS and QUIC ClientHello JA3/JA4 fingerprints from your configured suspicious
  fingerprint lists.
- Hysteria2/TUIC/QUIC-like long-lived UDP behavior as weak risk signals.
- MASQUE/CONNECT-UDP candidates only as HTTP/3-shaped weak risk signals.
- VLESS/REALITY, ShadowTLS, and AnyTLS only through observable TLS/SNI/DNS/JA3/JA4
  weak signals.
- DNS/SNI names containing common proxy ecosystem keywords.

Treat these as signals, not final proof. Modern proxy stacks can intentionally
look like normal HTTPS or HTTP/3 traffic, and normal applications can share the
same behavior. A production deployment should combine these logs with VM
identity, destination reputation, long-lived flow behavior, UDP/443 volume,
locally validated fingerprints, and an allowlist for approved VPNs.

## Blocking path

AF_PACKET capture is passive, so packet verdicts from rules are not applied to
the mirrored packet stream. The optional `response.ovs` path is a conservative
control-plane quarantine mechanism: it reacts to logged alerts by adding
temporary OVS drop flows for the correlated VM MAC, and it is disabled by
default.

For inline packet blocking without OVS quarantine, keep using the existing
NFQUEUE mode on a routed/forwarded path.
