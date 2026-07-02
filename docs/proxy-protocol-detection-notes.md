# Proxy Protocol Detection Notes

This document defines the detection boundary for Hysteria2, TUIC,
VLESS/REALITY, ShadowTLS, AnyTLS, and MASQUE in OpenGFW OVS mirror mode.

OVS mirror capture is passive. It can observe packet metadata, UDP flow shape,
TLS/QUIC ClientHello fields, DNS names, VM identity metadata, and configured
fingerprint matches. It cannot decrypt proxy payloads or prove that an encrypted
connection is a specific proxy protocol with 100% certainty.

The repository does not ship real proxy PCAPs. Use only PCAPs collected from an
authorized lab or production troubleshooting window, then replay them with the
manifest-driven tests in `cmd/pcap_replay_test.go`. The fields below are the
stable observables to summarize from those real samples and compare against
known-good VM workloads.

## Passive Detection Boundary

| Protocol family | Passive visibility | Operational stance |
| --- | --- | --- |
| Hysteria2 over QUIC/UDP | UDP flow duration, packet length distribution, bidirectionality, QUIC ClientHello if parseable, SNI/ALPN/ECH, QUIC JA3/JA4 | Weak to medium risk signal only. QUIC-like shape is not unique. |
| Hysteria2 custom UDP ports | UDP flow duration, length distribution, direction balance, non-443 destination port | Weak signal. Many games, voice/video apps, tunnels, and custom services look similar. |
| TUIC | QUIC-like UDP/443 shape, first packet length, direction balance, QUIC SNI/ALPN/ECH, QUIC JA3/JA4 | Weak to medium risk signal when combined with local fingerprints or missing/odd QUIC metadata. |
| VLESS/REALITY | TLS ClientHello metadata, SNI or ECH, ALPN, JA3/JA4, destination/domain context | Weak signal. REALITY is designed as TLS camouflage; passive capture cannot see the inner VLESS protocol. |
| ShadowTLS / AnyTLS | TLS ClientHello metadata, SNI or ECH, ALPN, JA3/JA4, destination/domain context | Weak signal. Treat domain keywords and fingerprints as correlation, not proof. |
| MASQUE / CONNECT-UDP | QUIC/HTTP3 ALPN, long-lived UDP/443 flow shape, SNI/ECH, QUIC JA3/JA4 | Weak candidate only. CONNECT-UDP method and target are encrypted inside QUIC. |

## PCAP Field Model

For every authorized proxy PCAP and matching known-good control PCAP, record the
same feature set. This keeps thresholds local to the host and VM population:

- UDP length distribution: `min_packet_len`, `max_packet_len`,
  `avg_packet_len`, `large_packet_ratio`, `small_packet_ratio`,
  `len_bucket_le64_ratio`, `len_bucket_le128_ratio`,
  `len_bucket_le256_ratio`, `len_bucket_le512_ratio`,
  `len_bucket_le1024_ratio`, `len_bucket_le1200_ratio`,
  `len_bucket_gt1200_ratio`.
- Directionality: `tx_packet_ratio`, `rx_packet_ratio`, `tx_byte_ratio`,
  `rx_byte_ratio`, `balanced_directions`, `direction_change_count`,
  `max_same_direction_run`.
- Startup shape: `first_packet_len`, `second_packet_len`, `third_packet_len`,
  `fourth_packet_len`, `first_tx_packet_len`, `first_rx_packet_len`.
- Lifetime and rate: `duration_seconds`, `long_lived`, `packet_count`,
  `packet_rate`, `total_bytes`, `byte_rate`.
- QUIC/TLS handshake context: SNI, ALPN, ECH, JA3, JA4, and whether the QUIC
  Initial could be parsed.
- Identity context: VM ID/name/MAC, tenant labels, destination IP/ASN/domain if
  available outside OpenGFW, and whether an allowlist entry should suppress it.

Do not tune thresholds from proxy PCAPs alone. Compare them against browser
HTTP/3, OS updates, gaming, voice/video, backup agents, monitoring exporters,
and approved VPN/proxy tools used by administrators.

## Rule Model

The example rules keep modern proxy candidates as `log: true` rules with no
direct action. They are intended to feed risk aggregation:

- UDP behavior rules look for long-lived, bidirectional flows with enough
  traffic volume and a length distribution consistent with encrypted tunnel
  traffic.
- QUIC rules add parseable ClientHello evidence when available: SNI, ALPN, ECH,
  and configured suspicious QUIC JA3/JA4 fingerprints.
- TLS camouflage rules use SNI/DNS keywords and configured suspicious TLS
  JA3/JA4 fingerprints. They are weak because the outer TLS session can be
  indistinguishable from ordinary HTTPS.
- MASQUE candidates require HTTP/3-looking ALPN plus long-lived bidirectional
  UDP behavior. This does not identify CONNECT-UDP itself.

Recommended default risk weights:

- Direct protocol markers: high, for example WireGuard and OpenVPN.
- Locally validated suspicious JA3/JA4: medium.
- Hysteria2/TUIC QUIC-like behavior: low to medium.
- Custom UDP Hysteria2, MASQUE candidates, domain keyword hits, and ECH-only
  observations: low.

Default OVS response rules must not include these weak candidates. Use risk
thresholds, allowlists, VM identity, and human review before enabling any
response path based on them.

## Common False Positives

- Browser HTTP/3 and QUIC connection migration.
- MASQUE or enterprise privacy relays that are explicitly approved.
- Video conferencing, game networking, and low-latency voice applications.
- CDN downloads, package managers, and backup agents with long-lived encrypted
  flows.
- Mobile app traffic from Android/iOS VMs or test labs.
- Security scanners and synthetic monitoring tools.
- Domain names containing proxy project keywords for documentation, mirrors, or
  package repositories rather than active proxy use.

Use `allowlist` entries for approved VM IDs, VM names, MAC addresses,
maintenance CIDRs, known-good rules, and approved SNI/DNS names. Keep
`allowlist.logSuppressed: true` while tuning so suppressed events remain
auditable without contributing to risk aggregation or OVS response.
