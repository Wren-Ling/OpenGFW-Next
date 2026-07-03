# PCAP risk calibration

This document records the default calibration target used by
`examples/ovs-mirror-config.yaml` and `testdata/pcap/samples.yaml`. The repository
does not ship real PCAP files, so these defaults are conservative starting
values that are validated by replay when local sanitized captures are present.

## Regression set

The local manifest covers these required families:

- `mihomo-socks-baseline` and `clash-socks-baseline` for explicit SOCKS proxy handshakes.
- `v2ray-xray-vless-reality` for VLESS/REALITY TLS camouflage breadcrumbs.
- `sing-box-shadowtls-anytls` for sing-box ShadowTLS/AnyTLS-style breadcrumbs.
- `hysteria2-quic-auth` and `hysteria2-custom-udp-auth` for QUIC-like and custom UDP behavior.
- `tuic-quic-auth` for TUIC QUIC-like startup and flow-shape behavior.
- `normal-http3-browsing-control`, `normal-game-udp-control`, and `normal-voice-video-control` as false-positive controls.

Each manifest entry declares `name`, `pcap`, `expectRules`, `allowedRules`,
`expectMinScore`, and `expectMaxScore`. `allowNoHits` is used only for known-good
control samples where zero hits is acceptable.

## Default score bands

| Sample family | Expected signal | Target band | Calibration intent |
| --- | --- | ---: | --- |
| Mihomo/Clash | `proxy-socks` plus optional domain/fingerprint context | 4-12 | A visible SOCKS handshake is stronger than a weak encrypted-flow clue, but one flow alone should not trigger quarantine. |
| V2Ray/Xray VLESS/REALITY | TLS/DNS REALITY or proxy-domain breadcrumbs | 3-14 | Domain and TLS camouflage hints should reach alert only when multiple independent clues repeat in the risk window. |
| Sing-box ShadowTLS/AnyTLS | TLS/DNS ShadowTLS/AnyTLS breadcrumbs | 3-14 | Same stance as REALITY: useful correlation, not proof from one packet trace. |
| Hysteria2 QUIC | QUIC-like bidirectional flow shape, optional QUIC fingerprint/ECH context | 3-12 | The family-specific QUIC-like rule carries weight, but generic UDP/443 without SNI is score-neutral. |
| Hysteria2 custom UDP | Long-lived encrypted-looking non-443 UDP | 1-8 | Kept deliberately weak because games and voice/video can look similar. |
| TUIC | QUIC-like startup and flow shape, optional short-burst or fingerprint context | 3-12 | Similar to Hysteria2 QUIC: alert only after repeated or corroborated evidence. |
| HTTP/3 control | Normal browser HTTP/3/MASQUE-like behavior | 0-2 | Normal HTTP/3 must remain below alert by default. |
| Game/voice controls | Long-lived custom UDP or UDP/443 media behavior | 0-1 | Real-time apps must not accumulate meaningful risk from one tolerated weak hit. |

## Config changes

The default alert threshold is `9` and the response threshold is `16`. This means
one direct high-confidence marker such as WireGuard/OpenVPN is visible but does
not quarantine a VM by itself, while repeated direct hits or a mix of direct and
corroborating signals can cross the response threshold.

The default weights intentionally separate context from risk:

- `udp443-long-lived-no-quic-sni` is weight `0`; it is logged for replay context
  but is too broad to score because normal HTTP/3, games, and voice/video can
  match the same shape.
- `hysteria2-quic-like-weak-signal` and `tuic-quic-like-weak-signal` are weight
  `3`; they are more specific than the generic UDP/443 helper but still require
  repetition or corroboration to alert.
- `proxy-socks` is weight `4`; a clear SOCKS handshake is stronger than flow
  shape, but the default still avoids one-off quarantine.
- Custom UDP, MASQUE, ECH-only, REALITY/ShadowTLS/AnyTLS, and broad domain rules
  remain low weight until local replay proves they separate from controls.

After adding sanitized PCAPs, run:

```sh
PATH="/usr/local/go/bin:$PATH" GOCACHE="$PWD/.gocache" go test ./... -v
```

Review the per-sample replay logs for rule counts, weights, contributions, and
total score. Tighten `expectMaxScore` for controls first, then raise or lower
individual weights only when the same direction is supported by both proxy and
known-good PCAPs.
