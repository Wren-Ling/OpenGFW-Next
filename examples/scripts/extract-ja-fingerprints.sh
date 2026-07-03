#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage: extract-ja-fingerprints.sh -p CAPTURE.pcap -k ja3|ja4|quicJa3|quicJa4 [-n NAME] [-t TAG]... [-f DISPLAY_FILTER]

Examples:
  extract-ja-fingerprints.sh -p mihomo-lab.pcap -k ja3 -n mihomo-1.18.8 -t mihomo -t lab > examples/fingerprints/ja3.yaml
  extract-ja-fingerprints.sh -p xray-reality.pcap -k ja4 -n xray-reality -t xray -t reality > examples/fingerprints/ja4.yaml

Requires tshark with JA3/JA4 fields available. Capture only authorized lab traffic.
USAGE
}

pcap=""
kind=""
name="lab-capture"
filter=""
tags=()
while getopts "p:k:n:t:f:h" opt; do
  case "$opt" in
    p) pcap="$OPTARG" ;;
    k) kind="$OPTARG" ;;
    n) name="$OPTARG" ;;
    t) tags+=("$OPTARG") ;;
    f) filter="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

if [[ -z "$pcap" || -z "$kind" ]]; then
  usage
  exit 2
fi
if ! command -v tshark >/dev/null 2>&1; then
  echo "tshark is required" >&2
  exit 1
fi

case "$kind" in
  ja3)
    hash_field="tls.handshake.ja3"
    default_filter='tls.handshake.type == 1 && tls.handshake.ja3'
    ;;
  ja4)
    hash_field="tls.handshake.ja4"
    default_filter='tls.handshake.type == 1 && tls.handshake.ja4'
    ;;
  quicJa3)
    hash_field="tls.handshake.ja3"
    default_filter='quic && tls.handshake.type == 1 && tls.handshake.ja3'
    ;;
  quicJa4)
    hash_field="tls.handshake.ja4"
    default_filter='quic && tls.handshake.type == 1 && tls.handshake.ja4'
    ;;
  *)
    echo "unsupported kind: $kind" >&2
    usage
    exit 2
    ;;
esac
if [[ -z "$filter" ]]; then
  filter="$default_filter"
fi

if ! tshark -G fields 2>/dev/null | awk '{print $3}' | grep -qx "$hash_field"; then
  echo "tshark field $hash_field is unavailable; upgrade Wireshark/tshark or use a JA3/JA4-capable extractor" >&2
  exit 1
fi

tag_yaml=""
if ((${#tags[@]} > 0)); then
  tag_yaml="["
  for i in "${!tags[@]}"; do
    [[ "$i" == 0 ]] || tag_yaml+=", "
    tag_yaml+="\"${tags[$i]}\""
  done
  tag_yaml+="]"
else
  tag_yaml="[]"
fi

echo "suspicious:"
tshark -r "$pcap" -Y "$filter" -T fields -e "$hash_field" 2>/dev/null \
  | tr '\t,' '\n\n' \
  | sed '/^$/d' \
  | sort -u \
  | while IFS= read -r hash; do
      cat <<ENTRY
  - hash: "$hash"
    name: "$name"
    severity: medium
    tags: $tag_yaml
ENTRY
    done
