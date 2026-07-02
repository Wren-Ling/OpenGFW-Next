#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  install-linux.sh [--binary PATH] [--prefix /usr/local] [--config-dir /etc/opengfw] [--enable] [--start]

Installs OpenGFW OVS mirror detection examples on a Linux host:
  - /usr/local/bin/OpenGFW
  - /etc/opengfw/config.yaml
  - /etc/opengfw/rules.yaml
  - /etc/opengfw/examples/scripts/setup-ovs-mirror.sh
  - /etc/opengfw/examples/scripts/cleanup-ovs-mirror.sh
  - /etc/systemd/system/opengfw-ovs-detect.service

By default the script installs files and reloads systemd, but does not enable or
start the service. OVS quarantine remains disabled by the example config.
USAGE
}

die() {
  echo "error: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

PREFIX="/usr/local"
CONFIG_DIR="/etc/opengfw"
BINARY=""
ENABLE=false
START=false
TMP_BIN=""
trap '[[ -n "$TMP_BIN" ]] && rm -f "$TMP_BIN"' EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)
      BINARY="${2:-}"
      shift 2
      ;;
    --prefix)
      PREFIX="${2:-}"
      shift 2
      ;;
    --config-dir)
      CONFIG_DIR="${2:-}"
      shift 2
      ;;
    --enable)
      ENABLE=true
      shift
      ;;
    --start)
      START=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || die "run as root"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
INSTALL_BIN="$PREFIX/bin/OpenGFW"
SERVICE_SRC="$REPO_ROOT/examples/systemd/opengfw-ovs-detect.service"
SERVICE_DST="/etc/systemd/system/opengfw-ovs-detect.service"

need_cmd install
need_cmd systemctl

if [[ -z "$BINARY" ]]; then
  if [[ -x "$REPO_ROOT/OpenGFW" ]]; then
    BINARY="$REPO_ROOT/OpenGFW"
  else
    need_cmd go
    TMP_BIN="$(mktemp -t opengfw.XXXXXX)"
    rm -f "$TMP_BIN"
    (cd "$REPO_ROOT" && go build -o "$TMP_BIN" .)
    BINARY="$TMP_BIN"
  fi
fi
[[ -f "$BINARY" ]] || die "binary not found: $BINARY"

install -d -m 0755 "$PREFIX/bin"
install -m 0755 "$BINARY" "$INSTALL_BIN"

install -d -m 0755 "$CONFIG_DIR"
install -d -m 0755 "$CONFIG_DIR/examples"
install -d -m 0755 "$CONFIG_DIR/examples/scripts"
install -m 0644 "$REPO_ROOT/examples/ovs-mirror-config.yaml" "$CONFIG_DIR/config.yaml"
install -m 0644 "$REPO_ROOT/examples/ovs-vpn-detect-rules.yaml" "$CONFIG_DIR/rules.yaml"
install -m 0644 "$REPO_ROOT/examples/vm-inventory.yaml" "$CONFIG_DIR/examples/vm-inventory.yaml"
install -m 0755 "$REPO_ROOT/examples/scripts/setup-ovs-mirror.sh" "$CONFIG_DIR/examples/scripts/setup-ovs-mirror.sh"
install -m 0755 "$REPO_ROOT/examples/scripts/cleanup-ovs-mirror.sh" "$CONFIG_DIR/examples/scripts/cleanup-ovs-mirror.sh"
install -m 0644 "$REPO_ROOT/docs/ovs-mirror-detection.md" "$CONFIG_DIR/ovs-mirror-detection.md"

install -m 0644 "$SERVICE_SRC" "$SERVICE_DST"
systemctl daemon-reload

if [[ "$ENABLE" == true ]]; then
  systemctl enable opengfw-ovs-detect.service
fi
if [[ "$START" == true ]]; then
  systemctl start opengfw-ovs-detect.service
fi

cat <<EOF
Installed OpenGFW OVS mirror detection.

Next steps:
  1. Review $CONFIG_DIR/config.yaml and $CONFIG_DIR/rules.yaml.
  2. Configure an OVS mirror, for example:
       $CONFIG_DIR/examples/scripts/setup-ovs-mirror.sh setup -b br0 -p vnet0 -i ogfw-mon0
  3. Start the service:
       systemctl enable --now opengfw-ovs-detect.service

The example config keeps response.ovs.enabled=false.
EOF
