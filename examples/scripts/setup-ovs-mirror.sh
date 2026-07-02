#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  setup-ovs-mirror.sh setup   -b BRIDGE -p MIRRORED_PORT -i MONITOR_IFACE [-n MIRROR_NAME]
  setup-ovs-mirror.sh setup   -b BRIDGE --all          -i MONITOR_IFACE [-n MIRROR_NAME]
  setup-ovs-mirror.sh cleanup -b BRIDGE                -i MONITOR_IFACE [-n MIRROR_NAME] [--delete-monitor]

Examples:
  setup-ovs-mirror.sh setup -b br0 -p vnet0 -i ogfw-mon0
  setup-ovs-mirror.sh setup -b br0 --all -i ogfw-mon0 -n opengfw-all
  setup-ovs-mirror.sh cleanup -b br0 -i ogfw-mon0

The setup command creates an OVS internal monitor interface and attaches an OVS
Mirror that sends selected traffic to it. The cleanup command removes the Mirror
created by this script and can optionally remove the monitor port.
USAGE
}

die() {
  echo "error: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

mirror_uuid() {
  ovs-vsctl --bare --columns=_uuid find Mirror "name=$MIRROR_NAME" | sed -n '1p'
}

cleanup_mirror() {
  local uuid
  uuid="$(mirror_uuid)"
  if [[ -n "$uuid" ]]; then
    ovs-vsctl --if-exists remove Bridge "$BRIDGE" mirrors "$uuid"
    ovs-vsctl --if-exists destroy Mirror "$uuid"
    echo "removed OVS mirror $MIRROR_NAME from $BRIDGE"
  else
    echo "OVS mirror $MIRROR_NAME not found"
  fi
}

ACTION="${1:-}"
if [[ -z "$ACTION" ]]; then
  usage
  exit 2
fi
shift

BRIDGE=""
MIRRORED_PORT=""
MONITOR_IFACE=""
MIRROR_NAME=""
MIRROR_ALL=false
DELETE_MONITOR=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -b|--bridge)
      BRIDGE="${2:-}"
      shift 2
      ;;
    -p|--port|--mirror-port)
      MIRRORED_PORT="${2:-}"
      shift 2
      ;;
    -i|--interface|--monitor-interface)
      MONITOR_IFACE="${2:-}"
      shift 2
      ;;
    -n|--name|--mirror-name)
      MIRROR_NAME="${2:-}"
      shift 2
      ;;
    --all)
      MIRROR_ALL=true
      shift
      ;;
    --delete-monitor)
      DELETE_MONITOR=true
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

[[ "$ACTION" == "setup" || "$ACTION" == "cleanup" ]] || die "action must be setup or cleanup"
[[ -n "$BRIDGE" ]] || die "--bridge is required"
[[ -n "$MONITOR_IFACE" ]] || die "--monitor-interface is required"
if [[ "$MIRROR_ALL" == false && "$ACTION" == "setup" ]]; then
  [[ -n "$MIRRORED_PORT" ]] || die "--port is required unless --all is used"
fi
if [[ -z "$MIRROR_NAME" ]]; then
  if [[ "$MIRROR_ALL" == true ]]; then
    MIRROR_NAME="opengfw-${BRIDGE}-all"
  else
    MIRROR_NAME="opengfw-${MIRRORED_PORT}"
  fi
fi

need_cmd ovs-vsctl
need_cmd ip
ovs-vsctl br-exists "$BRIDGE" || die "OVS bridge $BRIDGE does not exist"

case "$ACTION" in
  setup)
    ovs-vsctl --may-exist add-port "$BRIDGE" "$MONITOR_IFACE" -- set Interface "$MONITOR_IFACE" type=internal
    ip link set "$MONITOR_IFACE" up

    cleanup_mirror
    if [[ "$MIRROR_ALL" == true ]]; then
      ovs-vsctl \
        -- --id=@mon get Port "$MONITOR_IFACE" \
        -- --id=@m create Mirror "name=$MIRROR_NAME" select-all=true output-port=@mon \
        -- add Bridge "$BRIDGE" mirrors @m
    else
      ovs-vsctl get Port "$MIRRORED_PORT" >/dev/null
      ovs-vsctl \
        -- --id=@mon get Port "$MONITOR_IFACE" \
        -- --id=@src get Port "$MIRRORED_PORT" \
        -- --id=@m create Mirror "name=$MIRROR_NAME" select-src-port=@src select-dst-port=@src output-port=@mon \
        -- add Bridge "$BRIDGE" mirrors @m
    fi
    echo "installed OVS mirror $MIRROR_NAME on $BRIDGE -> $MONITOR_IFACE"
    ;;
  cleanup)
    cleanup_mirror
    if [[ "$DELETE_MONITOR" == true ]]; then
      ovs-vsctl --if-exists del-port "$BRIDGE" "$MONITOR_IFACE"
      echo "removed monitor port $MONITOR_IFACE from $BRIDGE"
    fi
    ;;
esac
