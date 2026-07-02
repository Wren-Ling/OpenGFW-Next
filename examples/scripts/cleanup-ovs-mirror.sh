#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  cleanup-ovs-mirror.sh -b BRIDGE -i MONITOR_IFACE [-p MIRRORED_PORT] [-n MIRROR_NAME] [--delete-monitor]
  cleanup-ovs-mirror.sh -b BRIDGE -i MONITOR_IFACE --all [-n MIRROR_NAME] [--delete-monitor]

Examples:
  cleanup-ovs-mirror.sh -b br0 -p vnet0 -i ogfw-mon0
  cleanup-ovs-mirror.sh -b br0 --all -i ogfw-mon0 -n opengfw-all
  cleanup-ovs-mirror.sh -b br0 -i ogfw-mon0 --delete-monitor

When no mirror name or mirrored port is supplied, the script removes OpenGFW
mirrors attached to MONITOR_IFACE whose names start with "opengfw-".
USAGE
}

die() {
  echo "error: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

mirror_uuid_by_name() {
  ovs-vsctl --bare --columns=_uuid find Mirror "name=$1" | sed -n '1p'
}

mirror_name() {
  ovs-vsctl --bare get Mirror "$1" name | tr -d '"'
}

monitor_port_uuid() {
  ovs-vsctl --bare --columns=_uuid find Port "name=$MONITOR_IFACE" | sed -n '1p'
}

mirror_uuids_by_monitor() {
  local mon_uuid name
  mon_uuid="$(monitor_port_uuid)"
  [[ -n "$mon_uuid" ]] || return 0

  ovs-vsctl --bare --columns=_uuid find Mirror "output_port=$mon_uuid" | while read -r uuid; do
    [[ -n "$uuid" ]] || continue
    name="$(mirror_name "$uuid")"
    if [[ "$name" == opengfw-* ]]; then
      echo "$uuid"
    fi
  done
}

remove_mirror_uuid() {
  local uuid="$1"
  local name
  name="$(mirror_name "$uuid")"
  ovs-vsctl --if-exists remove Bridge "$BRIDGE" mirrors "$uuid"
  ovs-vsctl --if-exists destroy Mirror "$uuid"
  echo "removed OVS mirror $name from $BRIDGE"
}

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

[[ -n "$BRIDGE" ]] || die "--bridge is required"
[[ -n "$MONITOR_IFACE" ]] || die "--monitor-interface is required"
if [[ "$MIRROR_ALL" == true && -n "$MIRRORED_PORT" ]]; then
  die "--all and --port cannot be used together"
fi

if [[ -z "$MIRROR_NAME" ]]; then
  if [[ "$MIRROR_ALL" == true ]]; then
    MIRROR_NAME="opengfw-${BRIDGE}-all"
  elif [[ -n "$MIRRORED_PORT" ]]; then
    MIRROR_NAME="opengfw-${MIRRORED_PORT}"
  fi
fi

need_cmd ovs-vsctl
ovs-vsctl br-exists "$BRIDGE" || die "OVS bridge $BRIDGE does not exist"

removed=false
if [[ -n "$MIRROR_NAME" ]]; then
  uuid="$(mirror_uuid_by_name "$MIRROR_NAME")"
  if [[ -n "$uuid" ]]; then
    remove_mirror_uuid "$uuid"
    removed=true
  fi
else
  while read -r uuid; do
    [[ -n "$uuid" ]] || continue
    remove_mirror_uuid "$uuid"
    removed=true
  done < <(mirror_uuids_by_monitor)
fi

if [[ "$removed" == false ]]; then
  echo "no OpenGFW OVS mirrors found on $BRIDGE for $MONITOR_IFACE"
fi

if [[ "$DELETE_MONITOR" == true ]]; then
  ovs-vsctl --if-exists del-port "$BRIDGE" "$MONITOR_IFACE"
  echo "removed monitor port $MONITOR_IFACE from $BRIDGE"
fi
