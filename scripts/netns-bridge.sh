#!/usr/bin/env bash

# Builds two network namespaces connected through a Linux bridge.
#
# Topology:
#   rvpnb-client <== veth ==> rvpnb-br <== veth ==> rvpnb-server
#   10.200.2.1/24                              10.200.2.2/24

set -euo pipefail

readonly CLIENT_NS="rvpnb-client"
readonly SERVER_NS="rvpnb-server"
readonly BRIDGE="rvpnb-br"
readonly CLIENT_IF="rvpnb-c"
readonly CLIENT_BRIDGE_IF="rvpnb-c-br"
readonly SERVER_IF="rvpnb-s"
readonly SERVER_BRIDGE_IF="rvpnb-s-br"
readonly CLIENT_ADDR="10.200.2.1/24"
readonly SERVER_ADDR="10.200.2.2/24"

usage() {
    echo "Usage: sudo $0 {up|status|down}"
}

require_root() {
    if [[ ${EUID} -ne 0 ]]; then
        echo "This script needs network-administration privileges; run it with sudo." >&2
        exit 1
    fi
}

namespace_exists() {
    ip netns list | awk '{print $1}' | grep -Fxq "$1"
}

link_exists() {
    ip link show "$1" >/dev/null 2>&1
}

up() {
    # Keep this topology independent from the direct `rvpn-*` lab.
    if namespace_exists "${CLIENT_NS}" || namespace_exists "${SERVER_NS}" \
        || link_exists "${BRIDGE}" || link_exists "${CLIENT_IF}" \
        || link_exists "${CLIENT_BRIDGE_IF}" || link_exists "${SERVER_IF}" \
        || link_exists "${SERVER_BRIDGE_IF}"; then
        echo "Bridge lab resources already exist; inspect with '$0 status'." >&2
        exit 1
    fi

    # Create two independent network stacks and one host-side virtual switch.
    ip netns add "${CLIENT_NS}"
    ip netns add "${SERVER_NS}"
    ip link add "${BRIDGE}" type bridge

    # Each namespace needs its own veth pair because a bridge is multi-port.
    ip link add "${CLIENT_IF}" type veth peer name "${CLIENT_BRIDGE_IF}"
    ip link add "${SERVER_IF}" type veth peer name "${SERVER_BRIDGE_IF}"

    # Move the namespace-facing endpoints out of the host network namespace.
    ip link set "${CLIENT_IF}" netns "${CLIENT_NS}"
    ip link set "${SERVER_IF}" netns "${SERVER_NS}"

    # Attach the remaining host endpoints to the bridge like switch ports.
    ip link set "${CLIENT_BRIDGE_IF}" master "${BRIDGE}"
    ip link set "${SERVER_BRIDGE_IF}" master "${BRIDGE}"

    # Configure the namespace-facing endpoints on one shared IPv4 subnet.
    ip -n "${CLIENT_NS}" addr add "${CLIENT_ADDR}" dev "${CLIENT_IF}"
    ip -n "${SERVER_NS}" addr add "${SERVER_ADDR}" dev "${SERVER_IF}"

    # Enable namespace-local loopback and both namespace-facing endpoints.
    ip -n "${CLIENT_NS}" link set lo up
    ip -n "${SERVER_NS}" link set lo up
    ip -n "${CLIENT_NS}" link set "${CLIENT_IF}" up
    ip -n "${SERVER_NS}" link set "${SERVER_IF}" up

    # Enable the virtual switch and both ports connected to it.
    ip link set "${BRIDGE}" up
    ip link set "${CLIENT_BRIDGE_IF}" up
    ip link set "${SERVER_BRIDGE_IF}" up

    echo "Bridged namespace lab is ready."
    echo "Test: sudo ip netns exec ${CLIENT_NS} ping -c 3 10.200.2.2"
}

status() {
    echo "Namespaces:"
    ip netns list | awk '{print $1}' | grep -E '^rvpnb-(client|server)$' || true

    echo
    echo "Host bridge and ports:"
    ip -brief link | grep -E '^(rvpnb-br|rvpnb-c-br|rvpnb-s-br)' || true
    bridge link show master "${BRIDGE}" 2>/dev/null || true

    if namespace_exists "${CLIENT_NS}"; then
        echo
        echo "${CLIENT_NS}:"
        ip -n "${CLIENT_NS}" -brief address
        ip -n "${CLIENT_NS}" route
        ip -n "${CLIENT_NS}" neigh
    fi

    if namespace_exists "${SERVER_NS}"; then
        echo
        echo "${SERVER_NS}:"
        ip -n "${SERVER_NS}" -brief address
        ip -n "${SERVER_NS}" route
        ip -n "${SERVER_NS}" neigh
    fi
}

down() {
    # Remove only resources owned by this `rvpnb-*` topology.
    if namespace_exists "${CLIENT_NS}"; then
        ip netns delete "${CLIENT_NS}"
    fi

    if namespace_exists "${SERVER_NS}"; then
        ip netns delete "${SERVER_NS}"
    fi

    # These checks also clean a partially completed setup.
    for interface in \
        "${CLIENT_IF}" "${CLIENT_BRIDGE_IF}" \
        "${SERVER_IF}" "${SERVER_BRIDGE_IF}"; do
        if link_exists "${interface}"; then
            ip link delete "${interface}"
        fi
    done

    if link_exists "${BRIDGE}"; then
        ip link delete "${BRIDGE}"
    fi

    echo "Bridged namespace lab was removed."
}

require_root

case "${1:-}" in
    up) up ;;
    status) status ;;
    down) down ;;
    *)
        usage
        exit 2
        ;;
esac
