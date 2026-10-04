#!/usr/bin/env bash

# Builds a client, a gateway, and a LAN host for routing and NAT experiments.
#
# Topology:
#   rvpnr-client (10.200.3.1) <== veth ==> (10.200.3.2) rvpnr-server
#   rvpnr-server (10.200.4.1) <== veth ==> (10.200.4.2) rvpnr-lan

set -euo pipefail

readonly CLIENT_NS="rvpnr-client"
readonly SERVER_NS="rvpnr-server"
readonly LAN_NS="rvpnr-lan"

readonly CLIENT_IF="rvpnr-c"
readonly SERVER_IF="rvpnr-s"
readonly SERVER_LAN_IF="rvpnr-sl"
readonly LAN_IF="rvpnr-l"

readonly CLIENT_ADDR="10.200.3.1/24"
readonly SERVER_ADDR="10.200.3.2/24"
readonly SERVER_LAN_ADDR="10.200.4.1/24"
readonly LAN_ADDR="10.200.4.2/24"

readonly LAN_SUBNET="10.200.4.0/24"
readonly TUNNEL_SUBNET="10.210.0.0/24"

usage() {
    echo "Usage: sudo $0 {up|route|status|down}"
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

# Moves one end of a fresh veth pair into each namespace and brings both up.
connect() {
    local left_ns=$1 left_if=$2 left_addr=$3 right_ns=$4 right_if=$5 right_addr=$6

    ip link add "${left_if}" type veth peer name "${right_if}"
    ip link set "${left_if}" netns "${left_ns}"
    ip link set "${right_if}" netns "${right_ns}"
    ip -n "${left_ns}" addr add "${left_addr}" dev "${left_if}"
    ip -n "${right_ns}" addr add "${right_addr}" dev "${right_if}"
    ip -n "${left_ns}" link set "${left_if}" up
    ip -n "${right_ns}" link set "${right_if}" up
}

up() {
    # Refuse to overwrite a partial or active lab. Use `down` explicitly first.
    if namespace_exists "${CLIENT_NS}" || namespace_exists "${SERVER_NS}" \
        || namespace_exists "${LAN_NS}" \
        || link_exists "${CLIENT_IF}" || link_exists "${SERVER_IF}" \
        || link_exists "${SERVER_LAN_IF}" || link_exists "${LAN_IF}"; then
        echo "Routed lab resources already exist; inspect with '$0 status'." >&2
        exit 1
    fi

    for ns in "${CLIENT_NS}" "${SERVER_NS}" "${LAN_NS}"; do
        ip netns add "${ns}"
        ip -n "${ns}" link set lo up
    done

    connect "${CLIENT_NS}" "${CLIENT_IF}" "${CLIENT_ADDR}" \
        "${SERVER_NS}" "${SERVER_IF}" "${SERVER_ADDR}"
    connect "${SERVER_NS}" "${SERVER_LAN_IF}" "${SERVER_LAN_ADDR}" \
        "${LAN_NS}" "${LAN_IF}" "${LAN_ADDR}"

    echo "Routed namespace lab is ready."
}

# Routes the client's LAN traffic through the tunnel and back.
# Run it after vpn_tunnel is running in both rvpnr-client and rvpnr-server.
route() {
    # The client route attaches to rvpn0, which exists only while vpn_tunnel runs.
    if ! ip -n "${CLIENT_NS}" link show rvpn0 >/dev/null 2>&1; then
        echo "rvpn0 does not exist in ${CLIENT_NS}; start vpn_tunnel there first." >&2
        exit 1
    fi

    ip -n "${CLIENT_NS}" route add "${LAN_SUBNET}" dev rvpn0
    # sysctl is not an `ip` command, so it needs `ip netns exec` instead of `ip -n`.
    ip netns exec "${SERVER_NS}" sysctl -qw net.ipv4.ip_forward=1
    ip -n "${LAN_NS}" route add "${TUNNEL_SUBNET}" via "${SERVER_LAN_ADDR%/*}"

    echo "Routing configured. Test: sudo ip netns exec ${CLIENT_NS} ping -c 3 10.200.4.2"
}

status() {
    echo "Namespaces:"
    ip netns list | awk '{print $1}' | grep -E '^rvpnr-(client|server|lan)$' || true

    for ns in "${CLIENT_NS}" "${SERVER_NS}" "${LAN_NS}"; do
        if namespace_exists "${ns}"; then
            echo
            echo "${ns}:"
            ip -n "${ns}" -brief address
            ip -n "${ns}" route
            ip -n "${ns}" neigh
        fi
    done
}

down() {
    for ns in "${CLIENT_NS}" "${SERVER_NS}" "${LAN_NS}"; do
        if namespace_exists "${ns}"; then
            ip netns delete "${ns}"
        fi
    done
    echo "Routed namespace lab was removed."
}

require_root

case "${1:-}" in
    up) up ;;
    route) route ;;
    status) status ;;
    down) down ;;
    *)
        usage
        exit 2
        ;;
esac
