#!/usr/bin/env bash

# Builds two network namespaces connected directly by one veth pair.
#
# Topology:
#   rvpn-client (10.200.1.1/24) <== veth ==> rvpn-server (10.200.1.2/24)

set -euo pipefail

readonly CLIENT_NS="rvpn-client"
readonly SERVER_NS="rvpn-server"
readonly CLIENT_IF="rvpn-c"
readonly SERVER_IF="rvpn-s"
readonly CLIENT_ADDR="10.200.1.1/24"
readonly SERVER_ADDR="10.200.1.2/24"

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
    # Refuse to overwrite a partial or active lab. Use `down` explicitly first.
    if namespace_exists "${CLIENT_NS}" || namespace_exists "${SERVER_NS}" \
        || link_exists "${CLIENT_IF}" || link_exists "${SERVER_IF}"; then
        echo "Direct lab resources already exist; inspect with '$0 status'." >&2
        exit 1
    fi

    # Create two independent network stacks.
    ip netns add "${CLIENT_NS}"
    ip netns add "${SERVER_NS}"

    # Create the two connected ends of one virtual Ethernet cable.
    ip link add "${CLIENT_IF}" type veth peer name "${SERVER_IF}"

    # Move one cable endpoint into each namespace.
    ip link set "${CLIENT_IF}" netns "${CLIENT_NS}"
    ip link set "${SERVER_IF}" netns "${SERVER_NS}"

    # Assign both endpoints addresses from the same directly connected subnet.
    ip -n "${CLIENT_NS}" addr add "${CLIENT_ADDR}" dev "${CLIENT_IF}"
    ip -n "${SERVER_NS}" addr add "${SERVER_ADDR}" dev "${SERVER_IF}"

    # Each namespace owns a separate loopback interface that starts down.
    ip -n "${CLIENT_NS}" link set lo up
    ip -n "${SERVER_NS}" link set lo up

    # Both veth endpoints must be up before the virtual link can carry frames.
    ip -n "${CLIENT_NS}" link set "${CLIENT_IF}" up
    ip -n "${SERVER_NS}" link set "${SERVER_IF}" up

    echo "Direct namespace lab is ready."
    echo "Test: sudo ip netns exec ${CLIENT_NS} ping -c 3 10.200.1.2"
}

status() {
    echo "Namespaces:"
    ip netns list | awk '{print $1}' | grep -E '^rvpn-(client|server)$' || true

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
    # Deleting a namespace also deletes a veth endpoint inside it; deleting one
    # endpoint removes its peer. The link checks handle partially created labs.
    if namespace_exists "${CLIENT_NS}"; then
        ip netns delete "${CLIENT_NS}"
    fi

    if namespace_exists "${SERVER_NS}"; then
        ip netns delete "${SERVER_NS}"
    fi

    if link_exists "${CLIENT_IF}"; then
        ip link delete "${CLIENT_IF}"
    fi

    if link_exists "${SERVER_IF}"; then
        ip link delete "${SERVER_IF}"
    fi

    echo "Direct namespace lab was removed."
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
