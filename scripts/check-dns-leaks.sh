#!/usr/bin/env bash

# Confirms that a fresh DNS query appears inside rvpn0 but not as DNS traffic
# on the physical interface. Run this while the client tunnel is established.

set -euo pipefail

readonly PHYSICAL_INTERFACE="${1:-}"
readonly TEST_DOMAIN="${2:-example.com}"
readonly TUN_INTERFACE="${TUN_INTERFACE:-rvpn0}"
readonly CAPTURE_SECONDS=8

usage() {
    echo "Usage: sudo $0 <physical-interface> [domain]" >&2
}

if [[ ${EUID} -ne 0 ]]; then
    echo "This check needs packet-capture privileges; run it with sudo." >&2
    exit 1
fi

if [[ -z ${PHYSICAL_INTERFACE} ]]; then
    usage
    exit 2
fi

for command in ip resolvectl tcpdump timeout; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        echo "Required command not found: ${command}" >&2
        exit 1
    fi
done

for interface in "${PHYSICAL_INTERFACE}" "${TUN_INTERFACE}"; do
    if ! ip link show "${interface}" >/dev/null 2>&1; then
        echo "Interface does not exist: ${interface}" >&2
        exit 1
    fi
done

readonly CAPTURE_DIR="$(mktemp -d)"
readonly TUN_CAPTURE="${CAPTURE_DIR}/tun.txt"
readonly PHYSICAL_CAPTURE="${CAPTURE_DIR}/physical.txt"

cleanup() {
    if [[ -n ${TUN_CAPTURE_PID:-} ]]; then
        kill "${TUN_CAPTURE_PID}" >/dev/null 2>&1 || true
    fi

    if [[ -n ${PHYSICAL_CAPTURE_PID:-} ]]; then
        kill "${PHYSICAL_CAPTURE_PID}" >/dev/null 2>&1 || true
    fi

    rm -rf -- "${CAPTURE_DIR}"
}

trap cleanup EXIT

readonly DNS_FILTER='udp port 53 or tcp port 53 or tcp port 853'

timeout "${CAPTURE_SECONDS}" tcpdump -l -n -i "${TUN_INTERFACE}" -c 1 \
    "${DNS_FILTER}" >"${TUN_CAPTURE}" 2>&1 &
TUN_CAPTURE_PID=$!

timeout "${CAPTURE_SECONDS}" tcpdump -l -n -i "${PHYSICAL_INTERFACE}" -c 1 \
    "${DNS_FILTER}" >"${PHYSICAL_CAPTURE}" 2>&1 &
PHYSICAL_CAPTURE_PID=$!

sleep 1
resolvectl flush-caches

# A random label prevents a cached result from hiding the actual network path.
readonly QUERY_NAME="rvpn-${RANDOM}-${RANDOM}.${TEST_DOMAIN}"
resolvectl query "${QUERY_NAME}" >/dev/null 2>&1 || true

set +e
wait "${TUN_CAPTURE_PID}"
TUN_STATUS=$?
wait "${PHYSICAL_CAPTURE_PID}"
PHYSICAL_STATUS=$?
set -e

if [[ ${TUN_STATUS} -ne 0 ]]; then
    echo "FAIL: no DNS traffic was captured on ${TUN_INTERFACE}." >&2
    exit 1
fi

if [[ ${PHYSICAL_STATUS} -eq 0 ]]; then
    echo "FAIL: DNS traffic escaped on ${PHYSICAL_INTERFACE}." >&2
    sed -n '1,20p' "${PHYSICAL_CAPTURE}" >&2
    exit 1
fi

echo "PASS: DNS used ${TUN_INTERFACE} and did not leak on ${PHYSICAL_INTERFACE}."
