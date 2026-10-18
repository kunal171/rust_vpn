# Phase 11: UDP handshake reliability

UDP preserves datagram boundaries, but it does not guarantee delivery, ordering, or duplicate
suppression. Phase 10 could establish an authenticated tunnel when every handshake datagram
arrived once and in order. Phase 11 makes handshake setup tolerate loss of a request or response
without weakening peer authentication.

## Reliability model

The handshake remains bounded and deliberately small:

```text
client                                      server
  │                                           │
  ├── ClientHello ───────────────────────────▶│
  │◀────────────────────────── ServerHello ───┤
  ├── ClientAuth ────────────────────────────▶│
  │◀──────────── protected HandshakeComplete ─┤
  │                                           │
  └── protected Data ────────────────────────▶│
                  confirmation cache cleared  │
```

The client retransmits a request after a timeout. A retry sends the exact same encoded bytes;
it does not generate a new ephemeral key, signature, session ID, or transcript. This is important
because changing handshake state during a retry would make the two peers derive or authenticate
different sessions.

Every retry path is limited to three total attempts. The bound prevents an absent peer from
keeping the handshake alive forever and limits work caused by duplicated traffic.

## Lost ClientHello or ServerHello

The client caches its encoded `ClientHello`. If `ServerHello` does not arrive before the socket
timeout, the client resends that identical datagram.

After the server has answered, it may receive another `ClientHello` because its first response was
lost. The server compares the repeated hello with the original:

- An identical hello receives the already encoded `ServerHello`.
- A changed hello is rejected instead of silently replacing the pending handshake.
- Duplicate responses stop at the configured retry limit.

Reusing the cached response preserves the original server ephemeral key, session ID, signature,
and authenticated transcript.

## Lost ClientAuth or HandshakeComplete

The client also caches the encoded `ClientAuth` and retries it while waiting for the protected
`HandshakeComplete` frame.

Once the server has authenticated `ClientAuth`, its main receive loop retains a small confirmation
cache containing:

- the exact encoded `ClientAuth` expected from this peer;
- the already protected `HandshakeComplete` bytes;
- the number of retry responses still allowed.

An exact duplicate `ClientAuth` receives the cached confirmation. Other datagrams are not treated
as handshake retries. Reusing the protected bytes also avoids consuming another send counter for
the same logical confirmation.

The cache is cleared when the server receives the first authenticated `Data` frame. That frame is
proof that the client received and accepted `HandshakeComplete`, so retaining retry state is no
longer useful.

## Security boundaries

Retransmission adds reliability; it does not make UDP reliable in general. Ordinary encrypted
tunnel packets are still datagrams and may be lost or reordered. TCP carried inside the tunnel can
perform its own recovery.

The retry logic preserves these existing security properties:

- Peer identities are still pinned and verified with Ed25519.
- Session keys still come from the authenticated ephemeral X25519 exchange.
- `HandshakeComplete` is still authenticated and encrypted before it is trusted.
- Retry bytes must match the active handshake rather than creating new state.
- Retry counts are bounded.
- The confirmation cache is discarded as soon as authenticated data proves completion.

## Verification

The automated tests cover:

- timeout errors that identify the handshake stage;
- retransmission of identical request bytes after a simulated lost response;
- reuse of a cached `ServerHello` for an identical duplicate `ClientHello`;
- rejection of a conflicting duplicate `ClientHello`;
- successful authenticated client/server handshake and encrypted data exchange;
- confirmation-cache matching and retry limits;
- rejection of plaintext, incorrectly keyed, malformed, and replayed confirmations.

The phase closes with the standard quality checks:

```bash
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Completion status

Phase 11 is complete. Handshake requests can be retransmitted without regenerating cryptographic
state, the server safely handles duplicate requests with bounded cached responses, and all quality
checks pass. Automatic recovery after an established peer exits or restarts is intentionally left
for Phase 12, because it requires a tunnel lifecycle state machine rather than another handshake
retry.
