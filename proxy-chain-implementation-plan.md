# Proxy Chain Implementation Plan

## Goal

Support a proxy chain where a client connects to proxy A, proxy A forwards the client's tunnel request to proxy B, and the traffic exits from proxy B.

## Current Flow

The current client accepts SOCKS5 locally, opens a pooled WebSocket to the configured server, and sends `Start session:<target>`.

The server currently dials the final target directly in `src/server.rs`:

- `websocket_traffic_handler` creates a direct TCP stream when `Target-Address` is present.
- `svr_normal_tunnel` opens a direct TCP stream when it receives `Start session:<target>`.

To support chaining, proxy A should still run as a server for inbound clients, but its outbound leg should optionally behave like an overtls client to proxy B.

## 1. Add Server-Side Chain Configuration

Extend `Server` in `src/config.rs` with an optional upstream chain config. Example:

```json
{
  "server_settings": {
    "listen_host": "0.0.0.0",
    "listen_port": 443,
    "chain": {
      "server_host": "proxy-b.example.com",
      "server_port": 443,
      "server_domain": "proxy-b.example.com",
      "tunnel_path": "/b-tunnel/",
      "disable_tls": false,
      "cafile": "",
      "dangerous_mode": false,
      "client_id": "proxy-a"
    }
  }
}
```

Prefer a dedicated `Chain` or `Upstream` struct instead of reusing top-level `client_settings` directly. `Config::check_correctness(true)` currently removes `self.client` in server mode, so chain configuration needs to live under `server_settings` or another server-preserved field.

## 2. Validate Proxy B at Startup

Update `Config::check_correctness(true)` to validate the chain block when present:

- Require `server_host` or `server_domain`.
- Default `server_port` to `443`.
- Standardize the chain tunnel path.
- Resolve and store proxy B's `SocketAddr`.
- Optionally run the same TCP reachability check used by client mode.
- Reject obvious self-chain loops where proxy A points to its own listen address.

This should mirror the normal client validation path while preserving server mode behavior.

## 3. Refactor WebSocket Client Creation for Reuse

The reusable pieces already exist in `src/client.rs`:

- `create_tls_ws_stream`
- `create_plaintext_ws_stream`
- `create_ws_stream`

Adjust these so proxy A can create a WebSocket to proxy B using chain config without requiring normal local SOCKS client settings.

A clean approach is to introduce an internal `UpstreamConfig` view containing:

- Target server address.
- TLS settings.
- Server domain.
- CA content or dangerous mode.
- Tunnel path.
- Client ID.

Then make both normal client mode and server-chain mode call the same WebSocket creation function.

## 4. Add a Server Egress Abstraction

Replace the hardcoded `tokio::net::TcpStream` outbound in `svr_normal_tunnel` with an abstraction that can represent either:

- Direct TCP to the final target, preserving current behavior.
- Chained WebSocket session to proxy B, new behavior.

The current server stores:

```rust
let mut outgoing: Option<tokio::net::TcpStream>;
```

Change this to an enum or boxed abstraction, for example:

```rust
enum ServerEgress<S> {
    Direct(tokio::net::TcpStream),
    Chained(tokio_tungstenite::WebSocketStream<S>),
}
```

For chained mode, when proxy A receives `Start session:<target>` from the original client, proxy A opens or reuses a WebSocket to proxy B and sends the same `Start session:<target>` to proxy B. Proxy B remains responsible for dialing the destination, so traffic exits at proxy B.

## 5. Preserve Session Control Messages

Proxy A must translate or forward these correctly:

- Client to A: `Start session:<target>`
- A to B: `Start session:<same target>`
- B to A: `Start session` confirmation
- A to client: `Start session` confirmation
- Either side: `End session`
- B to A: `Remote EOF`
- A to client: `Remote EOF`

The highest-risk behavior is confirmation timing. Today the server confirms after direct TCP connect. In chain mode, proxy A should only confirm to the client after proxy B confirms. Otherwise the client may start sending before proxy B has opened the final connection.

## 6. Start with TCP, Then Add UDP

TCP chaining should be implemented first because it matches the existing `Start session` protocol.

UDP chaining needs separate handling:

- Current UDP server mode exits locally in `src/server.rs`.
- Current UDP client mode already creates a UDP WebSocket tunnel in `src/udprelay.rs`.

After TCP works, add chain behavior so proxy A's UDP server tunnel forwards UDP packets through a UDP WebSocket to proxy B instead of sending datagrams locally.

## 7. Update Documentation and Examples

Document three modes:

- Normal client to server: existing behavior.
- Normal server direct egress: existing behavior.
- Chained server A to server B: new behavior.

Clarify that proxy B uses ordinary `server_settings`; only proxy A needs the chain block.

## 8. Verification Plan

Add tests in stages:

- Config parsing and validation for chain config.
- Chain disabled preserves current direct egress behavior.
- TCP integration test with three local processes:
  - Client local SOCKS.
  - Proxy A with chain to B.
  - Proxy B direct egress.
- Assert destination sees proxy B as the TCP peer, not proxy A.
- Failure test: proxy B unreachable causes proxy A to return `End session` and not confirm `Start session`.
- UDP integration test after TCP support lands.

