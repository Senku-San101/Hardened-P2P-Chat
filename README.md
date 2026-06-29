# Zero-Trust P2P Chat over Tor

A Debian-native, peer-to-peer encrypted chat that hides **content**,
**destination**, and **the fact that Tor is being used**. Two people who
can exchange a small bundle of data over a trusted side channel can hold a
forward-secret, deniable conversation that is hard to attribute even for a
state-level passive observer.

> **Honesty first.** No software guarantees anonymity against a *global*
> passive adversary, and operational mistakes (running outside
> Tails/Whonix, leaking the out-of-band bundle, malware on the endpoint)
> break every guarantee below. This tool reduces risk; it does not
> eliminate it. For higher assurance run it inside **Tails** or **Whonix**.

## Architecture

| Layer | Choice | Why |
|------|--------|-----|
| Transport | **Tor** via the **Snowflake** pluggable transport | Domain-fronted WebRTC traffic that looks like ordinary web calls; maintained and works today (meek-azure is deprecated). No VPN, no V2Ray, no third-party proxy that becomes a single observation point. |
| Destination hiding | **v3 onion service + x25519 client authorization** | Without the client's private key, Tor will not even serve the descriptor. Scanning/enumeration is infeasible. (v2 "stealth cookies" no longer exist in modern Tor.) |
| End-to-end encryption | **X3DH + Double Ratchet** (pure-Python) | Forward secrecy and deniability; compromise of one message key does not expose past or future messages. No long-term symmetric key. |
| Traffic analysis resistance | **Fixed 1024-byte cells + WTF-PAD-style adaptive padding** | Uniform cell sizes and randomized inter-cell timing defeat passive size/timing correlation, including during idle periods. |

```
[Sender]                               [Receiver]
 chatapp (X3DH+DR, padding)             chatapp (X3DH+DR, padding)
   | SOCKS5 127.0.0.1:9050                 | loopback 127.0.0.1:12345
 tor + snowflake-client  --- Tor --->   tor + snowflake-client
  (ClientOnionAuthDir)                    (v3 onion + authorized_clients)
```

## Requirements

- Debian 11 (Bullseye) or later, amd64
- `sudo`/root for installation
- `tor` and `snowflake-client` (installed by `install.sh`)
- Python 3.9+

## Install

```bash
git clone <this-repo> zt-chat && cd zt-chat
sudo ./install.sh
```

`install.sh` is idempotent. It installs system packages, creates a
virtualenv with the pure-Python crypto stack, and prepares a per-user
runtime directory at `~/.zt-chat` (mode `0700`). **No key material is ever
committed to the repo.**

If `snowflake-client` is not in your repos, enable Debian backports or the
Tor Project repository and re-run. The app expects it at
`/usr/bin/snowflake-client`.

## Usage

```bash
./run.sh
```

You are asked whether you are the **receiver** or the **sender**.

### Receiver
1. The app launches Tor over Snowflake and publishes a v3 onion service.
2. It prints three out-of-band (OOB) items (and a QR code):
   - **Onion address** (`<56 chars>.onion`)
   - **Client-auth private key** (x25519, base32) - the sender installs this
   - **Identity fingerprint** (SHA-256 of the X3DH identity key, 64 hex)
3. Share these **only** over a channel you trust (in person, encrypted
   call, dead drop). Then wait for the sender to connect.

### Sender
1. Paste the OOB bundle (`onion:auth_privkey:fingerprint`).
2. The app installs the client-auth key, launches Tor over Snowflake, and
   connects to the onion.
3. It fetches the receiver's prekey bundle, **verifies the identity key
   against the OOB fingerprint** (aborts on mismatch), runs X3DH, and
   starts the Double Ratchet.

Type messages; `/quit` exits. Every keystroke line is padded to a fixed
1024-byte cell and the padding scheduler fills silence with dummy cells.

## Out-of-band bundle

```
<onion>.onion:<base32 x25519 client-auth privkey>:<64-hex identity fingerprint>
```

The **client-auth private key is sent OOB** because, in this two-party
model, the sender is the single authorized client. The receiver keeps only
the public half in `authorized_clients/`.

## Security rationale

- **No VPN / no V2Ray / no public proxy.** Any central hop is a coercible
  legal entity and a single point of correlation. Removed entirely.
- **Snowflake** tunnels Tor inside domain-fronted WebRTC; blocking it means
  blocking large swaths of legitimate CDN/STUN traffic.
- **Client-authorized onion** refuses unauthorized descriptor fetches, so
  the destination cannot be probed or enumerated.
- **Double Ratchet** advances keys per message; old keys are discarded.
- **Fixed cells + adaptive padding** remove length and burst-silence
  signals that a guard-adjacent observer could correlate.

## What is intentionally NOT included

- No VPN layer, no V2Ray, no free external server.
- No static symmetric key (the OOB auth key is for Tor client auth only,
  never for message encryption).
- No unencrypted metadata such as plaintext message lengths.
- No hard-coded IPs of your own infrastructure.

## Operational security

- Plaintext is never written to disk; logging is stdout-only.
- Runtime dirs (`~/.zt-chat/*`) are `0700`; auth/key files are `0600`.
- Session keys live in memory and are wiped on exit (best-effort
  `sodium_memzero`). Python cannot guarantee no copies remain; for strong
  guarantees run inside an amnesic OS (Tails).
- Run nothing else that bypasses Tor on the same machine.

## Testing against the threat model

- **Client-auth enforcement:** try connecting without the auth key; the
  SOCKS connect must fail.
- **Fingerprint mismatch:** tamper with the prekey bundle; the sender must
  abort before any message is sent.
- **Transport fingerprint:** capture the NIC; you should see only
  Snowflake/WebRTC + CDN fronting, no Tor TLS signature.
- **Padding:** record timestamps while idle; cell cadence should be
  indistinguishable from active chat.

## Project status / known integration seam

The Tor management, v3 client auth, OOB exchange, transport, cell framing
and the WTF-PAD-style scheduler are implemented. The X3DH/Double Ratchet
wiring in `chatapp/crypto.py` is structured as a thin wrapper with clearly
marked integration seams (`public_prekey_bundle`, `start_initiator`,
`start_responder`, `encrypt`, `decrypt`). These must be bound to the pinned
`X3DH` / `DoubleRatchet` library versions (their abstract base classes
require app-chosen curve/AEAD/KDF/info parameters, and the API differs
between major versions). See the docstrings in `chatapp/crypto.py`.

This is the single remaining task to reach a runnable end-to-end build.

## License

MIT - see [LICENSE](LICENSE).
