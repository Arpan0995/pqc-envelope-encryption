# pqc-envelope-encryption

**What does it cost to protect stored data against "harvest-now-decrypt-later"?** A uniform Java
benchmark of classical, post-quantum, and hybrid **envelope encryption** — the KEM-wraps-a-DEK pattern
that every cloud KMS and encrypting datastore uses for data-at-rest.

Envelope encryption protects a payload with a random AES data-encryption key (DEK) and stores that DEK
**wrapped** under a key-encryption key (KEK). If the wrap uses classical RSA/ECDH key transport, every
record copied today is exposed to future quantum decryption. Migrating the wrap to ML-KEM (FIPS 203)
closes that exposure. This project measures the latency, storage, throughput, and key-rotation cost of
doing so.

## Status

Core + benchmarks implemented; first results in. Pre-registered design in
[`docs/EXPERIMENT-DESIGN.md`](docs/EXPERIMENT-DESIGN.md); full results in
[`results/RESULTS.md`](results/RESULTS.md).

**Headline (exploratory macOS/arm64 host):** migrating envelope encryption from RSA-2048 to ML-KEM-768
is a latency and throughput *improvement* on every operation — ML-KEM unwrap is **~20× faster than
RSA** (42 µs vs 870 µs), ~20× higher read throughput, and ~11× faster key rotation — and its only cost
is **storage** (~1 KB/record, ~12× X25519 at scale). For data-at-rest, PQC is a read-path upgrade over
RSA, not a sacrifice.

## Schemes compared (uniform `KeyEnvelopeProvider` interface)

| Scheme | Key transport | ~ stored per envelope |
|---|---|---|
| `aes-kw-static` | static symmetric KEK (RFC 3394) | ~40 B |
| `rsa-2048-oaep` | RSA-2048 OAEP | ~256 B |
| `x25519-ecies` | ephemeral X25519 + HKDF | ~92 B |
| `ml-kem-768` | ML-KEM-768 encapsulation + HKDF | ~1148 B |
| `hybrid-mlkem768-x25519` | ML-KEM-768 ⊕ X25519 + HKDF | ~1180 B |

All schemes share the identical DEK-wrap step (AES-256-GCM), so measured differences reflect key
transport, not incidental choices.

## Toolchain

- Java 21 (pinned OpenJDK 21)
- BouncyCastle `bcprov-jdk18on` 1.84
- JMH 1.37 for latency/throughput; Maven multi-module

Apple-Silicon (arm64) runs are exploratory; authoritative runs are on a pinned-frequency Linux/x86-64
host (see design doc §9).

## Layout

```
docs/EXPERIMENT-DESIGN.md   Pre-registered design (read this first)
envelope/                   KeyEnvelopeProvider abstraction + scheme implementations
benchmarks/                 JMH wrap/unwrap/rotation benchmarks
results/                    Raw JMH data + summaries (reproducible)
```

## License

Apache-2.0 (see `LICENSE`).
