# Results — PQC envelope encryption for data-at-rest (exploratory host)

Preliminary measurements of classical, post-quantum, and hybrid envelope encryption through a uniform
`KeyEnvelopeProvider` (identical HKDF + AES-256-GCM DEK wrap; only the KEM key transport differs).

**Headline: migrating envelope encryption from RSA-2048 to ML-KEM-768 is a latency and throughput
*improvement* on every operation — often by 10–20× — and its sole cost is storage (~1 KB per record).**
For data-at-rest, PQC is not a performance sacrifice; it is a read-path upgrade over RSA.

## Environment

- JDK OpenJDK 21.0.11 (Homebrew); macOS 27.0, arm64 (Apple Silicon), 8 logical processors; **unpinned**.
- BouncyCastle `bcprov-jdk18on` 1.84 (lightweight API for X25519/ML-KEM; JCE for RSA/AES-GCM).
- JMH 1.37; deterministic seeds. Treat as **exploratory**; authoritative runs on a pinned Linux/x86 host.
- Raw JMH JSON: `rq1-latency.json`, `rq34-single.json`, `rq3-8t.json`.

## RQ1 — wrap / unwrap latency (µs/op)

| Scheme | wrap median | wrap p99 | unwrap median | unwrap p99 |
|---|---|---|---|---|
| aes-kw-static | 3.83 | 9.41 | 3.75 | 9.39 |
| rsa-2048-oaep | 42.75 | 78.04 | **870.40** | 1120.26 |
| x25519-ecies | 80.38 | 123.52 | 60.61 | 94.59 |
| **ml-kem-768** | **34.69** | 64.74 | **42.30** | 79.78 |
| hybrid-mlkem768-x25519 | 112.00 | 177.66 | 99.20 | 158.46 |

The read-critical **unwrap** path: ML-KEM-768 is **~20× faster than RSA-2048** (42 µs vs 870 µs — RSA
pays a slow 2048-bit private-key operation) and faster than X25519. ML-KEM **wrap** is also faster than
both RSA and X25519. This confirms **H1** and exceeds it.

## RQ2 — per-record envelope storage

| Scheme | bytes/record | @10⁶ | @10⁹ | @10¹² |
|---|---|---|---|---|
| aes-kw-static | 60 | 57 MiB | 56 GiB | 55 TiB |
| rsa-2048-oaep | 316 | 301 MiB | 294 GiB | 287 TiB |
| x25519-ecies | 92 | 88 MiB | 86 GiB | 84 TiB |
| ml-kem-768 | 1148 | 1.1 GiB | **1.0 TiB** | 1.0 PiB |
| hybrid-mlkem768-x25519 | 1180 | 1.1 GiB | 1.1 TiB | 1.0 PiB |

ML-KEM's ~1088-byte ciphertext makes its envelope **~12× larger than X25519** and ~3.6× RSA. At 10⁹
records that is **1.0 TiB vs 86 GiB** of DEK-storage overhead. This confirms **H2**: PQC's cost here is
storage, not latency. (Payload ciphertext is separate and scheme-independent.)

## RQ3 — read-path (unwrap) throughput (ops/s)

| Scheme | 1 thread | 8 threads | scaling |
|---|---|---|---|
| aes-kw-static | 254,044 | 920,130 | 3.6× |
| rsa-2048-oaep | 1,127 | 6,054 | 5.4× |
| x25519-ecies | 16,040 | 84,004 | 5.2× |
| **ml-kem-768** | 22,747 | 118,179 | 5.2× |
| hybrid-mlkem768-x25519 | 9,614 | 49,409 | 5.1× |

ML-KEM sustains **~20× the read throughput of RSA** (118k vs 6k ops/s at 8 threads) and scales well
with cores.

## RQ4 — key-rotation cost (per DEK re-wrapped: unwrap old KEK + wrap new KEK)

| Scheme | µs / DEK | project: 10⁶ DEKs | 10⁹ DEKs (single thread) |
|---|---|---|---|
| aes-kw-static | 8.06 | 8 s | 2.2 h |
| rsa-2048-oaep | 932.46 | 15.5 min | **10.8 days** |
| x25519-ecies | 148.74 | 2.5 min | 1.7 days |
| **ml-kem-768** | 82.35 | 82 s | **22.9 h** |
| hybrid-mlkem768-x25519 | 220.39 | 3.7 min | 2.6 days |

ML-KEM rotation is **~11× faster than RSA** (dominated by RSA's slow unwrap). Rotating a billion DEKs:
~23 hours single-thread for ML-KEM versus ~11 days for RSA — and rotation is embarrassingly parallel.
Confirms **H4** (linear in DEK count; per-DEK cost tracks the key-transport ops).

## RQ5 — hybrid overhead

Hybrid ML-KEM-768 + X25519 is approximately **additive** over its components: unwrap 99 µs
(≈ 42 + 61), wrap 112 µs, rotation 220 µs, and +32 bytes of storage over ML-KEM-only. Cheap insurance
relative to the security benefit during transition. Confirms **H3**.

## Summary and interpretation

The common assumption that "PQC is heavy" is **false for envelope encryption of data-at-rest**. Against
the RSA baseline that KMS systems most commonly use for key wrapping, ML-KEM-768 is faster to wrap,
~20× faster to unwrap, ~20× higher read throughput, and ~11× faster to rotate. The one real cost is
storage: ~1 KB of KEM ciphertext per record, material at 10⁹⁺ records. The engineering guidance that
follows is concrete: for HNDL-threatened stored data, migrate DEK wrapping to ML-KEM (or hybrid) now —
the read path improves, and budget for the per-record storage overhead.

## Caveats and next

- Exploratory unpinned host; authoritative numbers on a pinned Linux/x86 host.
- Single implementation (BouncyCastle 1.84 / JDK JCE) and one parameter set per family.
- End-to-end record read/write (payload AES-GCM + envelope) is held constant here since the payload
  cipher is scheme-independent; a full-record workload harness is a natural extension.
