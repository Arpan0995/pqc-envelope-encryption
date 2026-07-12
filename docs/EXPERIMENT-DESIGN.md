# Experimental Design — PQC-Protected Envelope Encryption for Data-at-Rest

**Working title:** *The Cost of Protecting Stored Data Now: A Java Measurement of Post-Quantum
Envelope Encryption for Data-at-Rest*

**Author:** Arpan Sharma
**Status:** Design draft v0.1 — pre-registration of research questions, hypotheses, and method. No
results yet.
**Repository:** `pqc-envelope-encryption` (standalone).

---

## 1. Motivation and gap

Envelope encryption is the universal pattern for protecting data-at-rest: a random per-record (or
per-object) **data-encryption key (DEK)** encrypts the payload with AES, and the DEK is itself
"wrapped" (encrypted) under a long-lived **key-encryption key (KEK)**. Every major cloud KMS (AWS KMS,
GCP KMS, Azure Key Vault) and every envelope-encrypting datastore uses this structure. The wrapped DEK
is stored next to the ciphertext, and rotating the KEK requires only re-wrapping DEKs, not
re-encrypting data.

Data-at-rest is precisely the asset threatened by **harvest-now-decrypt-later (HNDL)**: an adversary
who copies encrypted records today can decrypt them once a cryptographically relevant quantum computer
exists, if the DEKs were wrapped with classical (RSA/ECDH) key transport. Migrating the *wrapping* step
to ML-KEM (FIPS 203) closes this exposure for stored data.

Despite how central this pattern is, there is **no systematic measurement** of what PQC envelope
encryption costs in a JVM backend: the latency of wrap/unwrap, the per-record storage overhead of KEM
ciphertexts, throughput under load, and the cost of KEK rotation. Practitioners currently guess. This
project measures it.

## 2. System model

We model the KMS-style envelope, not a network KMS or HSM. A **KeyEnvelopeProvider** exposes:

- `wrap(DEK) -> Envelope` — protect a fresh AES-256 DEK under the KEK (the write path).
- `unwrap(Envelope) -> DEK` — recover the DEK to read a record (the read path; latency-critical).

The payload is encrypted with AES-256-GCM using the DEK; payload encryption is identical across
schemes and is measured separately (it is scheme-independent and not the object of study). The
`Envelope` is the serialized bytes stored per record: the key-transport material plus the wrapped DEK.

## 3. Schemes under test

All schemes are expressed through the same `KeyEnvelopeProvider` interface for a fair comparison. Each
derives (or transports) a wrapping key and wraps the 32-byte DEK with AES-256-GCM key wrap.

| Scheme | Key transport | Stored per envelope (approx.) |
|---|---|---|
| `aes-kw-static` (baseline) | static symmetric KEK, AES-KW (RFC 3394) | wrapped DEK (~40 B) |
| `rsa-2048-oaep` | RSA-2048 OAEP wrap of DEK | RSA ciphertext (~256 B) |
| `x25519-ecies` | ephemeral X25519 + HKDF, AES-GCM wrap | ephemeral pubkey (32 B) + wrapped DEK (~60 B) |
| `ml-kem-768` | ML-KEM-768 encapsulation + HKDF, AES-GCM wrap | KEM ciphertext (1088 B) + wrapped DEK (~60 B) |
| `hybrid-mlkem768-x25519` | ML-KEM-768 ⊕ X25519 shared secrets, HKDF, AES-GCM wrap | KEM ct (1088 B) + X25519 pubkey (32 B) + wrapped DEK |

The static-symmetric baseline bounds "no asymmetric key transport"; RSA and X25519 are the classical
comparators; ML-KEM is the PQC target; hybrid is the belt-and-suspenders configuration recommended
during transition (CNSA 2.0).

## 4. Research questions

- **RQ1 (latency).** How do wrap and, especially, **unwrap** (read-path) latencies of ML-KEM-768 and
  hybrid compare to RSA-2048-OAEP and X25519-ECIES at the DEK level?
- **RQ2 (storage).** What is the per-record envelope size for each scheme, and what does the overhead
  project to at scale (10⁶, 10⁹, 10¹² records)?
- **RQ3 (throughput).** What single-thread and concurrent read-path (unwrap) throughput does each
  scheme sustain?
- **RQ4 (key rotation).** What is the cost of rotating the KEK — re-wrapping N DEKs — for each scheme?
  (This is envelope encryption's core operational advantage; its PQC cost is unmeasured.)
- **RQ5 (hybrid overhead).** What is the marginal latency and storage cost of hybrid over PQC-only and
  over classical?

## 5. Hypotheses (pre-registered)

- **H1.** ML-KEM-768 **unwrap** (decapsulation) is *competitive with or faster than* RSA-2048
  decryption — RSA private-key operations are slow, and ML-KEM decapsulation is fast — so the read
  path may not regress, and could improve, despite PQC's reputation for being "heavy."
- **H2.** ML-KEM's cost is dominated by **storage**, not latency: the ~1088-byte KEM ciphertext per
  record is the defining overhead, material at 10⁹⁺ records, whereas classical schemes store far less.
- **H3.** Hybrid adds a small latency increment (one X25519 op) and ~32 bytes over PQC-only — cheap
  insurance.
- **H4.** KEK rotation cost scales linearly in the number of DEKs; the per-DEK re-wrap cost is
  dominated by one encapsulation (PQC) or one public-key op (classical), so PQC rotation throughput
  tracks encapsulation speed.

Any of these being *false* is equally publishable; the contribution is the measured reality.

## 6. Variables

**Independent:** scheme (5 levels); operation (wrap / unwrap / rotate); concurrency (1 … N threads for
RQ3); record/DEK count (for RQ2, RQ4). **Dependent:** latency (ns, with percentiles), throughput
(ops/s), envelope size (bytes). **Controlled:** DEK = AES-256; payload cipher = AES-256-GCM; pinned
JDK 21 and BouncyCastle 1.84; deterministic keys from recorded seeds; fixed heap; warm JVM.

## 7. Methodology

- **Micro-latency and throughput (RQ1, RQ3):** JMH — `SampleTime` mode for wrap/unwrap latency
  distributions (median, p95, p99) and `Throughput` mode for ops/s, including a multi-threaded read-path
  benchmark. Blackhole-guarded; steady-state after warm-up.
- **Storage accounting (RQ2):** deterministic construction of one envelope per scheme; measure exact
  serialized bytes; project to record-count scales; report a table and the storage-vs-scale curve.
- **Key rotation (RQ4):** create N DEK envelopes under KEK₀, rotate to KEK₁, re-wrap all N, measure
  total and per-DEK time and throughput per scheme.
- **Correctness (gating):** every provider must round-trip (`unwrap(wrap(dek)) == dek`) and the payload
  must decrypt; known-answer vectors where available; a wrong-KEK unwrap must fail cleanly. These run as
  JUnit tests before any benchmark result is trusted.

## 8. Metrics and reporting

Per scheme: wrap/unwrap median and p95/p99 latency; single- and multi-thread unwrap throughput;
envelope bytes and projected storage at 10⁶/10⁹/10¹² records; rotation time and throughput for N DEKs.
Raw JMH JSON and a results summary are committed under `results/`.

## 9. Threats to validity

- **JVM measurement noise** (JIT warm-up, GC): mitigated by JMH's methodology; report configuration.
- **Exploratory host.** Apple-Silicon (arm64), unpinned — treat as exploratory; authoritative numbers
  on a pinned-frequency Linux/x86-64 host. Both environments recorded.
- **Library specificity.** Results are tied to BouncyCastle 1.84 (and the JDK's RSA/EC); pinned and
  recorded. Framed as version-specific and re-runnable.
- **Fair-comparison risk.** All schemes share the identical DEK-wrap step (AES-256-GCM) and interface,
  so differences reflect key transport, not incidental implementation choices.

## 10. Reproducibility

Pinned OpenJDK 21 (exact build recorded), BouncyCastle 1.84 (`bcprov-jdk18on`), JMH 1.37, deterministic
seeds. Every result artifact embeds `java -version`, OS/CPU, JVM flags, and the harness git commit.
One-command reproduction per benchmark; raw data committed.

## 11. Deliverables and target venues

- **Artifact:** an open-source, uniform Java envelope-encryption benchmark across classical, PQC, and
  hybrid key transport — reusable beyond this paper.
- **Paper:** the first systematic measurement of PQC envelope-encryption cost for data-at-rest on the
  JVM, with concrete latency/storage/rotation numbers and scale projections.
  - Venues: IEEE SecDev, ACM SAC (Security track), ARES; practitioner-facing.

## 12. Non-goals

- Not a full/network KMS, HSM integration, or access-control model.
- Not a database-engine-internal at-rest study (page-level encryption); we measure the envelope layer.
- Not payload-cipher speed (AES-GCM), which is scheme-independent and held constant.
- Not key-agreement authentication/PKI (that is a separate project in this program).

---

*Pre-registration: research questions, schemes, and hypotheses are fixed before data collection so that
a result contrary to a hypothesis carries the same weight as a confirming one.*
