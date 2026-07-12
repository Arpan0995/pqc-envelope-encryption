package org.pqcenvelope.kem;

/**
 * A key-transport mechanism modeled uniformly as a KEM: {@link #encapsulate()} produces an
 * encapsulation (the bytes stored per envelope) and a shared secret (from which the DEK wrapping key
 * is derived), and {@link #decapsulate(byte[])} recovers the shared secret. Expressing every
 * scheme---the static-symmetric baseline, RSA-KEM, X25519, ML-KEM, and hybrid---through this one
 * interface makes their comparison fair: they differ only in key transport, then share an identical
 * HKDF + AES-256-GCM DEK wrap.
 */
public interface Kem {

    /** Stable scheme identifier used in results (e.g. {@code ml-kem-768}). */
    String name();

    /** Fixed length in bytes of the encapsulation this KEM produces (so envelopes need no length prefix). */
    int encapsulationLength();

    /** Produce a fresh encapsulation and its shared secret (the write path's key-transport step). */
    Encapsulation encapsulate();

    /** Recover the shared secret from an encapsulation (the read path's key-transport step). */
    byte[] decapsulate(byte[] encapsulation);
}
