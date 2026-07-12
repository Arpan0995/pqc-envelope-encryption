package org.pqcenvelope.kem;

import org.pqcenvelope.util.DeterministicSecureRandom;

/**
 * Baseline "no asymmetric key transport": a static symmetric KEK is used directly as the shared
 * secret. Models a KMS with a symmetric master key. The encapsulation is empty; the DEK wrap (with a
 * random GCM nonce) still provides per-record uniqueness.
 */
public final class StaticSymmetricKem implements Kem {

    private final byte[] kek = new byte[32];

    public StaticSymmetricKem(long seed) {
        new DeterministicSecureRandom(seed).nextBytes(kek);
    }

    @Override
    public String name() {
        return "aes-kw-static";
    }

    @Override
    public int encapsulationLength() {
        return 0;
    }

    @Override
    public Encapsulation encapsulate() {
        return new Encapsulation(new byte[0], kek.clone());
    }

    @Override
    public byte[] decapsulate(byte[] encapsulation) {
        return kek.clone();
    }
}
