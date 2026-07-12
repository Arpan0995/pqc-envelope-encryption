package org.pqcenvelope;

import org.pqcenvelope.kem.HybridKem;
import org.pqcenvelope.kem.Kem;
import org.pqcenvelope.kem.MlKem768Kem;
import org.pqcenvelope.kem.RsaOaepKem;
import org.pqcenvelope.kem.StaticSymmetricKem;
import org.pqcenvelope.kem.X25519Kem;
import org.pqcenvelope.util.DeterministicSecureRandom;

import java.util.List;

/**
 * Builds a {@link KeyEnvelopeProvider} for each scheme by name, from recorded deterministic seeds so
 * runs are reproducible. Central place shared by tests and benchmarks.
 */
public final class Providers {

    public static final String AES_KW_STATIC = "aes-kw-static";
    public static final String RSA_2048_OAEP = "rsa-2048-oaep";
    public static final String X25519_ECIES = "x25519-ecies";
    public static final String ML_KEM_768 = "ml-kem-768";
    public static final String HYBRID = "hybrid-mlkem768-x25519";

    private Providers() {
    }

    /** All scheme names, in the reporting order used across the study. */
    public static List<String> names() {
        return List.of(AES_KW_STATIC, RSA_2048_OAEP, X25519_ECIES, ML_KEM_768, HYBRID);
    }

    public static KeyEnvelopeProvider create(String name) {
        return create(name, 0L);
    }

    /**
     * Build a provider for a distinct KEK "generation" (different key material per generation), used by
     * the key-rotation benchmark to re-wrap DEKs from an old KEK under a new one.
     */
    public static KeyEnvelopeProvider create(String name, long generation) {
        long g = generation * 1000L;
        Kem kem = switch (name) {
            case AES_KW_STATIC -> new StaticSymmetricKem(0x01 + g);
            case RSA_2048_OAEP -> new RsaOaepKem(0x02 + g);
            case X25519_ECIES -> new X25519Kem(0x03 + g);
            case ML_KEM_768 -> new MlKem768Kem(0x04 + g);
            case HYBRID -> new HybridKem(0x05 + g, 0x06 + g);
            default -> throw new IllegalArgumentException("Unknown scheme: " + name
                    + ". Known: " + names());
        };
        // Distinct stream for the AES-GCM nonces, separate from the KEM key material.
        return new KemEnvelopeProvider(kem,
                new DeterministicSecureRandom(0xE0F00D ^ name.hashCode() ^ generation));
    }
}
