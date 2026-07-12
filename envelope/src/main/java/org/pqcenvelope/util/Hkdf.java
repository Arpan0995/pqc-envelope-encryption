package org.pqcenvelope.util;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import java.nio.charset.StandardCharsets;

/**
 * HKDF-SHA256 derivation of a 256-bit AES wrapping key from a KEM shared secret. Using a KDF (rather
 * than the raw shared secret) is required for correctness and binds a domain-separation label; for the
 * hybrid scheme it also combines the concatenated classical and post-quantum secrets into one key.
 */
public final class Hkdf {

    private static final byte[] INFO = "pqc-envelope/wrap-key/v1".getBytes(StandardCharsets.UTF_8);
    private static final int WRAP_KEY_BYTES = 32;

    private Hkdf() {
    }

    public static byte[] deriveWrappingKey(byte[] sharedSecret) {
        HKDFBytesGenerator gen = new HKDFBytesGenerator(new SHA256Digest());
        gen.init(new HKDFParameters(sharedSecret, null, INFO));
        byte[] out = new byte[WRAP_KEY_BYTES];
        gen.generateBytes(out, 0, WRAP_KEY_BYTES);
        return out;
    }
}
