package org.pqcenvelope;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/** Helper for generating fresh AES-256 data-encryption keys. */
public final class Dek {

    public static final int DEK_BYTES = 32;

    private Dek() {
    }

    public static SecretKey random(SecureRandom rng) {
        byte[] key = new byte[DEK_BYTES];
        rng.nextBytes(key);
        return new SecretKeySpec(key, "AES");
    }
}
