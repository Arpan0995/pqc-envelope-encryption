package org.pqcenvelope.util;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * The single, uniform DEK-wrap step shared by every scheme: AES-256-GCM under a wrapping key derived
 * from the KEM shared secret. Because all schemes wrap the DEK identically, measured differences
 * between schemes reflect key transport, not the wrap. The wrapped form is {@code nonce || ciphertext+tag}.
 */
public final class AesGcmKeyWrap {

    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;

    private AesGcmKeyWrap() {
    }

    /** Overhead in bytes added to the DEK by wrapping (nonce + GCM tag). */
    public static final int OVERHEAD_BYTES = NONCE_BYTES + TAG_BITS / 8;

    public static byte[] wrap(byte[] wrappingKey, byte[] dekBytes, SecureRandom rng) {
        try {
            byte[] nonce = new byte[NONCE_BYTES];
            rng.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(wrappingKey, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            byte[] ct = cipher.doFinal(dekBytes);
            byte[] out = new byte[NONCE_BYTES + ct.length];
            System.arraycopy(nonce, 0, out, 0, NONCE_BYTES);
            System.arraycopy(ct, 0, out, NONCE_BYTES, ct.length);
            return out;
        } catch (GeneralSecurityException e) {
            throw new EnvelopeException("AES-GCM key wrap failed", e);
        }
    }

    public static byte[] unwrap(byte[] wrappingKey, byte[] wrapped) {
        try {
            byte[] nonce = Arrays.copyOfRange(wrapped, 0, NONCE_BYTES);
            byte[] ct = Arrays.copyOfRange(wrapped, NONCE_BYTES, wrapped.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(wrappingKey, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            return cipher.doFinal(ct);
        } catch (GeneralSecurityException e) {
            throw new EnvelopeException("AES-GCM key unwrap failed", e);
        }
    }
}
