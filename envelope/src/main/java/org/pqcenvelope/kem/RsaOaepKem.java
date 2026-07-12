package org.pqcenvelope.kem;

import org.pqcenvelope.util.DeterministicSecureRandom;
import org.pqcenvelope.util.EnvelopeException;

import javax.crypto.Cipher;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * RSA-2048 key transport expressed as a KEM (RSA-KEM): encapsulation is an RSA-OAEP encryption of a
 * fresh random 32-byte secret, which is the shared secret. This lets RSA share the uniform
 * HKDF+AES-GCM DEK-wrap pipeline with the other schemes for a fair comparison, while the cost measured
 * (a 2048-bit private-key operation on decapsulation) is the real RSA read-path cost.
 */
public final class RsaOaepKem implements Kem {

    private static final String TRANSFORM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final int SECRET_BYTES = 32;
    private static final int RSA_2048_CIPHERTEXT_BYTES = 256;

    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    private final SecureRandom rng;

    public RsaOaepKem(long seed) {
        try {
            this.rng = new DeterministicSecureRandom(seed);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048, rng);
            KeyPair kp = kpg.generateKeyPair();
            this.publicKey = kp.getPublic();
            this.privateKey = kp.getPrivate();
        } catch (GeneralSecurityException e) {
            throw new EnvelopeException("RSA key generation failed", e);
        }
    }

    @Override
    public String name() {
        return "rsa-2048-oaep";
    }

    @Override
    public int encapsulationLength() {
        return RSA_2048_CIPHERTEXT_BYTES;
    }

    @Override
    public Encapsulation encapsulate() {
        try {
            byte[] secret = new byte[SECRET_BYTES];
            rng.nextBytes(secret);
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, rng);
            byte[] ciphertext = cipher.doFinal(secret);
            return new Encapsulation(ciphertext, secret);
        } catch (GeneralSecurityException e) {
            throw new EnvelopeException("RSA-OAEP encapsulation failed", e);
        }
    }

    @Override
    public byte[] decapsulate(byte[] encapsulation) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(encapsulation);
        } catch (GeneralSecurityException e) {
            throw new EnvelopeException("RSA-OAEP decapsulation failed", e);
        }
    }
}
