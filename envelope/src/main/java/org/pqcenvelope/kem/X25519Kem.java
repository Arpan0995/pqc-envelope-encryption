package org.pqcenvelope.kem;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.pqcenvelope.util.DeterministicSecureRandom;

import java.security.SecureRandom;

/**
 * X25519 ECIES-style key transport as a KEM: encapsulation generates an ephemeral X25519 key pair and
 * agrees with the recipient's static public key; the raw 32-byte ephemeral public key is the
 * encapsulation and the agreement output is the shared secret. Uses the BouncyCastle lightweight API
 * for compact raw (unwrapped) 32-byte public keys.
 */
public final class X25519Kem implements Kem {

    private static final int X25519_KEY_BYTES = 32;

    private final X25519PrivateKeyParameters privateKey;
    private final X25519PublicKeyParameters publicKey;
    private final SecureRandom rng;

    public X25519Kem(long seed) {
        this.rng = new DeterministicSecureRandom(seed);
        X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
        gen.init(new X25519KeyGenerationParameters(rng));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        this.privateKey = (X25519PrivateKeyParameters) kp.getPrivate();
        this.publicKey = (X25519PublicKeyParameters) kp.getPublic();
    }

    @Override
    public String name() {
        return "x25519-ecies";
    }

    @Override
    public int encapsulationLength() {
        return X25519_KEY_BYTES;
    }

    @Override
    public Encapsulation encapsulate() {
        X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
        gen.init(new X25519KeyGenerationParameters(rng));
        AsymmetricCipherKeyPair ephemeral = gen.generateKeyPair();
        X25519PrivateKeyParameters ephemeralPriv = (X25519PrivateKeyParameters) ephemeral.getPrivate();
        X25519PublicKeyParameters ephemeralPub = (X25519PublicKeyParameters) ephemeral.getPublic();

        byte[] sharedSecret = new byte[X25519_KEY_BYTES];
        X25519Agreement agreement = new X25519Agreement();
        agreement.init(ephemeralPriv);
        agreement.calculateAgreement(publicKey, sharedSecret, 0);
        return new Encapsulation(ephemeralPub.getEncoded(), sharedSecret);
    }

    @Override
    public byte[] decapsulate(byte[] encapsulation) {
        X25519PublicKeyParameters ephemeralPub = new X25519PublicKeyParameters(encapsulation, 0);
        byte[] sharedSecret = new byte[X25519_KEY_BYTES];
        X25519Agreement agreement = new X25519Agreement();
        agreement.init(privateKey);
        agreement.calculateAgreement(ephemeralPub, sharedSecret, 0);
        return sharedSecret;
    }
}
