package org.pqcenvelope.kem;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.pqcenvelope.util.DeterministicSecureRandom;

import java.security.SecureRandom;

/**
 * ML-KEM-768 (FIPS 203) key transport, via the BouncyCastle lightweight API. Encapsulation produces
 * the 1088-byte KEM ciphertext and a 32-byte shared secret; decapsulation recovers the shared secret.
 * This is the post-quantum wrapping the study measures against the classical schemes.
 */
public final class MlKem768Kem implements Kem {

    private final MLKEMPublicKeyParameters publicKey;
    private final MLKEMExtractor extractor;
    private final SecureRandom rng;
    private final int encapsulationLength;

    public MlKem768Kem(long seed) {
        this.rng = new DeterministicSecureRandom(seed);
        MLKEMKeyPairGenerator kpg = new MLKEMKeyPairGenerator();
        kpg.init(new MLKEMKeyGenerationParameters(rng, MLKEMParameters.ml_kem_768));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        this.publicKey = (MLKEMPublicKeyParameters) kp.getPublic();
        this.extractor = new MLKEMExtractor((MLKEMPrivateKeyParameters) kp.getPrivate());
        this.encapsulationLength = extractor.getEncapsulationLength();
    }

    @Override
    public String name() {
        return "ml-kem-768";
    }

    @Override
    public int encapsulationLength() {
        return encapsulationLength;
    }

    @Override
    public Encapsulation encapsulate() {
        SecretWithEncapsulation swe = new MLKEMGenerator(rng).generateEncapsulated(publicKey);
        return new Encapsulation(swe.getEncapsulation(), swe.getSecret());
    }

    @Override
    public byte[] decapsulate(byte[] encapsulation) {
        return extractor.extractSecret(encapsulation);
    }
}
