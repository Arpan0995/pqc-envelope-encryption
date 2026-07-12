package org.pqcenvelope;

import org.pqcenvelope.kem.Encapsulation;
import org.pqcenvelope.kem.Kem;
import org.pqcenvelope.util.AesGcmKeyWrap;
import org.pqcenvelope.util.Hkdf;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * The one envelope provider used for every scheme: it delegates key transport to a {@link Kem}, then
 * applies the uniform HKDF + AES-256-GCM DEK wrap. Because only the {@link Kem} varies, benchmark
 * differences across schemes isolate the cost of key transport.
 *
 * <p>Envelope layout: {@code encapsulation (Kem.encapsulationLength bytes) || wrapped-DEK}.
 */
public final class KemEnvelopeProvider implements KeyEnvelopeProvider {

    private final Kem kem;
    private final SecureRandom rng;

    public KemEnvelopeProvider(Kem kem, SecureRandom rng) {
        this.kem = kem;
        this.rng = rng;
    }

    @Override
    public String name() {
        return kem.name();
    }

    @Override
    public Envelope wrap(SecretKey dek) {
        Encapsulation e = kem.encapsulate();
        byte[] wrappingKey = Hkdf.deriveWrappingKey(e.sharedSecret());
        byte[] wrapped = AesGcmKeyWrap.wrap(wrappingKey, dek.getEncoded(), rng);

        byte[] enc = e.encapsulation();
        byte[] out = new byte[enc.length + wrapped.length];
        System.arraycopy(enc, 0, out, 0, enc.length);
        System.arraycopy(wrapped, 0, out, enc.length, wrapped.length);
        return new Envelope(out);
    }

    @Override
    public SecretKey unwrap(Envelope envelope) {
        byte[] bytes = envelope.bytes();
        int encLen = kem.encapsulationLength();
        byte[] encapsulation = Arrays.copyOfRange(bytes, 0, encLen);
        byte[] wrapped = Arrays.copyOfRange(bytes, encLen, bytes.length);

        byte[] sharedSecret = kem.decapsulate(encapsulation);
        byte[] wrappingKey = Hkdf.deriveWrappingKey(sharedSecret);
        byte[] dekBytes = AesGcmKeyWrap.unwrap(wrappingKey, wrapped);
        return new SecretKeySpec(dekBytes, "AES");
    }
}
