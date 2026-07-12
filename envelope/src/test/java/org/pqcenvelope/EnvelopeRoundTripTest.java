package org.pqcenvelope;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pqcenvelope.util.DeterministicSecureRandom;
import org.pqcenvelope.util.EnvelopeException;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Correctness gate for every scheme: a wrapped DEK round-trips, envelopes are randomized per wrap, and
 * a tampered envelope fails authentication. No benchmark result is trusted until these pass.
 */
class EnvelopeRoundTripTest {

    static List<String> schemes() {
        return Providers.names();
    }

    @ParameterizedTest
    @MethodSource("schemes")
    void wrapThenUnwrapRecoversTheDek(String scheme) {
        KeyEnvelopeProvider provider = Providers.create(scheme);
        SecretKey dek = Dek.random(new DeterministicSecureRandom(100));

        Envelope envelope = provider.wrap(dek);
        SecretKey recovered = provider.unwrap(envelope);

        assertArrayEquals(dek.getEncoded(), recovered.getEncoded(),
                scheme + ": unwrap(wrap(dek)) must recover the DEK");
        assertEquals32(recovered.getEncoded().length, scheme);
    }

    @ParameterizedTest
    @MethodSource("schemes")
    void envelopesAreRandomizedPerWrap(String scheme) {
        KeyEnvelopeProvider provider = Providers.create(scheme);
        SecretKey dek = Dek.random(new DeterministicSecureRandom(101));

        byte[] a = provider.wrap(dek).bytes();
        byte[] b = provider.wrap(dek).bytes();
        assertFalse(Arrays.equals(a, b),
                scheme + ": two wraps of the same DEK must differ (fresh encapsulation / nonce)");
    }

    @ParameterizedTest
    @MethodSource("schemes")
    void tamperedEnvelopeFailsAuthentication(String scheme) {
        KeyEnvelopeProvider provider = Providers.create(scheme);
        SecretKey dek = Dek.random(new DeterministicSecureRandom(102));

        byte[] bytes = provider.wrap(dek).bytes();
        bytes[bytes.length - 1] ^= 0x01; // flip a bit in the GCM tag region
        assertThrows(EnvelopeException.class, () -> provider.unwrap(new Envelope(bytes)),
                scheme + ": a tampered envelope must fail to unwrap");
    }

    private static void assertEquals32(int len, String scheme) {
        assertTrue(len == Dek.DEK_BYTES, scheme + ": DEK must be 32 bytes, was " + len);
    }
}
