package org.pqcenvelope;

import org.junit.jupiter.api.Test;
import org.pqcenvelope.util.AesGcmKeyWrap;
import org.pqcenvelope.util.DeterministicSecureRandom;

import javax.crypto.SecretKey;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Pins the exact per-record envelope size for each scheme (RQ2). The wrapped-DEK part is constant
 * across schemes (DEK + AES-GCM overhead), so sizes differ only by the encapsulation length.
 */
class EnvelopeSizeTest {

    private static final int WRAPPED_DEK = Dek.DEK_BYTES + AesGcmKeyWrap.OVERHEAD_BYTES; // 32 + 28 = 60

    @Test
    void envelopeSizesMatchExpectedPerScheme() {
        Map<String, Integer> expectedEncapsulation = new LinkedHashMap<>();
        expectedEncapsulation.put(Providers.AES_KW_STATIC, 0);
        expectedEncapsulation.put(Providers.RSA_2048_OAEP, 256);
        expectedEncapsulation.put(Providers.X25519_ECIES, 32);
        expectedEncapsulation.put(Providers.ML_KEM_768, 1088);
        expectedEncapsulation.put(Providers.HYBRID, 1088 + 32);

        SecretKey dek = Dek.random(new DeterministicSecureRandom(200));
        for (Map.Entry<String, Integer> e : expectedEncapsulation.entrySet()) {
            KeyEnvelopeProvider provider = Providers.create(e.getKey());
            int size = provider.wrap(dek).sizeBytes();
            assertEquals(e.getValue() + WRAPPED_DEK, size,
                    e.getKey() + ": envelope size");
        }
    }
}
