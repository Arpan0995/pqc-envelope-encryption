package org.pqcenvelope;

import javax.crypto.SecretKey;

/**
 * Protects and recovers a per-record data-encryption key (DEK) under a long-lived key-encryption key
 * (KEK) --- the envelope-encryption pattern used by every KMS and encrypting datastore.
 *
 * <ul>
 *   <li>{@link #wrap(SecretKey)} --- the write path: protect a fresh DEK, returning the envelope to
 *       store alongside the record.</li>
 *   <li>{@link #unwrap(Envelope)} --- the read path (latency-critical): recover the DEK to decrypt a
 *       record.</li>
 * </ul>
 */
public interface KeyEnvelopeProvider {

    /** Stable scheme identifier used in results. */
    String name();

    /** Protect a DEK under the KEK (write path). */
    Envelope wrap(SecretKey dek);

    /** Recover a DEK from its envelope (read path). */
    SecretKey unwrap(Envelope envelope);
}
