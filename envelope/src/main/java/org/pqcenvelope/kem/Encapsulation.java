package org.pqcenvelope.kem;

/**
 * The output of {@link Kem#encapsulate()}: the {@code encapsulation} bytes stored in the envelope, and
 * the {@code sharedSecret} from which the DEK wrapping key is derived (the shared secret is never
 * stored).
 */
public record Encapsulation(byte[] encapsulation, byte[] sharedSecret) {
}
