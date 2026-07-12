package org.pqcenvelope;

/**
 * The serialized bytes stored per record to protect its DEK: {@code encapsulation || wrapped-DEK}. Its
 * {@link #sizeBytes()} is the per-record storage overhead the study measures (RQ2).
 */
public record Envelope(byte[] bytes) {
    public int sizeBytes() {
        return bytes.length;
    }
}
