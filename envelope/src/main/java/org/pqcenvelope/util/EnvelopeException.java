package org.pqcenvelope.util;

/** Unchecked wrapper for the checked JCE/crypto exceptions on the wrap/unwrap path. */
public final class EnvelopeException extends RuntimeException {
    public EnvelopeException(String message, Throwable cause) {
        super(message, cause);
    }
}
