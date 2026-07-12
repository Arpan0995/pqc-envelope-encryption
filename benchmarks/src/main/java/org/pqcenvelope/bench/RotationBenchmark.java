package org.pqcenvelope.bench;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.pqcenvelope.Dek;
import org.pqcenvelope.Envelope;
import org.pqcenvelope.KeyEnvelopeProvider;
import org.pqcenvelope.Providers;
import org.pqcenvelope.util.DeterministicSecureRandom;

import javax.crypto.SecretKey;
import java.util.concurrent.TimeUnit;

/**
 * RQ4 --- per-DEK key-rotation cost per scheme. Rotating the KEK re-wraps each stored DEK: unwrap under
 * the old KEK, then wrap under the new KEK. This is the operation envelope encryption performs to
 * rotate without re-encrypting data; total rotation time is this per-DEK cost times the number of DEKs.
 */
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 10, time = 1)
@Fork(1)
public class RotationBenchmark {

    @Param({"aes-kw-static", "rsa-2048-oaep", "x25519-ecies", "ml-kem-768", "hybrid-mlkem768-x25519"})
    public String scheme;

    private KeyEnvelopeProvider oldKek;
    private KeyEnvelopeProvider newKek;
    private Envelope underOldKek;

    @Setup(Level.Trial)
    public void setup() {
        oldKek = Providers.create(scheme, 0);
        newKek = Providers.create(scheme, 1);
        SecretKey dek = Dek.random(new DeterministicSecureRandom(0xDE4));
        underOldKek = oldKek.wrap(dek);
    }

    @Benchmark
    public Envelope reWrapOneDek() {
        SecretKey dek = oldKek.unwrap(underOldKek);
        return newKek.wrap(dek);
    }
}
