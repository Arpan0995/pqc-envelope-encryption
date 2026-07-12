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
import org.openjdk.jmh.infra.Blackhole;
import org.pqcenvelope.Dek;
import org.pqcenvelope.Envelope;
import org.pqcenvelope.KeyEnvelopeProvider;
import org.pqcenvelope.Providers;
import org.pqcenvelope.util.DeterministicSecureRandom;

import javax.crypto.SecretKey;
import java.util.concurrent.TimeUnit;

/**
 * RQ1 --- wrap and unwrap latency per scheme, reported as a sampled time distribution (median, p95,
 * p99). The unwrap path is the latency-critical read path. A pre-built envelope is unwrapped so the
 * measurement isolates the read cost (decapsulation + HKDF + AES-GCM unwrap) from wrap.
 */
@State(Scope.Thread)
@BenchmarkMode(Mode.SampleTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 10, time = 1)
@Fork(1)
public class WrapUnwrapBenchmark {

    @Param({"aes-kw-static", "rsa-2048-oaep", "x25519-ecies", "ml-kem-768", "hybrid-mlkem768-x25519"})
    public String scheme;

    private KeyEnvelopeProvider provider;
    private SecretKey dek;
    private Envelope preWrapped;

    @Setup(Level.Trial)
    public void setup() {
        provider = Providers.create(scheme);
        dek = Dek.random(new DeterministicSecureRandom(0xDE4));
        preWrapped = provider.wrap(dek);
    }

    @Benchmark
    public Envelope wrap() {
        return provider.wrap(dek);
    }

    @Benchmark
    public void unwrap(Blackhole bh) {
        bh.consume(provider.unwrap(preWrapped));
    }
}
