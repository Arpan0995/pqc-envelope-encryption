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

import java.util.concurrent.TimeUnit;

/**
 * RQ3 --- read-path (unwrap) throughput in operations/second per scheme. Run with {@code -t 1} for the
 * single-thread figure and {@code -t <cores>} for the concurrent figure; the provider is thread-scoped
 * so each worker unwraps independently, modeling many concurrent record reads.
 */
@State(Scope.Thread)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 10, time = 1)
@Fork(1)
public class UnwrapThroughputBenchmark {

    @Param({"aes-kw-static", "rsa-2048-oaep", "x25519-ecies", "ml-kem-768", "hybrid-mlkem768-x25519"})
    public String scheme;

    private KeyEnvelopeProvider provider;
    private Envelope preWrapped;

    @Setup(Level.Trial)
    public void setup() {
        provider = Providers.create(scheme);
        preWrapped = provider.wrap(Dek.random(new DeterministicSecureRandom(0xDE4)));
    }

    @Benchmark
    public void unwrap(Blackhole bh) {
        bh.consume(provider.unwrap(preWrapped));
    }
}
