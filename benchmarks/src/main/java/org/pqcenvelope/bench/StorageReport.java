package org.pqcenvelope.bench;

import org.pqcenvelope.Dek;
import org.pqcenvelope.KeyEnvelopeProvider;
import org.pqcenvelope.Providers;
import org.pqcenvelope.util.DeterministicSecureRandom;

import javax.crypto.SecretKey;
import java.util.Locale;

/**
 * RQ2 --- per-record envelope size per scheme and its projection to scale. Envelope overhead is a
 * fixed per-record cost, so it is the defining cost of PQC envelope encryption at large record counts,
 * even where latency is competitive. Prints a table; run via
 * {@code java -cp benchmarks/target/benchmarks.jar org.pqcenvelope.bench.StorageReport}.
 */
public final class StorageReport {

    private static final long[] SCALES = {1_000_000L, 1_000_000_000L, 1_000_000_000_000L};

    private StorageReport() {
    }

    public static void main(String[] args) {
        SecretKey dek = Dek.random(new DeterministicSecureRandom(0x570A6E));

        System.out.println("Per-record envelope size and projected DEK-storage overhead by scheme");
        System.out.printf(Locale.ROOT, "%-26s %10s %14s %14s %14s%n",
                "scheme", "bytes/rec", "@1e6", "@1e9", "@1e12");
        System.out.println("-".repeat(82));

        long baseline = -1;
        for (String scheme : Providers.names()) {
            KeyEnvelopeProvider provider = Providers.create(scheme);
            int bytes = provider.wrap(dek).sizeBytes();
            if (baseline < 0) {
                baseline = bytes;
            }
            System.out.printf(Locale.ROOT, "%-26s %10d %14s %14s %14s%n",
                    scheme, bytes,
                    humanBytes((long) bytes * SCALES[0]),
                    humanBytes((long) bytes * SCALES[1]),
                    humanBytes((long) bytes * SCALES[2]));
        }
        System.out.println("-".repeat(82));
        System.out.printf(Locale.ROOT,
                "Note: 'bytes/rec' is the wrapped-DEK envelope only (payload ciphertext is separate and "
                        + "scheme-independent).%n");
    }

    private static String humanBytes(long bytes) {
        String[] units = {"B", "KiB", "MiB", "GiB", "TiB", "PiB"};
        double v = bytes;
        int u = 0;
        while (v >= 1024 && u < units.length - 1) {
            v /= 1024;
            u++;
        }
        return String.format(Locale.ROOT, "%.1f %s", v, units[u]);
    }
}
