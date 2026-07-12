package org.pqcenvelope.kem;

import java.util.Arrays;

/**
 * Hybrid ML-KEM-768 + X25519 key transport ("belt and suspenders" for the CNSA 2.0 transition): the
 * encapsulation concatenates both component encapsulations, and the shared secret is the concatenation
 * of both component secrets. The downstream HKDF binds the two into one wrapping key, so the DEK stays
 * protected as long as <em>either</em> primitive holds.
 */
public final class HybridKem implements Kem {

    private final MlKem768Kem mlkem;
    private final X25519Kem x25519;

    public HybridKem(long mlkemSeed, long x25519Seed) {
        this.mlkem = new MlKem768Kem(mlkemSeed);
        this.x25519 = new X25519Kem(x25519Seed);
    }

    @Override
    public String name() {
        return "hybrid-mlkem768-x25519";
    }

    @Override
    public int encapsulationLength() {
        return mlkem.encapsulationLength() + x25519.encapsulationLength();
    }

    @Override
    public Encapsulation encapsulate() {
        Encapsulation a = mlkem.encapsulate();
        Encapsulation b = x25519.encapsulate();
        return new Encapsulation(concat(a.encapsulation(), b.encapsulation()),
                concat(a.sharedSecret(), b.sharedSecret()));
    }

    @Override
    public byte[] decapsulate(byte[] encapsulation) {
        int split = mlkem.encapsulationLength();
        byte[] aEnc = Arrays.copyOfRange(encapsulation, 0, split);
        byte[] bEnc = Arrays.copyOfRange(encapsulation, split, encapsulation.length);
        return concat(mlkem.decapsulate(aEnc), x25519.decapsulate(bEnc));
    }

    private static byte[] concat(byte[] x, byte[] y) {
        byte[] out = new byte[x.length + y.length];
        System.arraycopy(x, 0, out, 0, x.length);
        System.arraycopy(y, 0, out, x.length, y.length);
        return out;
    }
}
