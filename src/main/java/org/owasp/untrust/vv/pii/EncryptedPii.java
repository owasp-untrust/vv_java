package org.owasp.untrust.vv.pii;

import java.util.Arrays;
import java.util.Objects;

public final class EncryptedPii<T> implements Pii<T> {
    private final byte[] ciphertext;
    private final byte[] iv;

    public EncryptedPii(byte[] ciphertext, byte[] iv) {
        this.ciphertext = Objects.requireNonNull(ciphertext).clone();
        this.iv = Objects.requireNonNull(iv).clone();
    }

    public byte[] ciphertext() {
        return ciphertext.clone();
    }

    public byte[] iv() {
        return iv.clone();
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof EncryptedPii<?> that)) {
            return false;
        }
        return Arrays.equals(ciphertext, that.ciphertext) && Arrays.equals(iv, that.iv);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(ciphertext) + Arrays.hashCode(iv);
    }
}
