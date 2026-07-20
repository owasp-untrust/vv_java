package org.owasp.untrust.vv.pii;

import java.util.Arrays;
import java.util.Objects;

public final class HashedPii<T> implements Pii<T> {
    private final byte[] hash;

    public HashedPii(byte[] hash) {
        this.hash = Objects.requireNonNull(hash).clone();
    }

    public T exposeUnchecked() {
        throw new UnsupportedOperationException("Cannot expose encrypted PII without decryption");
    }

    public byte[] hash() {
        return hash.clone();
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof HashedPii<?> that)) {
            return false;
        }
        return Arrays.equals(hash, that.hash);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(hash);
    }
}
