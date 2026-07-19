package org.owasp.untrust.vv.pii;

import java.util.Objects;

public final class HashingPendingPii<T> implements Pii<T> {
    private final T value;
    private final PiiHasher<T> hasher;

    public HashingPendingPii(T value, PiiHasher<T> hasher) {
        this.value = Objects.requireNonNull(value);
        this.hasher = Objects.requireNonNull(hasher);
    }

    public HashedPii<T> hash() {
        return new HashedPii<>(hasher.hash(value));
    }
}
