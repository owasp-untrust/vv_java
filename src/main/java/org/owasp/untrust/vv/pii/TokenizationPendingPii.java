package org.owasp.untrust.vv.pii;

import java.util.Objects;

public final class TokenizationPendingPii<T> implements Pii<T> {
    private final T value;

    public TokenizationPendingPii(T value) {
        this.value = Objects.requireNonNull(value);
    }

    public TokenizedPii<T> tokenize(String token) {
        return new TokenizedPii<>(token);
    }
}
