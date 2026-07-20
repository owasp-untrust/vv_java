package org.owasp.untrust.vv.pii;

import java.util.Objects;
import java.util.function.Function;

public final class TokenizationPendingPii<T> implements PendingPii<T> {
    private final T value;

    public TokenizationPendingPii(T value) {
        this.value = Objects.requireNonNull(value);
    }

    public TokenizedPii<T> tokenize(Function<T, String> tokenizer) {
        return new TokenizedPii<>(value, tokenizer.apply(value));
    }
}
