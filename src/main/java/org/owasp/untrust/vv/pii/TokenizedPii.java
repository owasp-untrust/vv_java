package org.owasp.untrust.vv.pii;

import java.util.Objects;

public final class TokenizedPii<T> implements Pii<T> {
    private final T value;
    private final String token;

    public TokenizedPii(T value, String token) {
        this.value = value;
        this.token = Objects.requireNonNull(token);
    }

    public T exposeUnchecked() {
        return value;
    }

    public String token() {
        return token;
    }

    @Override
    public String toPublicString() {
        return token;
    }
}
