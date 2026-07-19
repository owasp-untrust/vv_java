package org.owasp.untrust.vv.pii;

import java.util.Objects;

public final class TokenizedPii<T> implements Pii<T> {
    private final String token;

    public TokenizedPii(String token) {
        this.token = Objects.requireNonNull(token);
    }

    public String token() {
        return token;
    }
}
