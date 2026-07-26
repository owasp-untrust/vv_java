package org.owasp.untrust.vv.visibility.token;

import org.owasp.untrust.valuedescriptors.foundation.PubliclyRepresentable;
import org.owasp.untrust.vv.foundation.HalfBakedExposable;
import org.owasp.untrust.vv.foundation.SelfValidating;

public final class PendingTokenization<V extends SelfValidating<T> & HalfBakedExposable<T>, T>
        implements PubliclyRepresentable {
    private final V value;

    public PendingTokenization(V value) {
        this.value = value;
    }

    public RetainedTokenizedValue<T, V> retainRaw(String token) {
        return new RetainedTokenizedValue<>(value, token);
    }

    public TokenOnlyValue<T, V> tokenOnly(String token) {
        return new TokenOnlyValue<>(value, token);
    }

    @Override
    public String toPublicString() {
        return "[pending pii]";
    }

    @Override
    public String toString() {
        return toPublicString();
    }
}
