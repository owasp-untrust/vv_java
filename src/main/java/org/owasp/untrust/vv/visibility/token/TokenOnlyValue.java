package org.owasp.untrust.vv.visibility.token;

import org.owasp.untrust.valuedescriptors.foundation.ExposableValue;
import org.owasp.untrust.vv.foundation.HalfBakedExposable;
import org.owasp.untrust.vv.foundation.SelfValidating;
import org.owasp.untrust.vv.visibility.PiiValue;

public final class TokenOnlyValue<T, V extends SelfValidating<T> & HalfBakedExposable<T>>
        extends PiiValue<T, V>
        implements ExposableValue<T> {
    private final String token;

    public TokenOnlyValue(V value, String token) {
        super(value);
        this.token = token;
    }

    @Override
    public T exposeUnchecked() {
        throw new UnsupportedOperationException("Token-only value cannot expose the original value.");
    }

    public String token() {
        return token;
    }

    @Override
    public String toPublicString() {
        return token;
    }
}
