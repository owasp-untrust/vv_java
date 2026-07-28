package org.owasp.untrust.vv.visibility;

import org.owasp.untrust.valuedescriptors.foundation.ExposableValue;

public class TokenizedValue<T> implements Sensitive<T>, ExposableValue<T> {
    private final T m_value;
    private final String m_replacement;

    public TokenizedValue(T value, String replacement) {
        this.m_value = value;
        this.m_replacement = replacement;
    }

    @Override
    public T exposeUnchecked() {
        return m_value;
    }

    @Override
    public String toPublicString() {
        return m_replacement;
    }

    @Override
    public String toString() {
        return toPublicString();
    }
}
