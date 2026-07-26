package org.owasp.untrust.vv.visibility;

public interface RedactedValue<T> extends Sensitive<T> {
    public static final String PUBLIC_REPLACEMENT = "[sensitive]";

    @Override
    default String toPublicString() {
        return PUBLIC_REPLACEMENT;
    }
}
