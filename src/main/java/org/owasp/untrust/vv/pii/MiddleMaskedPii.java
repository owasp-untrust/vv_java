package org.owasp.untrust.vv.pii;

public interface MiddleMaskedPii<T> extends MaskedPii<T> {
    @Override
    default String mask(T rawValue) {
        String value = String.valueOf(rawValue);
        if (value.length() < 4) {
            return "*".repeat(value.length());
        }
        return value.substring(0, 2) + "*".repeat(value.length() - 4) + value.substring(value.length() - 2);
    }
}
