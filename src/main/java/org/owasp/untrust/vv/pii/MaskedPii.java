package org.owasp.untrust.vv.pii;

public interface MaskedPii<T> extends Pii<T> {
    //T exposeUnchecked();

    String mask(T value);

    @Override
    default String toPublicString() {
        return mask(exposeUnchecked());
    }
}
