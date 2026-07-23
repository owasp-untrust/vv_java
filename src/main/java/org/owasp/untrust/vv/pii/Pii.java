package org.owasp.untrust.vv.pii;

import org.owasp.untrust.valuedescriptors.foundation.PubliclyRepresentable;

public interface Pii<T> extends PubliclyRepresentable {
    String PUBLIC_REPLACEMENT = "[pii]";

    T exposeUnchecked();

    @Override
    default String toPublicString() {
        return PUBLIC_REPLACEMENT;
    }
}
