package org.owasp.untrust.vv.pii;

import org.owasp.untrust.valuedescriptors.foundation.PubliclyRepresentable;

public interface PendingPii<T> extends PubliclyRepresentable {
    String PUBLIC_REPLACEMENT = "[pending pii]";

    @Override
    default String toPublicString() {
        return PUBLIC_REPLACEMENT;
    }
}
