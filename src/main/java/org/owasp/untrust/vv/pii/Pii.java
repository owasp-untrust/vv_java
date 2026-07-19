package org.owasp.untrust.vv.pii;

import org.owasp.untrust.valuedescriptors.foundation.ToStringPublicReplacement;

public interface Pii<T> extends ToStringPublicReplacement {
    String PUBLIC_REPLACEMENT = "[pii]";

    @Override
    default String toPublicString() {
        return PUBLIC_REPLACEMENT;
    }
}
