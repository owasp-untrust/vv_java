package org.owasp.untrust.vv.pii;

import org.owasp.untrust.valuedescriptors.foundation.ToStringPublicReplacement;

public interface PendingPii<T> extends ToStringPublicReplacement {
    String PUBLIC_REPLACEMENT = "[pending pii]";

    @Override
    default String toPublicString() {
        return PUBLIC_REPLACEMENT;
    }
}
