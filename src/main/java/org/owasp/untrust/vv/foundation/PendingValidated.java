package org.owasp.untrust.vv.foundation;

import org.owasp.untrust.valuedescriptors.foundation.PubliclyRepresentable;

public interface PendingValidated<T> extends SelfValidating<T>, PubliclyRepresentable {
    T exposeForValidationOnly();

    @Override
    default String toPublicString() {
        return "[pending validation]";
    }
}
