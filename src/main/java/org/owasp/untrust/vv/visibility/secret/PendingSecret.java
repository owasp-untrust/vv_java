package org.owasp.untrust.vv.visibility.secret;

import org.owasp.untrust.valuedescriptors.foundation.PubliclyRepresentable;
import org.owasp.untrust.vv.foundation.HalfBakedExposable;

public interface PendingSecret<T, ReceiverOfInitializer> 
        extends HalfBakedExposable<T>, PubliclyRepresentable {
    default SecretValueInitializer<T, ReceiverOfInitializer> hide(
            SecretStore<T> store,
            SecretReference reference,
            String displayValue) {
        store.write(reference, exposeUnchecked(EXPOSE_HALF_BAKED_VALUE_INTENDED_FOR_INTERNAL_LIBRARY_USE_ONLY_MARKER));
        return new SecretValueInitializer<>(store, reference, displayValue);
    }

    @Override
    default String toPublicString() {
        return "[pending secret]";
    }
}
