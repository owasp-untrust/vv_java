package org.owasp.untrust.vv.visibility;

import org.owasp.untrust.valuedescriptors.foundation.PubliclyRepresentable;
import org.owasp.untrust.valuedescriptors.foundation.ExposableValue;
import org.owasp.untrust.vv.foundation.HalfBakedExposable;

public interface MaskedValue<T> extends 
        Sensitive<T>, 
        HalfBakedExposable<T>,
        PubliclyRepresentable {
    @Override
    default String toPublicString() {
        return mask(exposeUnchecked(EXPOSE_HALF_BAKED_VALUE_INTENDED_FOR_INTERNAL_LIBRARY_USE_ONLY_MARKER));
    }

    String mask(T value);
}
