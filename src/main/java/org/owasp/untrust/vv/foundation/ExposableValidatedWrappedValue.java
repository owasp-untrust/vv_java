package org.owasp.untrust.vv.foundation;

import org.owasp.untrust.buildmetadata.NonFinalValidatedValue;
import org.owasp.untrust.valuedescriptors.foundation.ExposableValue;

@NonFinalValidatedValue("This shared base provides the only approved public exposure bridge for validated wrappers, so domain values can compose explicit ExposableValue behavior without duplicating the internal marker handoff.")
public abstract class ExposableValidatedWrappedValue<T> extends ValidatedWrappedValue<T> implements ExposableValue<T> {
    protected ExposableValidatedWrappedValue(String raw, ValidationTraits<T> traits) {
        super(raw, traits);
    }

    @Override
    public T exposeUnchecked() {
        return exposeUnchecked(EXPOSE_HALF_BAKED_VALUE_INTENDED_FOR_INTERNAL_LIBRARY_USE_ONLY_MARKER);
    }
}
