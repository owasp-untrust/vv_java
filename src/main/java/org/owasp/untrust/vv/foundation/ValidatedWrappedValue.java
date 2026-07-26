package org.owasp.untrust.vv.foundation;

public class ValidatedWrappedValue<T> implements SelfValidating<T>, HalfBakedExposable<T> {
    private T m_validatedValue;


    protected ValidatedWrappedValue(String raw, ValidationTraits<T> traits) {
        m_validatedValue = validate(raw, traits);
    }


    @Override
    public T exposeUnchecked(ExposeHalfBakedValueIntendedForInternalLibraryUseOnlyMarker marker) {
        return m_validatedValue;
    }
}
