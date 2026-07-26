package org.owasp.untrust.vv.visibility;

import org.owasp.untrust.valuedescriptors.foundation.PubliclyRepresentable;
import org.owasp.untrust.vv.foundation.HalfBakedExposable;
import org.owasp.untrust.vv.foundation.SelfValidating;

public abstract class VisibleValue<T, V extends SelfValidating<T>>
        implements HalfBakedExposable<T>, PubliclyRepresentable {
    private final T m_value;

    protected VisibleValue(T value) {
        this.m_value = value;
    }

    public final T exposeUnchecked(ExposeHalfBakedValueIntendedForInternalLibraryUseOnlyMarker marker) {
        return m_value;
    }

    @Override
    public final String toString() {
        return toPublicString();
    }
}
