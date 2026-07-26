package org.owasp.untrust.vv.visibility;

import org.owasp.untrust.vv.foundation.HalfBakedExposable;
import org.owasp.untrust.vv.foundation.SelfValidating;

public abstract class PiiValue<T, V extends SelfValidating<T> & HalfBakedExposable<T>>
        extends VisibleValue<T, V>
        implements Sensitive<T> {
    protected PiiValue(V value) {
        super(value.exposeUnchecked(EXPOSE_HALF_BAKED_VALUE_INTENDED_FOR_INTERNAL_LIBRARY_USE_ONLY_MARKER));
    }

    protected final T exposedValue() {
        return exposeUnchecked(EXPOSE_HALF_BAKED_VALUE_INTENDED_FOR_INTERNAL_LIBRARY_USE_ONLY_MARKER);
    }

    @Override
    public String toPublicString() {
        return "[sensitive]";
    }
}
