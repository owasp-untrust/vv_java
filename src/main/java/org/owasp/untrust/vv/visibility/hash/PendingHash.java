package org.owasp.untrust.vv.visibility.hash;

import org.owasp.untrust.valuedescriptors.foundation.PubliclyRepresentable;
import org.owasp.untrust.vv.foundation.HalfBakedExposable;
import org.owasp.untrust.vv.foundation.SelfValidating;

public final class PendingHash<V extends SelfValidating<T> & HalfBakedExposable<T>, T>
        implements PubliclyRepresentable {
    private final V value;

    public PendingHash(V value) {
        this.value = value;
    }

    public V valueObjectForValidationFlow() {
        return value;
    }

    public RetainedHashedValue<T, V> retainRaw(PiiHasher<T> hasher) {
        return new RetainedHashedValue<>(
                value,
                hasher.hash(value.exposeUnchecked(HalfBakedExposable.EXPOSE_HALF_BAKED_VALUE_INTENDED_FOR_INTERNAL_LIBRARY_USE_ONLY_MARKER)));
    }

    public HashOnlyValue<T, V> hashOnly(PiiHasher<T> hasher) {
        return new HashOnlyValue<>(
                value,
                hasher.hash(value.exposeUnchecked(HalfBakedExposable.EXPOSE_HALF_BAKED_VALUE_INTENDED_FOR_INTERNAL_LIBRARY_USE_ONLY_MARKER)));
    }

    @Override
    public String toPublicString() {
        return "[pending pii]";
    }

    @Override
    public String toString() {
        return toPublicString();
    }
}
