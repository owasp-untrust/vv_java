package org.owasp.untrust.vv.visibility.hash;

import java.util.Arrays;
import java.util.HexFormat;

import org.owasp.untrust.valuedescriptors.foundation.ExposableValue;
import org.owasp.untrust.vv.foundation.HalfBakedExposable;
import org.owasp.untrust.vv.foundation.SelfValidating;
import org.owasp.untrust.vv.visibility.PiiValue;

public final class RetainedHashedValue<T, V extends SelfValidating<T> & HalfBakedExposable<T>>
        extends PiiValue<T, V>
        implements ExposableValue<T> {
    private final byte[] hash;

    public RetainedHashedValue(V value, byte[] hash) {
        super(value);
        this.hash = hash.clone();
    }

    @Override
    public T exposeUnchecked() {
        return exposedValue();
    }

    public byte[] hash() {
        return hash.clone();
    }

    @Override
    public String toPublicString() {
        return HexFormat.of().formatHex(hash);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof RetainedHashedValue<?, ?> that)) {
            return false;
        }
        return Arrays.equals(hash, that.hash);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(hash);
    }
}
