package org.owasp.untrust.vv.visibility.encryption;

import java.util.Arrays;
import java.util.HexFormat;

import org.owasp.untrust.valuedescriptors.foundation.ExposableValue;
import org.owasp.untrust.vv.foundation.HalfBakedExposable;
import org.owasp.untrust.vv.foundation.SelfValidating;
import org.owasp.untrust.vv.visibility.PiiValue;

public final class EncryptedOnlyValue<T, V extends SelfValidating<T> & HalfBakedExposable<T>>
        extends PiiValue<T, V>
        implements ExposableValue<T> {
    private final byte[] ciphertext;
    private final byte[] iv;

    public EncryptedOnlyValue(V value, byte[] ciphertext, byte[] iv) {
        super(value);
        this.ciphertext = ciphertext.clone();
        this.iv = iv.clone();
    }

    @Override
    public T exposeUnchecked() {
        throw new UnsupportedOperationException("Encrypted-only value cannot expose the original value.");
    }

    public byte[] ciphertext() {
        return ciphertext.clone();
    }

    public byte[] iv() {
        return iv.clone();
    }

    @Override
    public String toPublicString() {
        return HexFormat.of().formatHex(ciphertext);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof EncryptedOnlyValue<?, ?> that)) {
            return false;
        }
        return Arrays.equals(ciphertext, that.ciphertext)
                && Arrays.equals(iv, that.iv);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(ciphertext) + Arrays.hashCode(iv);
    }
}
