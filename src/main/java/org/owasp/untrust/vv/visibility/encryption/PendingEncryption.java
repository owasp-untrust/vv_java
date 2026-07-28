package org.owasp.untrust.vv.visibility.encryption;

import org.owasp.untrust.valuedescriptors.foundation.PubliclyRepresentable;
import org.owasp.untrust.vv.foundation.HalfBakedExposable;
import org.owasp.untrust.vv.foundation.SelfValidating;

public class PendingEncryption<T, V extends SelfValidating<T> & HalfBakedExposable<T>, K>
        implements PubliclyRepresentable {
    private final V value;
    private final PiiEncryptor<T, K> encryptor;

    public PendingEncryption(V value, PiiEncryptor<T, K> encryptor) {
        this.value = value;
        this.encryptor = encryptor;
    }

    public RetainedEncryptedValue<T, V> retainRaw(K key, byte[] iv) {
        return new RetainedEncryptedValue<>(
                value,
                encryptor.encrypt(
                        value.exposeUnchecked(HalfBakedExposable.EXPOSE_HALF_BAKED_VALUE_INTENDED_FOR_INTERNAL_LIBRARY_USE_ONLY_MARKER),
                        key,
                        iv),
                iv);
    }

    public EncryptedOnlyValue<T, V> encryptedOnly(K key, byte[] iv) {
        return new EncryptedOnlyValue<>(
                value,
                encryptor.encrypt(
                        value.exposeUnchecked(HalfBakedExposable.EXPOSE_HALF_BAKED_VALUE_INTENDED_FOR_INTERNAL_LIBRARY_USE_ONLY_MARKER),
                        key,
                        iv),
                iv);
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
