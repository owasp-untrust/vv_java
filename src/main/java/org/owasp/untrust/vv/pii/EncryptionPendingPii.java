package org.owasp.untrust.vv.pii;

import java.util.Objects;

public final class EncryptionPendingPii<T, K> implements PendingPii<T> {
    private final T value;
    private final PiiEncryptor<T, K> encryptor;

    public EncryptionPendingPii(T value, PiiEncryptor<T, K> encryptor) {
        this.value = Objects.requireNonNull(value);
        this.encryptor = Objects.requireNonNull(encryptor);
    }

    public EncryptedPii<T> encrypt(K key, byte[] iv) {
        Objects.requireNonNull(key);
        Objects.requireNonNull(iv);
        return new EncryptedPii<>(encryptor.encrypt(value, key, iv), iv);
    }
}
