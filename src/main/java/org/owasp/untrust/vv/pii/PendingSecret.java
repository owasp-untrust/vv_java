package org.owasp.untrust.vv.pii;

import java.util.Objects;

public final class PendingSecret<T> implements PendingPii<T> {
    private T value;

    public PendingSecret(T value) {
        this.value = Objects.requireNonNull(value);
    }

    public synchronized Secret<T> hide(
            SecretStore<T> store,
            SecretReference reference) {

        Objects.requireNonNull(store);
        Objects.requireNonNull(reference);

        if (value == null) {
            throw new IllegalStateException(
                    "Pending secret has already been hidden");
        }

        store.write(reference, value);

        /*
         * Remove this object's reference only after Vault confirms
         * that the write succeeded.
         */
        value = null;

        return new Secret<>(store, reference);
    }
}
