package org.owasp.untrust.vv.pii;

import java.util.Objects;

public final class Secret<T> implements Pii<T> {
    private final SecretStore<T> store;
    private final SecretReference reference;

    public Secret(
            SecretStore<T> store,
            SecretReference reference) {

        this.store = Objects.requireNonNull(store);
        this.reference = Objects.requireNonNull(reference);
    }

    @Override
    public T exposeUnchecked() {
        return store.read(reference);
    }
}
