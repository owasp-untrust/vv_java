package org.owasp.untrust.vv.visibility.secret;

import org.owasp.untrust.vv.foundation.SelfValidating;

// ReceiverOfInitializer ensures that an initializer emitted by a PendingX is used on
// a SecretX and not on a SecretY. 
// This is a compile-time check that prevents accidental misuse of initializers.
public final class SecretValueInitializer<T, ReceiverOfInitializer> {
    private final SecretStore<T> store;
    private final SecretReference reference;
    private final String displayValue;

    SecretValueInitializer(
            SecretStore<T> store,
            SecretReference reference,
            String displayValue) {
        this.store = store;
        this.reference = reference;
        this.displayValue = displayValue;
    }

    SecretStore<T> store() {
        return store;
    }

    SecretReference reference() {
        return reference;
    }

    String displayValue() {
        return displayValue;
    }
}
