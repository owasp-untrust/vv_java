package org.owasp.untrust.vv.visibility.secret;

import org.owasp.untrust.valuedescriptors.foundation.ExposableValue;
import org.owasp.untrust.valuedescriptors.foundation.PubliclyRepresentable;
import org.owasp.untrust.vv.foundation.SelfValidating;

public abstract class SecretValue<T>
        implements PubliclyRepresentable, ExposableValue<T>, SelfValidating<T> {
    private final SecretStore<T> store;
    private final SecretReference reference;
    private final String displayValue;

    protected <Derived extends SecretValue<T>> SecretValue(SecretValueInitializer<T, Derived> initializer) {
        this.store = initializer.store();
        this.reference = initializer.reference();
        this.displayValue = initializer.displayValue();
    }

    protected SecretValue(
            SecretStore<T> store,
            SecretReference reference,
            String displayValue) {
        this.store = store;
        this.reference = reference;
        this.displayValue = displayValue;
    }

    public SecretReference reference() {
        return reference;
    }

    @Override
    public T exposeUnchecked() {
        return revalidate(store.read(reference));
    }

    @Override
    public String toPublicString() {
        return displayValue;
    }

    @Override
    public String toString() {
        return toPublicString();
    }

    protected abstract T revalidate(T value);
}
