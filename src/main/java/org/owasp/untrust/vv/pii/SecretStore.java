package org.owasp.untrust.vv.pii;

public interface SecretStore<T> {
    void write(SecretReference reference, T value);

    T read(SecretReference reference);
}
