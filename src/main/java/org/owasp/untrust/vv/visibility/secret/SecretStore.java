package org.owasp.untrust.vv.visibility.secret;

public interface SecretStore<T> {
    void write(SecretReference reference, T value);

    T read(SecretReference reference);
}
