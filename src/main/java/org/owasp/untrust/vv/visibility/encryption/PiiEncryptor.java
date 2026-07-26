package org.owasp.untrust.vv.visibility.encryption;

@FunctionalInterface
public interface PiiEncryptor<T, K> {
    byte[] encrypt(T value, K key, byte[] iv);
}
