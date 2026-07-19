package org.owasp.untrust.vv.pii;

@FunctionalInterface
public interface PiiEncryptor<T, K> {
    byte[] encrypt(T value, K key, byte[] iv);
}
