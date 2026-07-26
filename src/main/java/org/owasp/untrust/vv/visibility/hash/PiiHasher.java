package org.owasp.untrust.vv.visibility.hash;

@FunctionalInterface
public interface PiiHasher<T> {
    byte[] hash(T value);
}
