package org.owasp.untrust.vv.pii;

@FunctionalInterface
public interface PiiHasher<T> {
    byte[] hash(T value);
}
