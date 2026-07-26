package org.owasp.untrust.vv.visibility.secret;

public record SecretReference(String path) {
    public SecretReference {
        if (path.isBlank()) {
            throw new IllegalArgumentException("Secret reference path must not be blank.");
        }
        if (path.startsWith("/") || path.contains("..")) {
            throw new IllegalArgumentException("Secret reference path must be relative and bounded.");
        }
    }
}
