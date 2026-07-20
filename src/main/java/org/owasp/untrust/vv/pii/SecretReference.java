package org.owasp.untrust.vv.pii;

import java.util.Objects;

public record SecretReference(String path) {
    public SecretReference {
        Objects.requireNonNull(path);

        if (path.isBlank() || path.startsWith("/")) {
            throw new IllegalArgumentException(
                    "Secret path must be relative and non-empty");
        }
    }
}
