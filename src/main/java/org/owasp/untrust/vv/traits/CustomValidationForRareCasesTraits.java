package org.owasp.untrust.vv.traits;

import java.util.Optional;

import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.foundation.ValidationTraits;

public abstract class CustomValidationForRareCasesTraits<T> implements ValidationTraits<T> {
    public record Bounds(int minimum, int maximum, String message) {
    }

    public abstract Bounds rawBounds();

    @Override
    public Optional<ValidationException> findValidationProblemInRaw(String raw) {
        Bounds bounds = rawBounds();
        if (raw.length() < bounds.minimum()) {
            return Optional.of(new ValidationException(raw, bounds.message(), bounds.minimum()));
        }

        if (raw.length() > bounds.maximum()) {
            return Optional.of(new ValidationException(raw, bounds.message(), bounds.maximum()));
        }

        return Optional.empty();
    }
}
