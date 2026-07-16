package org.owasp.untrust.vv.traits;

import java.util.Optional;

import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.foundation.ValidationTraits;

public abstract class CustomValidationForRareCasesTraits<T> implements ValidationTraits<T> {
    public static record Bounds(int min, int max, String message) { }

    public abstract Bounds rawBounds();
    
    @Override
    public Optional<ValidationException> findValidationProblemInRaw(String raw) {
        Bounds bounds = rawBounds();
        if (raw.length() < bounds.min()) {
            return Optional.of(new ValidationException(raw, bounds.message, bounds.min()));
        }
        if (raw.length() > bounds.max()) {
            return Optional.of(new ValidationException(raw, bounds.message, bounds.max()));
        }
        return Optional.empty();
    }
}
