package org.owasp.untrust.vv.traits;

import java.util.Optional;

import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.foundation.ValidationTraits;

// When using this traits class - supply a justification
// why the entire type's range is valid in the app.
public abstract class RareTraitsCaseWhereParsingIsTheWholeValidation<T> implements ValidationTraits<T> {
    public static record Bounds<T>(T min, T max) { }

    public abstract Bounds<Integer> rawBounds();
    
    @Override
    public Optional<ValidationException> findValidationProblemInRaw(String raw) {
        Bounds<Integer> bounds = rawBounds();
        if (raw.length() < bounds.min()) {
            return Optional.of(new ValidationException(raw, descriptionInErrors() + ": Value is too short.", bounds.min()));
        }
        if (raw.length() > bounds.max()) {
            return Optional.of(new ValidationException(raw, descriptionInErrors() + ": Value is too long.", bounds.max()));
        }
        return Optional.empty();
    }

    @Override
    public Optional<ValidationException> findValidationProblemInNormalizedValue(T value) {
        // Since parsing is the whole validation, we don't need to check bounds for normalized values
        return Optional.empty();
    }
}
