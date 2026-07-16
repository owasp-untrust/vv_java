package org.owasp.untrust.vv.traits;

import java.util.Optional;

import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.foundation.ValidationTraits;

public abstract class BoundedValueTraits<T> implements ValidationTraits<T> {
    public static record Bounds<T>(T min, T max) { }

    public abstract Bounds<Integer> rawBounds();
    public abstract Bounds<T> valueBounds();
    public abstract boolean smallerThan(T value1, T value2);
    public abstract Optional<ValidationException> findValidationProblemInBounded(T value);
    
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
        Bounds<T> bounds = valueBounds();
        if (smallerThan(value, bounds.min())) {
            return Optional.of(new ValidationException(value, descriptionInErrors() + ": Value is too small.", bounds.min()));
        }
        if (smallerThan(bounds.max(), value)) {
            return Optional.of(new ValidationException(value, descriptionInErrors() + ": Value is too big.", bounds.max()));
        }

        return findValidationProblemInBounded(value);
    }
}
