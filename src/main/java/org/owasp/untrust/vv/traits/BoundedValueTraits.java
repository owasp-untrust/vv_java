package org.owasp.untrust.vv.traits;

import java.util.Optional;

import org.owasp.untrust.buildmetadata.StringConcatenationSafe;
import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.foundation.ValidationTraits;

import static org.owasp.untrust.valuedescriptors.Hardcoded.hardcoded;

@StringConcatenationSafe("Bounded trait messages are assembled from developer-authored validation labels and fixed rule text only. The rejected raw or parsed value is kept as structured ValidationException data and is not inserted into the string message.")
public abstract class BoundedValueTraits<T> implements ValidationTraits<T> {
    public record Bounds(int minimum, int maximum) {
    }

    public abstract Bounds rawBounds();

    public Optional<Bounds> valueBounds() {
        return Optional.empty();
    }

    public int valueForBounds(T normalized) {
        throw new UnsupportedOperationException("valueForBounds must be implemented when valueBounds is present.");
    }

    public Optional<ValidationException> findValidationProblemInBounded(T normalized) {
        return Optional.empty();
    }

    @Override
    public Optional<ValidationException> findValidationProblemInRaw(String raw) {
        Bounds bounds = rawBounds();
        int length = raw.length();
        if (length < bounds.minimum()) {
            return Optional.of(new ValidationException(raw, descriptionInErrors()
                    .concat(hardcoded(": Value is too short.")).value(), bounds.minimum()));
        }

        if (length > bounds.maximum()) {
            return Optional.of(new ValidationException(raw, descriptionInErrors()
                    .concat(hardcoded(": Value is too long.")).value(), bounds.maximum()));
        }

        return Optional.empty();
    }

    @Override
    public Optional<ValidationException> findValidationProblemInNormalizedValue(T normalized) {
        Optional<Bounds> maybeBounds = valueBounds();
        if (maybeBounds.isPresent()) {
            Bounds bounds = maybeBounds.get();
            int value = valueForBounds(normalized);
            if (value < bounds.minimum()) {
                return Optional.of(new ValidationException(normalized, descriptionInErrors()
                        .concat(hardcoded(": Value is too small.")).value(), bounds.minimum()));
            }

            if (value > bounds.maximum()) {
                return Optional.of(new ValidationException(normalized, descriptionInErrors()
                        .concat(hardcoded(": Value is too big.")).value(), bounds.maximum()));
            }
        }

        return findValidationProblemInBounded(normalized);
    }
}
