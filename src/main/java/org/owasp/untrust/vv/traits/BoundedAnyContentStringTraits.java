package org.owasp.untrust.vv.traits;

import java.util.Optional;

import org.owasp.untrust.vv.exceptions.ValidationException;

public abstract class BoundedAnyContentStringTraits extends BoundedValueTraits<String> {
    public String reformatString(String raw) {
        return raw;
    }

    @Override
    public String parse(String raw) {
        return raw;
    }

    @Override
    public String normalize(String parsed) {
        String reformatted = reformatString(parsed);
        return normalizeReformattedString(reformatted);
    }

    protected String normalizeReformattedString(String reformatted) {
        return reformatted;
    }

    @Override
    public Optional<Bounds> valueBounds() {
        return Optional.of(rawBounds());
    }

    @Override
    public int valueForBounds(String normalized) {
        return normalized.length();
    }

    @Override
    public Optional<ValidationException> findValidationProblemInBounded(String normalized) {
        return findExtraValidationProblem(normalized);
    }

    public Optional<ValidationException> findExtraValidationProblem(String normalized) {
        return Optional.empty();
    }
}
