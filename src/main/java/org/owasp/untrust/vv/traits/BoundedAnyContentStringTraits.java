package org.owasp.untrust.vv.traits;

import java.util.List;
import java.util.Optional;

import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.foundation.ValidationTraits;
import org.owasp.untrust.valuedescriptors.Hardcoded;

import static org.owasp.untrust.valuedescriptors.Hardcoded.hardcoded;

public abstract class BoundedAnyContentStringTraits implements ValidationTraits<String> {
    public static record Bounds(long min, long max) { }

    public abstract Bounds bounds();
    public String reformatString(String raw) { return raw; } // this is the place to trim, compress multiple spaces, change case, etc. - any normalization that is not strictly related to validation and is not expected to cause validation problems should be done here. Length check is repeated after this phase.

    @Override
    public String parse(String raw) {
        return raw;
    }

    @Override
    public final String normalize(String parsed) throws ValidationException{
        String reformatted = reformatString(parsed);
        if (reformatted.length() != parsed.length()) {
            Optional<ValidationException> validationProblem = checkBounds(parsed, Optional.of(reformatted), descriptionInErrors().concat(hardcoded(" (reformatted)")));
            if (validationProblem.isPresent()) {
                throw validationProblem.get();
            }
        }
        return reformatted;
    }

    @Override
    public Optional<ValidationException> findValidationProblemInRaw(String raw) {
        return checkBounds(raw, Optional.empty(), descriptionInErrors());
    }

    protected Optional<ValidationException> checkBounds(String raw, Optional<String> formatted, Hardcoded description) {
        Bounds bounds = bounds();
        if (raw.length() < bounds.min()) {
            return Optional.of(new ValidationException(Optional.of(raw), formatted, List.of(description + ": Value is too short."), Optional.of(bounds.min())));
        }
        if (raw.length() > bounds.max()) {
            return Optional.of(new ValidationException(Optional.of(raw), formatted, List.of(description + ": Value is too long."), Optional.of(bounds.max())));
        }
        return Optional.empty();
    }
}

