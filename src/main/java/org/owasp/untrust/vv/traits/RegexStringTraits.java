package org.owasp.untrust.vv.traits;

import java.util.Optional;
import java.util.regex.Pattern;

import org.owasp.untrust.buildmetadata.StringConcatenationSafe;
import org.owasp.untrust.vv.exceptions.ValidationException;

import static org.owasp.untrust.valuedescriptors.Hardcoded.hardcoded;

@StringConcatenationSafe("Regex validation messages are assembled from fixed developer-authored fragments and Hardcoded descriptions. The regex and rejected value are passed as structured fields, not manually interpolated into the message.")
public abstract class RegexStringTraits extends BoundedAnyContentStringTraits {
    public abstract Pattern welcomeListRegex();

    public Optional<ValidationException> findExtraValidationProblem(String normalized) {
        return Optional.empty();
    }

    @Override
    public Optional<ValidationException> findValidationProblemInNormalizedValue(String normalized) {
        Optional<ValidationException> boundedProblem = super.findValidationProblemInNormalizedValue(normalized);
        if (boundedProblem.isPresent()) {
            return boundedProblem;
        }

        if (!welcomeListRegex().matcher(normalized).matches()) {
            return Optional.of(new ValidationException(
                    normalized,
                    hardcoded("Invalid ").concat(descriptionInErrors()).concat(hardcoded(".")).value(),
                    welcomeListRegex()));
        }

        return findExtraValidationProblem(normalized);
    }
}
