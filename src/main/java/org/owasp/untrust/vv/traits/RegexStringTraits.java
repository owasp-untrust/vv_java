package org.owasp.untrust.vv.traits;

import java.util.Optional;
import java.util.regex.Pattern;

import org.owasp.untrust.vv.exceptions.ValidationException;

public abstract class RegexStringTraits extends PrintableUnicodeStringTraits {
    public abstract Pattern welcomeListRegex();
    public abstract Optional<ValidationException> findExtraValidationProblem(String value);

    @Override
    public Optional<ValidationException> findExtraValidationProblemInPrintableValue(String value) {
        if (!welcomeListRegex().matcher(value).matches()) {
            return Optional.of(new ValidationException(value, "String does not match required " + descriptionInErrors() + " pattern.", welcomeListRegex().toString()));
        }
    
        return findExtraValidationProblem(value);
    }    
}
