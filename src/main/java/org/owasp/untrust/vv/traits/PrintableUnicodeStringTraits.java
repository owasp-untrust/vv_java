package org.owasp.untrust.vv.traits;

import java.util.Optional;

import org.owasp.untrust.vv.exceptions.ValidationException;

public abstract class PrintableUnicodeStringTraits extends BoundedAnyContentStringTraits {
    public abstract Optional<ValidationException> findExtraValidationProblemInPrintableValue(String value);

    @Override
    public final Optional<ValidationException> findValidationProblemInNormalizedValue(String value) {
        Optional<Integer> invalidCodePoint = value.codePoints()
                .filter(codePoint -> !isPrintableUnicode(codePoint))
                .boxed()
                .findFirst();

        if (invalidCodePoint.isPresent()) {
            return Optional.of(new ValidationException(value, "Value must contain only printable Unicode characters.", Optional.empty()));
        }

        return findExtraValidationProblemInPrintableValue(value);
    }

    private static boolean isPrintableUnicode(int codePoint) {
        if (!Character.isValidCodePoint(codePoint)) {
            return false;
        }

        int type = Character.getType(codePoint);
        return type != Character.CONTROL
                && type != Character.FORMAT
                && type != Character.PRIVATE_USE
                && type != Character.SURROGATE
                && type != Character.UNASSIGNED;
    }
}
