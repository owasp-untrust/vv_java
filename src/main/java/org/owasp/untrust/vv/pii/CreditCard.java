package org.owasp.untrust.vv.pii;

import java.util.Objects;
import java.util.Optional;

import org.apache.commons.validator.routines.CreditCardValidator;
import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.foundation.ValidationTraits;
import org.owasp.untrust.vv.foundation.ValidatedValue;

import static org.owasp.untrust.valuedescriptors.Hardcoded.hardcoded;

public final class CreditCard extends ValidatedValue<String, CreditCard.Traits> implements MaskedPii<String> {
    public CreditCard(String raw) throws ValidationException {
        super(raw, new Traits());
    }

    @Override
    public String mask(String value) {
        Objects.requireNonNull(value);
        if (value.length() <= 4) {
            return Pii.PUBLIC_REPLACEMENT;
        }
        return "*".repeat(value.length() - 4) + value.substring(value.length() - 4);
    }

    public static final class Traits implements ValidationTraits<String> {
        private static final CreditCardValidator VALIDATOR = CreditCardValidator.genericCreditCardValidator(12, 19);

        @Override
        public String parse(String raw) throws IllegalArgumentException {
            return raw;
        }

        @Override
        public String normalize(String parsed) throws ValidationException {
            return parsed;
        }

        @Override
        public Optional<ValidationException> findValidationProblemInRaw(String raw) {
            if (VALIDATOR.isValid(raw)) {
                return Optional.empty();
            }
            return Optional.of(new ValidationException(
                Pii.PUBLIC_REPLACEMENT,
                "Invalid credit card number.",
                "Failed credit card syntax or check digit validation."));
        }

        @Override
        public Optional<ValidationException> findValidationProblemInNormalizedValue(String normalized) {
            return Optional.empty();
        }

        @Override
        public Hardcoded descriptionInErrors() {
            return hardcoded("credit card number");
        }
    }
}
