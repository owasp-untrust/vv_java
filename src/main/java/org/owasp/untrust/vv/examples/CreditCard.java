package org.owasp.untrust.vv.examples;

import java.util.Optional;

import org.apache.commons.validator.routines.CreditCardValidator;
import com.fasterxml.jackson.annotation.JsonCreator;
import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.foundation.ValidatedWrappedValue;
import org.owasp.untrust.vv.foundation.ValidationTraits;
import org.owasp.untrust.vv.visibility.MaskedValue;

import static org.owasp.untrust.valuedescriptors.Hardcoded.hardcoded;

public final class CreditCard extends ValidatedWrappedValue<String> implements MaskedValue<String> {
    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    public CreditCard(String raw) {
        super(raw, new Traits());
    }

    public static CreditCard from(String raw) {
        return new CreditCard(raw);
    }

    @Override
    public String mask(String value) {
        if (value.length() <= 4) {
            return "[sensitive]";
        }

        char[] masked = new char[value.length()];
        int hiddenLength = value.length() - 4;
        for (int i = 0; i < hiddenLength; i++) {
            masked[i] = '*';
        }
        value.getChars(hiddenLength, value.length(), masked, hiddenLength);
        return String.valueOf(masked);
    }

    @Override
    public String toString() {
        return toPublicString();
    }

    public static final class Traits implements ValidationTraits<String> {
        private static final CreditCardValidator VALIDATOR = CreditCardValidator.genericCreditCardValidator(12, 19);

        @Override
        public Hardcoded descriptionInErrors() {
            return hardcoded("credit card number");
        }

        @Override
        public Optional<ValidationException> findValidationProblemInRaw(String raw) {
            if (VALIDATOR.isValid(raw)) {
                return Optional.empty();
            }

            return Optional.of(new ValidationException(
                    "[sensitive]",
                    "Invalid credit card number.",
                    "Failed credit card syntax or check digit validation."));
        }

        @Override
        public String parse(String raw) {
            return raw;
        }

        @Override
        public String normalize(String parsed) {
            return parsed;
        }

        @Override
        public Optional<ValidationException> findValidationProblemInNormalizedValue(String normalized) {
            return Optional.empty();
        }
    }
}
