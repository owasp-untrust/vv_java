package org.owasp.untrust.vv.examples;

import java.util.function.Predicate;
import java.util.regex.Pattern;

import org.owasp.untrust.buildmetadata.NonFinalValidatedValue;
import org.owasp.untrust.vv.foundation.CrossValidatedReceiver;
import org.owasp.untrust.vv.foundation.CrossValidationCandidate;
import org.owasp.untrust.vv.foundation.ValidatedWrappedValue;
import org.owasp.untrust.vv.foundation.CrossValidationCandidate.FullyValidated;
import org.owasp.untrust.vv.traits.RegexStringTraits;
import org.owasp.untrust.vv.visibility.MiddleMaskedValue;
import org.owasp.untrust.valuedescriptors.Hardcoded;

import static org.owasp.untrust.valuedescriptors.Hardcoded.hardcoded;

public abstract class UsernameBase<ReceiverOfValidated extends UsernameBase<ReceiverOfValidated>>
        extends CrossValidatedReceiver<String, ReceiverOfValidated>
        implements MiddleMaskedValue {
        // ExposableValue<String> {
    protected UsernameBase(FullyValidated<String, ReceiverOfValidated> opaqueValue) {
        super(opaqueValue);
    }

    @NonFinalValidatedValue("This shared candidate base owns the common username syntax validation and cross-validation conversion used by distinct existing and registration username flows without changing its validation contract.")
    public abstract static class CandidateBase<ReceiverOfValidated extends UsernameBase<ReceiverOfValidated>>
            extends ValidatedWrappedValue<String> 
            implements MiddleMaskedValue,
                    CrossValidationCandidate<String, ReceiverOfValidated> {
        protected CandidateBase(String raw) {
            super(raw, new Traits());
        }

        protected FullyValidated<String, ReceiverOfValidated> crossValidateExists(Predicate<String> exists) {
            return crossValidate(exists, hardcoded("Username does not exist."));
        }

        protected FullyValidated<String, ReceiverOfValidated> crossValidateDoesNotExist(Predicate<String> exists) {
            return crossValidate((value) -> !exists.test(value), hardcoded("Username does not exist."));
        }

        @Override
        public String toString() {
            return toPublicString();
        }
    }

    private static final class Traits extends RegexStringTraits {
        private static final Pattern USERNAME =
                Pattern.compile("[A-Za-z]([A-Za-z0-9._-]*[A-Za-z0-9])?");

        @Override
        public Hardcoded descriptionInErrors() {
            return hardcoded("username");
        }

        @Override
        public Bounds rawBounds() {
            return new Bounds(1, 80);
        }

        @Override
        public String reformatString(String raw) {
            return raw.trim();
        }

        @Override
        public Pattern welcomeListRegex() {
            return USERNAME;
        }
    }

    @Override
    public String exposeUnchecked(ExposeHalfBakedValueIntendedForInternalLibraryUseOnlyMarker marker) {
        return exposeUnchecked(marker);
    }
}
