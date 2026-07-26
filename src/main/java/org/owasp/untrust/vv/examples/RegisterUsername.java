package org.owasp.untrust.vv.examples;

import java.util.function.Predicate;

import com.fasterxml.jackson.annotation.JsonCreator;
import org.owasp.untrust.vv.foundation.CrossValidationCandidate.FullyValidated;

public class RegisterUsername extends UsernameBase<RegisterUsername> {
    private RegisterUsername(FullyValidated<String, RegisterUsername> opaqueValue) {
        super(opaqueValue);
    }

    public static final class Candidate extends CandidateBase<RegisterUsername> {
        @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
        public Candidate(String raw) {
            super(raw);
        }

        public static Candidate from(String raw) {
            return new Candidate(raw);
        }

        public FullyValidated<String, RegisterUsername> crossValidate(Predicate<String> exists) {
            return crossValidateDoesNotExist(exists);
        }
    }
}
