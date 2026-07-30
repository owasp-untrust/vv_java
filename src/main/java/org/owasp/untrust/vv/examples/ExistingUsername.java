package org.owasp.untrust.vv.examples;

import java.util.function.Predicate;

import com.fasterxml.jackson.annotation.JsonCreator;
import org.owasp.untrust.vv.foundation.CrossValidationCandidate.FullyValidated;

public class ExistingUsername extends UsernameBase<ExistingUsername> {
    private ExistingUsername(FullyValidated<String, ExistingUsername> opaqueValue) {
        super(opaqueValue);
    }

    public static final class Candidate extends CandidateBase<ExistingUsername> {
        @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
        public Candidate(String raw) {
            super(raw);
        }

        public static Candidate from(String raw) {
            return new Candidate(raw);
        }

        public ExistingUsername crossValidate(Predicate<String> exists) {
            return new ExistingUsername(crossValidateExists(exists));
        }
    }
}
