package org.owasp.untrust.vv;

import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.buildmetadata.NonFinalValidatedValue;
import org.owasp.untrust.valuedescriptors.foundation.PubliclyExposed;
import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.foundation.ExposableValidatedWrappedValue;
import org.owasp.untrust.vv.traits.LineTextTraits;
import java.util.Optional;

@NonFinalValidatedValue("This shared base centralizes single-line normalization and newline rejection while each domain value supplies its own bounded Traits implementation and allow-list validation policy.")
public abstract class SingleLine extends ExposableValidatedWrappedValue<String>
        implements PubliclyExposed<String> {
    protected <T extends Traits> SingleLine(String raw, T traits) {
        super(raw, traits);
    }

    public abstract static class Traits extends LineTextTraits {
        @Override
        public boolean allowNewlines() {
            return false;
        }

        @Override
        public boolean allowEmoji() {
            return true;
        }

        @Override
        public boolean requirePathSafeText() {
            return false;
        }

        @Override
        public Hardcoded descriptionInErrors() {
            return lineTextDescription("single-line", "text with emoji");
        }
    }
}
