package org.owasp.untrust.vv;

import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.valuedescriptors.foundation.PubliclyViewable;
import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.foundation.ValidatedValue;
import org.owasp.untrust.vv.traits.LineTextTraits;

public final class MultiLine extends ValidatedValue<String, MultiLine.Traits> implements PubliclyViewable<String> {
    public MultiLine(String raw) throws ValidationException {
        super(raw, new Traits());
    }

    public static final class Traits extends LineTextTraits {
        @Override
        public boolean allowNewlines() {
            return true;
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
            return lineTextDescription("multi-line", "text with emoji");
        }
    }
}
