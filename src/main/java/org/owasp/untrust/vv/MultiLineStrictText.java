package org.owasp.untrust.vv;

import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.valuedescriptors.foundation.PubliclyExposed;
import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.foundation.ValidatedValue;
import org.owasp.untrust.vv.traits.LineTextTraits;

public final class MultiLineStrictText extends ValidatedValue<String, MultiLineStrictText.Traits> implements PubliclyExposed<String> {
    public MultiLineStrictText(String raw) throws ValidationException {
        super(raw, new Traits());
    }

    public static final class Traits extends LineTextTraits {
        @Override
        public boolean allowNewlines() {
            return true;
        }

        @Override
        public boolean allowEmoji() {
            return false;
        }

        @Override
        public boolean requirePathSafeText() {
            return false;
        }

        @Override
        public Hardcoded descriptionInErrors() {
            return lineTextDescription("multi-line", "strict text");
        }
    }
}
