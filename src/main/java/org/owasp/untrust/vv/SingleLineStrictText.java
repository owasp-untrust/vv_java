package org.owasp.untrust.vv;

import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.valuedescriptors.foundation.PubliclyViewable;
import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.foundation.ValidatedValue;
import org.owasp.untrust.vv.traits.LineTextTraits;

public final class SingleLineStrictText extends ValidatedValue<String, SingleLineStrictText.Traits> implements PubliclyViewable<String> {
    public SingleLineStrictText(String raw) throws ValidationException {
        super(raw, new Traits());
    }

    public static final class Traits extends LineTextTraits {
        @Override
        public boolean allowNewlines() {
            return false;
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
            return lineTextDescription("single-line", "strict text");
        }
    }
}
