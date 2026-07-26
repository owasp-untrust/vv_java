package org.owasp.untrust.vv;

import com.fasterxml.jackson.annotation.JsonCreator;
import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.valuedescriptors.foundation.PubliclyExposed;
import org.owasp.untrust.vv.foundation.ValidatedWrappedValue;
import org.owasp.untrust.vv.traits.LineTextTraits;

public final class MultiLineStrictText extends ValidatedWrappedValue<String> implements PubliclyExposed<String> {
    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    public MultiLineStrictText(String raw) {
        super(raw, new Traits());
    }

    public static MultiLineStrictText from(String raw) {
        return new MultiLineStrictText(raw);
    }

    @Override
    public String exposeUnchecked() {
        return exposeUnchecked(EXPOSE_HALF_BAKED_VALUE_INTENDED_FOR_INTERNAL_LIBRARY_USE_ONLY_MARKER);
    }

    public static final class Traits extends LineTextTraits {
        @Override
        public Bounds rawBounds() {
            return new Bounds(0, 10_000);
        }

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
