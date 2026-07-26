package org.owasp.untrust.vv;

import com.fasterxml.jackson.annotation.JsonCreator;
import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.valuedescriptors.foundation.PubliclyExposed;
import org.owasp.untrust.vv.foundation.ValidatedWrappedValue;
import org.owasp.untrust.vv.traits.LineTextTraits;

public final class SingleLineStrictText extends ValidatedWrappedValue<String> implements PubliclyExposed<String> {
    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    public SingleLineStrictText(String raw) {
        super(raw, new Traits());
    }

    public static SingleLineStrictText from(String raw) {
        return new SingleLineStrictText(raw);
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
