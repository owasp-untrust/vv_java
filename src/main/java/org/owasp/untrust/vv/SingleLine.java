package org.owasp.untrust.vv;

import com.fasterxml.jackson.annotation.JsonCreator;
import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.valuedescriptors.foundation.PubliclyExposed;
import org.owasp.untrust.vv.foundation.ValidatedWrappedValue;
import org.owasp.untrust.vv.traits.LineTextTraits;

public final class SingleLine extends ValidatedWrappedValue<String> implements PubliclyExposed<String> {
    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    public SingleLine(String raw) {
        super(raw, new Traits());
    }

    public static SingleLine from(String raw) {
        return new SingleLine(raw);
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
