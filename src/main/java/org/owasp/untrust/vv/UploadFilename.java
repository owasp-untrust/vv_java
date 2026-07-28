package org.owasp.untrust.vv;

import java.util.Optional;

import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.traits.BoundedValueTraits;

import static org.owasp.untrust.valuedescriptors.Hardcoded.hardcoded;

public final class UploadFilename extends SingleLine {
    public UploadFilename(String raw, int maximumLength) { super(raw, new Traits(maximumLength)); }

    private static final class Traits extends SingleLine.Traits {
        private final int maximumLength;

        private Traits(int maximumLength) {
            if (maximumLength < 1) throw new IllegalArgumentException("maximumLength must be positive.");
            this.maximumLength = maximumLength;
        }

        @Override public Hardcoded descriptionInErrors() { return hardcoded("upload filename"); }
        @Override public BoundedValueTraits.Bounds rawBounds() { return new BoundedValueTraits.Bounds(1, maximumLength); }

        @Override protected Optional<ValidationException> findExtraValidationProblemInLineText(String normalized) {
            if (normalized.indexOf('/') >= 0 || normalized.indexOf('\\') >= 0) {
                return Optional.of(new ValidationException(normalized, "Upload filenames must not contain path separators.", Optional.empty()));
            }
            return Optional.empty();
        }
    }
}
