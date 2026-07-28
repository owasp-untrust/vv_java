package org.owasp.untrust.vv;

import java.util.Optional;

import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.traits.BoundedValueTraits;

import static org.owasp.untrust.valuedescriptors.Hardcoded.hardcoded;

public final class UploadContentType extends SingleLine {
    public UploadContentType(String raw) { super(raw, new Traits()); }

    private static final class Traits extends SingleLine.Traits {
        @Override public Hardcoded descriptionInErrors() { return hardcoded("upload content type"); }
        @Override public BoundedValueTraits.Bounds rawBounds() { return new BoundedValueTraits.Bounds(3, 255); }

        @Override protected Optional<ValidationException> findExtraValidationProblemInLineText(String normalized) {
            if (!normalized.matches("[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+")) {
                return Optional.of(new ValidationException(normalized, "Upload content type must be a media type without parameters.", Optional.empty()));
            }
            return Optional.empty();
        }
    }
}
