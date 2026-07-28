package org.owasp.untrust.vv;

import java.util.Optional;

import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.traits.BoundedValueTraits;

import static org.owasp.untrust.valuedescriptors.Hardcoded.hardcoded;

public final class UploadPartName extends SingleLine {
    public UploadPartName(String raw) { super(raw, new Traits()); }

    private static final class Traits extends SingleLine.Traits {
        @Override public Hardcoded descriptionInErrors() { return hardcoded("upload part name"); }
        @Override public BoundedValueTraits.Bounds rawBounds() { return new BoundedValueTraits.Bounds(1, 255); }
        @Override protected Optional<ValidationException> findExtraValidationProblemInLineText(String normalized) { return Optional.empty(); }
    }
}
