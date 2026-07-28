package org.owasp.untrust.vv;

import java.util.UUID;

import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.foundation.ExposableValidatedWrappedValue;
import org.owasp.untrust.vv.traits.RareTraitsCaseWhereParsingIsTheWholeValidation;
import org.owasp.untrust.buildmetadata.NonFinalValidatedValue;
import org.owasp.untrust.buildmetadata.StringConcatenationSafe;
import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.valuedescriptors.foundation.PubliclyExposed;

import static org.owasp.untrust.valuedescriptors.Hardcoded.hardcoded;

@StringConcatenationSafe("UUIDs have a fixed format and length, so concatenation won't cause issues.")
@NonFinalValidatedValue("UUID-backed identifier types share the same complete UUID parsing and fixed-length validation policy; domain-specific identifiers only add type distinction and cannot weaken that parsing invariant.")
public abstract class ViewableUuidValue extends ExposableValidatedWrappedValue<UUID> implements PubliclyExposed<UUID> {
    protected ViewableUuidValue(String raw) throws ValidationException {
        super(raw, new Traits());
    }

    public static class Traits extends RareTraitsCaseWhereParsingIsTheWholeValidation<UUID> {
        @Override
        public Hardcoded descriptionInErrors() {
            return hardcoded("UUID");
        }

        @Override
        public UUID parse(String raw) throws IllegalArgumentException {
            return UUID.fromString(raw);
        }

        @Override
        public Bounds rawBounds() {
            // A UUID string has a fixed length of 36 characters (including hyphens)
            return new Bounds(36, 36);
        }

        @Override
        public UUID normalize(UUID parsed) throws ValidationException {
            return parsed;
        }
    }
}
