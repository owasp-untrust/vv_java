package org.owasp.untrust.vv;

import java.util.UUID;

import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.foundation.ValidatedValue;
import org.owasp.untrust.vv.traits.RareTraitsCaseWhereParsingIsTheWholeValidation;
import org.owasp.untrust.buildmetadata.NonFinalValidatedValue;
import org.owasp.untrust.buildmetadata.StringConcatenationSafe;
import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.valuedescriptors.foundation.PubliclyViewable;

import static org.owasp.untrust.valuedescriptors.Hardcoded.hardcoded;

// VALIDATED VALUE INHERITANCE REASON:
// All validated values that have a uuid type (basically all id types) can use
// a common ancestor since they all validate only to the extent of parsing -
// there should (normally) be no limitation on uuid range when used as an id.
@StringConcatenationSafe("UUIDs have a fixed format and length, so concatenation won't cause issues.")
@NonFinalValidatedValue("All validated values that have a uuid type (basically all id types) can use a common ancestor since they all validate only to the extent of parsing - there should (normally) be no limitation on uuid range when used as an id.")
public class ViewableUuidValue extends ValidatedValue<UUID, ViewableUuidValue.Traits> implements PubliclyViewable<UUID> {
    public ViewableUuidValue(String raw) throws ValidationException {
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
        public Bounds<Integer> rawBounds() {
            // A UUID string has a fixed length of 36 characters (including hyphens)
            return new Bounds<>(36, 36);
        }

        @Override
        public UUID normalize(UUID parsed) throws ValidationException {
            return parsed;
        }
    }
}
