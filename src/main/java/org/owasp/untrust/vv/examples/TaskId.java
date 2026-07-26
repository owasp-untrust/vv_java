package org.owasp.untrust.vv.examples;

import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonCreator;
import org.owasp.untrust.valuedescriptors.foundation.ExposableValue;
import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.vv.foundation.SelfValidating;
import org.owasp.untrust.vv.foundation.ValidatedWrappedValue;
import org.owasp.untrust.vv.traits.RareTraitsCaseWhereParsingIsTheWholeValidation;

import static org.owasp.untrust.valuedescriptors.Hardcoded.hardcoded;

public final class TaskId extends ValidatedWrappedValue<UUID> 
        implements SelfValidating<UUID>, ExposableValue<UUID> {
    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    public TaskId(String raw) {
        super(raw, new Traits());
    }

    public static TaskId from(String raw) {
        return new TaskId(raw);
    }

    @Override
    public UUID exposeUnchecked() {
        return exposeUnchecked(EXPOSE_HALF_BAKED_VALUE_INTENDED_FOR_INTERNAL_LIBRARY_USE_ONLY_MARKER);
    }

    private static final class Traits
            extends RareTraitsCaseWhereParsingIsTheWholeValidation<UUID> {
        @Override
        public Hardcoded descriptionInErrors() {
            return hardcoded("task id");
        }

        @Override
        public Bounds rawBounds() {
            return new Bounds(36, 36);
        }

        @Override
        public UUID parse(String raw) {
            return UUID.fromString(raw.trim());
        }

        @Override
        public UUID normalize(UUID parsed) {
            return parsed;
        }
    }
}
