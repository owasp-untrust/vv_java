package org.owasp.untrust.vv.examples;

import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonCreator;
import org.owasp.untrust.vv.ViewableUuidValue;

public final class TaskId extends ViewableUuidValue {
    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    public TaskId(String raw) {
        super(raw);
    }

    public static TaskId from(String raw) {
        return new TaskId(raw);
    }
}
