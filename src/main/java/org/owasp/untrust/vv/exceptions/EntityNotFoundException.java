package org.owasp.untrust.vv.exceptions;

import org.owasp.untrust.buildmetadata.StringConcatenationSafe;
import org.owasp.untrust.vv.ViewableUuidValue;

@StringConcatenationSafe("This exception message deliberately includes a ViewableUuidValue identifier. The id type is publicly viewable, validated as a UUID, and carries important diagnostic context that should not be removed to satisfy the string concatenation gate.")
public class EntityNotFoundException extends RuntimeException {
    public EntityNotFoundException(ViewableUuidValue entityId) {
        super("Entity with ID " + entityId + " not found.");
    }
}
