package org.owasp.untrust.vv.exceptions;

import org.owasp.untrust.vv.ViewableUuidValue;

public class EntityNotFoundException extends RuntimeException {
    public EntityNotFoundException(ViewableUuidValue entityId) {
        super("Entity with ID " + entityId + " not found.");
    }
}
