package org.owasp.untrust.vv.exceptions;

import org.owasp.untrust.vv.ViewableUuidValue;

public class EntityAccessForbiddenException extends RuntimeException {
    public EntityAccessForbiddenException(ViewableUuidValue entityId) {
        super("Access to entity with ID " + entityId + " is forbidden.");
    }
}
