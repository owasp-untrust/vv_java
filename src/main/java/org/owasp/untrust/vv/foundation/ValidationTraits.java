package org.owasp.untrust.vv.foundation;

import java.util.Optional;

import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.vv.exceptions.ValidationException;

public interface ValidationTraits<T> {
    Hardcoded descriptionInErrors();

    Optional<ValidationException> findValidationProblemInRaw(String raw);

    T parse(String raw);

    T normalize(T parsed);

    Optional<ValidationException> findValidationProblemInNormalizedValue(T normalized);
}
