package org.owasp.untrust.vv.foundation;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.valuedescriptors.Hardcoded;

public interface ValidationTraits<T> {
    Hardcoded descriptionInErrors();
    // Parses legally formatted values.
    // Prefer format validation via parsing to explicit checks in one of the findValidationProblemXxx methods.
    T parse(String raw) throws IllegalArgumentException;
    T normalize(T parsed) throws ValidationException;

    // Called BEFORE parsing.
    // Should not contain validation that ensures parsing passes - the parser knows best!
    // i.e. if the parser is int.parseInt, then this method should not test that the string contains digits only.
    // in same vain - if the integer value is suppose to be positive - do not check that the string has no '-' prefix:
    // range tests are the purview of findValidationProblemInNormalizedValue() (post parsing and normalization)
    Optional<ValidationException> findValidationProblemInRaw(String raw);
    Optional<ValidationException> findValidationProblemInNormalizedValue(T normalized);

    /*protected static class ValidationChainingEnforcer
    {
        private ValidationChainingEnforcer() { }
        public void invalidate(ValidationException error) throws ValidationException{ throw error; }
    }*/
    //protected ValidationChainingEnforcer rawChainableValidation(String raw) { return new ValidationChainingEnforcer(); }
    //protected ValidationChainingEnforcer normalizedValueChainableValidation(T value) { return new ValidationChainingEnforcer(); }
}
