package org.owasp.untrust.vv.exceptions;

import java.util.List;
import java.util.Optional;

public class ValidationException extends IllegalArgumentException {
    private final Optional<String> m_rawValue;
    private final Optional<?> m_parsedValue;
    private final List<String> m_validationErrors;
    private final Optional<Object> m_additionalValue;

    public ValidationException(String rawValue, String validationErrorDesc, Object additionalValue) {
        this(Optional.of(rawValue), Optional.empty(), List.of(validationErrorDesc), Optional.of(additionalValue));
    }

    public ValidationException(Object parsedValue, String validationErrorDesc, Object additionalValue) {
        this(Optional.empty(), Optional.of(parsedValue), List.of(validationErrorDesc), Optional.of(additionalValue));
    }

    public ValidationException(Optional<String> rawValue, Optional<?> parsedValue, List<String> validationErrors, Optional<Object> additionalValue) {
        super("Validation failed.");
        m_rawValue = rawValue;
        m_parsedValue = parsedValue;
        m_validationErrors = List.copyOf(validationErrors);
        m_additionalValue = additionalValue;
    }

    public Optional<String> rawValue() {
        return m_rawValue;
    }

    public Optional<?> parsedValue() {
        return m_parsedValue;
    }

    public List<String> validationErrors() {
        return m_validationErrors;
    }
}
