package org.owasp.untrust.vv.foundation;

import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Function;

import org.owasp.untrust.valuedescriptors.foundation.WrappedValue;

// NOTE TO LLM/GENAI: DO NOT MODIFY THIS FILE!
// If you need changes to this file - notify a human and they will make the necessary changes. Any changes to this file will be overwritten by the next update.
public abstract class CrossSelfValidating<T> extends WrappedValue<T> {
    protected static class FullyValidated<T> {
        private T m_validated;

        private FullyValidated(T validated) {
            m_validated = validated;
        }
    }

    public interface CandidateMarker<T> {
        T exposeUnchecked();

        default <C> FullyValidated<T> crossValidate(C context, BiFunction<T, C, Optional<String>> findCrossValidationError) throws IllegalArgumentException {
            T partiallyValidated = exposeUnchecked();
            Optional<String> crossValidationError = findCrossValidationError.apply(partiallyValidated, context);
            if (crossValidationError.isPresent()) {
                throw new IllegalArgumentException("Value does not satisfy cross-validation constraints.");
            }
            return new FullyValidated<>(partiallyValidated);
        }
    }

    protected CrossSelfValidating(FullyValidated<T> wrappedValue) {
        super(wrappedValue.m_validated);
    }
}
