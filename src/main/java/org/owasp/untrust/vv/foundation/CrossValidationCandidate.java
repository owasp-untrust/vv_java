package org.owasp.untrust.vv.foundation;

import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;

import org.owasp.untrust.valuedescriptors.foundation.PubliclyRepresentable;
import org.owasp.untrust.valuedescriptors.Hardcoded;

public interface CrossValidationCandidate<T, ReceiverOfValidated extends CrossValidatedReceiver<T, ReceiverOfValidated>>
        extends HalfBakedExposable<T>, PubliclyRepresentable {
    //default <In> LinkT performLink(In in) {
    //}
    public static class FullyValidated<T, ReceiverOfValidated> {
        T m_validated; // package private

        private FullyValidated(T validated) {
            m_validated = validated;
        }
    }

    default <C> FullyValidated<T, ReceiverOfValidated> crossValidate(C context, BiFunction<T, C, Optional<String>> findCrossValidationError) throws IllegalArgumentException {
        T partiallyValidated = exposeUnchecked(EXPOSE_HALF_BAKED_VALUE_INTENDED_FOR_INTERNAL_LIBRARY_USE_ONLY_MARKER);
        Optional<String> crossValidationError = findCrossValidationError.apply(partiallyValidated, context);
        if (crossValidationError.isPresent()) {
            throw new IllegalArgumentException("Value does not satisfy cross-validation constraints.", new Exception(crossValidationError.get()));
        }
        return new FullyValidated<>(partiallyValidated);
    }

    default <C> FullyValidated<T, ReceiverOfValidated> crossValidate(Function<T, Optional<String>> findCrossValidationError) throws IllegalArgumentException {
        T partiallyValidated = exposeUnchecked(EXPOSE_HALF_BAKED_VALUE_INTENDED_FOR_INTERNAL_LIBRARY_USE_ONLY_MARKER);
        Optional<String> crossValidationError = findCrossValidationError.apply(partiallyValidated);
        if (crossValidationError.isPresent()) {
            throw new IllegalArgumentException("Value does not satisfy cross-validation constraints.", new Exception(crossValidationError.get()));
        }
        return new FullyValidated<>(partiallyValidated);
    }

    default <C> FullyValidated<T, ReceiverOfValidated> crossValidate(Predicate<T> isOk, Hardcoded errorDescription) throws IllegalArgumentException {
        T partiallyValidated = exposeUnchecked(EXPOSE_HALF_BAKED_VALUE_INTENDED_FOR_INTERNAL_LIBRARY_USE_ONLY_MARKER);
        if (isOk.test(partiallyValidated)) {
            return new FullyValidated<>(partiallyValidated);
        } else {
            throw new IllegalArgumentException("Value does not satisfy cross-validation constraints.", new Exception(errorDescription.value()));
        }
    }
}
