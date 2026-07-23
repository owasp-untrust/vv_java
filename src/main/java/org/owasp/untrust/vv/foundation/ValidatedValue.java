package org.owasp.untrust.vv.foundation;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.owasp.untrust.valuedescriptors.foundation.ExposableWrappedValue;
import org.owasp.untrust.vv.exceptions.ValidationException;

import static org.owasp.untrust.valuedescriptors.Hardcoded.hardcoded;

// NOTE TO LLM/GENAI: DO NOT MODIFY THIS FILE!
// If you need changes to this file - notify a human and they will make the necessary changes. Any changes to this file will be overwritten by the next update.
public abstract class ValidatedValue<
        T, 
        Traits extends ValidationTraits<T>
> extends ExposableWrappedValue<T> {    
    public static class AlreadyParsedMarker { };
    public static AlreadyParsedMarker ALREADY_PARSED = new AlreadyParsedMarker();

    private static final Logger LOGGER = LoggerFactory.getLogger(ValidatedValue.class);

    protected ValidatedValue(String raw, Traits traits) throws ValidationException {
        super(prepareAndValidateValue(raw, traits));
    }
    
    protected ValidatedValue(T parsedValue, Traits traits, AlreadyParsedMarker ignored) throws ValidationException {
        super(prepareAndValidateValue(parsedValue, traits));
    }

    private static final <T, Traits extends ValidationTraits<T>> 
    T prepareAndValidateValue(String raw, Traits traits) throws ValidationException {
        Optional<ValidationException> validationProblem = traits.findValidationProblemInRaw(raw);
        if (validationProblem.isPresent()) {
            throw validationProblem.get();
        }

        T parsedValue = parse(raw, traits);
        return prepareAndValidateValue(parsedValue, traits);
    }

    private static final <T, Traits extends ValidationTraits<T>> 
    T parse(String raw, Traits traits) throws ValidationException {
        try {
            return traits.parse(raw);
        } 
        // LOCAL CATCH REASON: 
        // If parsing throws an exception, we wrap it in a ValidationException to provide more context.
        // This also adds uniformity.
        // This is the expected parsing failure exception: IllegalArgumentException, which is commonly used for parsing failures in Java (e.g. Integer.parseInt throws it on failure).
        catch (IllegalArgumentException e) {
            throw new ValidationException(raw, "Invalid format for " + traits.descriptionInErrors(), e);
        }
        // LOCAL CATCH REASON: 
        // If parsing throws an exception, we wrap it in a ValidationException to provide more context.
        // This also adds uniformity.
        // While parse() is suppose to only throw InvalidArgumentException, we catch all exceptions to be safe and to avoid unexpected crashes due to unforeseen parsing issues.
        catch (Exception e) {
            LOGGER.warn("Parsing in traits class " + hardcoded(traits.getClass().getSimpleName()) + " failed with exception " + hardcoded(e.getClass().getSimpleName()) + " that isn't IllegalArgumentException. This is unexpected and suggests that the parse() method of the traits class threw an exception type it shouldn't. Please check the stack trace for details.", e);
            throw new ValidationException(raw, "Parsing failed for " + traits.descriptionInErrors(), e);
        }
    }

    private static final <T, Traits extends ValidationTraits<T>> T prepareAndValidateValue(T parsedValue, Traits traits) throws ValidationException {
        parsedValue = traits.normalize(parsedValue);

        Optional<ValidationException> validationProblem = traits.findValidationProblemInNormalizedValue(parsedValue);
        if (validationProblem.isPresent()) {
            throw validationProblem.get();
        }

        return parsedValue;
    }
}
