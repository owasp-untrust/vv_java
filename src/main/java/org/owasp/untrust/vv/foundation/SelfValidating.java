package org.owasp.untrust.vv.foundation;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.owasp.untrust.buildmetadata.StringConcatenationSafe;
import org.owasp.untrust.vv.exceptions.ValidationException;
import static org.owasp.untrust.valuedescriptors.Hardcoded.hardcoded;

@StringConcatenationSafe("Validation error messages in this interface are assembled only from developer-authored message fragments and Hardcoded descriptors supplied by traits. The raw user value is passed separately to ValidationException, not spliced into the message text.")
public interface SelfValidating<T> {
    //public static class AlreadyParsedMarker { };
    //static AlreadyParsedMarker ALREADY_PARSED = new AlreadyParsedMarker();
    public static final Logger LOGGER = LoggerFactory.getLogger(SelfValidating.class);

    default <V extends ValidationTraits<T>> T validate(
            String raw,
            V traits
    ) {
        return prepareAndValidateValue(raw, traits);
    }

    default <V extends ValidationTraits<T>> T validateParsed(
            T unvalidated,
            V traits
    ) {
        return prepareAndValidateValue(unvalidated, traits);
    }

    private static <T, Traits extends ValidationTraits<T>> 
    T prepareAndValidateValue(String raw, Traits traits) throws ValidationException {
        Optional<ValidationException> validationProblem = traits.findValidationProblemInRaw(raw);
        if (validationProblem.isPresent()) {
            throw validationProblem.get();
        }

        T parsedValue = parse(raw, traits);
        return prepareAndValidateValue(parsedValue, traits);
    }

    private static <T, Traits extends ValidationTraits<T>> 
    T parse(String raw, Traits traits) throws ValidationException {
        try {
            return traits.parse(raw);
        } 
        // LOCAL CATCH REASON: 
        // If parsing throws an exception, we wrap it in a ValidationException to provide more context.
        // This also adds uniformity.
        // This is the expected parsing failure exception: IllegalArgumentException, which is commonly used for parsing failures in Java (e.g. Integer.parseInt throws it on failure).
        catch (IllegalArgumentException e) {
            throw new ValidationException(
                    raw,
                    hardcoded("Invalid format for ").concat(traits.descriptionInErrors()).value(),
                    e);
        }
        // LOCAL CATCH REASON: 
        // If parsing throws an exception, we wrap it in a ValidationException to provide more context.
        // This also adds uniformity.
        // While parse() is suppose to only throw InvalidArgumentException, we catch all exceptions to be safe and to avoid unexpected crashes due to unforeseen parsing issues.
        catch (Exception e) {
            LOGGER.warn(
                    "Parsing in traits class {} failed with exception {} that is not IllegalArgumentException. This is unexpected and suggests that the parse() method of the traits class threw an exception type it should not. Please check the stack trace for details.",
                    hardcoded(traits.getClass().getSimpleName()),
                    hardcoded(e.getClass().getSimpleName()),
                    e);
            throw new ValidationException(
                    raw,
                    hardcoded("Parsing failed for ").concat(traits.descriptionInErrors()).value(),
                    e);
        }
    }

    private static <T, Traits extends ValidationTraits<T>> T prepareAndValidateValue(T parsedValue, Traits traits) throws ValidationException {
        parsedValue = traits.normalize(parsedValue);

        Optional<ValidationException> validationProblem = traits.findValidationProblemInNormalizedValue(parsedValue);
        if (validationProblem.isPresent()) {
            throw validationProblem.get();
        }

        return parsedValue;
    }
}
