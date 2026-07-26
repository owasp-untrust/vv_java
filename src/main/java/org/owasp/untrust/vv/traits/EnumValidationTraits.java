package org.owasp.untrust.vv.traits;

import java.util.Optional;
import java.util.stream.Stream;

import org.owasp.untrust.buildmetadata.StringConcatenationSafe;
import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.foundation.ValidationTraits;

import static org.owasp.untrust.valuedescriptors.Hardcoded.hardcoded;

@StringConcatenationSafe("Enum validation messages are assembled from developer-authored Hardcoded descriptions and fixed rule text. User input is parsed against enum constants and is not embedded into these messages through concatenation.")
public class EnumValidationTraits<E extends Enum<E>> implements ValidationTraits<E> {
    private final Class<E> enumClass;
    private final Hardcoded description;
    private final int maxEnumLength;

    public EnumValidationTraits(Class<E> enumClass, Hardcoded description) {
        this.enumClass = enumClass;
        this.description = description;
        this.maxEnumLength = Stream.of(enumClass.getEnumConstants())
                .map(value -> value.toString().length())
                .max(Integer::compareTo)
                .orElse(0);
    }

    @Override
    public Hardcoded descriptionInErrors() {
        return description;
    }

    @Override
    public Optional<ValidationException> findValidationProblemInRaw(String raw) {
        if (raw.isEmpty()) {
            return Optional.of(new ValidationException(raw, hardcoded("Cannot have an empty ").concat(description).value(), Optional.empty()));
        }

        if (raw.length() > maxEnumLength) {
            return Optional.of(new ValidationException(raw, hardcoded("Length is too long to be a valid ").concat(description).value(), Optional.empty()));
        }

        return Optional.empty();
    }

    @Override
    public E parse(String raw) {
        for (E value : enumClass.getEnumConstants()) {
            if (value.toString().equalsIgnoreCase(raw.trim())) {
                return value;
            }
        }

        throw new IllegalArgumentException(hardcoded("Unsupported ").concat(description).concat(hardcoded(".")).value());
    }

    @Override
    public E normalize(E parsed) {
        return parsed;
    }

    @Override
    public Optional<ValidationException> findValidationProblemInNormalizedValue(E normalized) {
        return Optional.empty();
    }
}
