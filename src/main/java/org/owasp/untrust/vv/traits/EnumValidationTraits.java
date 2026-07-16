package org.owasp.untrust.vv.traits;

import java.util.Optional;
import java.util.stream.Stream;

import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.foundation.ValidationTraits;
import org.owasp.untrust.valuedescriptors.Hardcoded;

public class EnumValidationTraits<E extends Enum<E>> implements ValidationTraits<E> {
    private final Class<E> m_enumClass;
    private final Hardcoded m_desc;
    private final int m_maxEnumLength;

    public EnumValidationTraits(Class<E> enumClass, Hardcoded desc) {
        m_enumClass = enumClass;
        m_desc = desc;
        m_maxEnumLength = Stream.of(enumClass.getEnumConstants())
                .map(e -> e.toString().length())
                .max(Integer::compareTo)
                .orElse(0);
    }

    @Override
    public Hardcoded descriptionInErrors() {
        return m_desc;
    }

    @Override
    public E parse(String raw) throws ValidationException {
        for (E type : m_enumClass.getEnumConstants()) {
            if (type.toString().equalsIgnoreCase(raw)) {
                return type;
            }
        }

        throw new IllegalArgumentException("Unsupported " + m_desc + ".");
    }    

    @Override
    public E normalize(E parsed) {
        return parsed;
    }

    @Override
    public Optional<ValidationException> findValidationProblemInRaw(String raw) {
        if (raw.length() == 0) {
            return Optional.of(new ValidationException(raw, "Cannot have an empty " + m_desc, Optional.empty()));
        }
        if (raw.length() > m_maxEnumLength) {
            return Optional.of(new ValidationException(raw, "Length is too long to be a valid " + m_desc, Optional.empty()));
        }
        return Optional.empty();
    }

    @Override
    public Optional<ValidationException> findValidationProblemInNormalizedValue(E normalized) {
        return Optional.empty();
    }
}
