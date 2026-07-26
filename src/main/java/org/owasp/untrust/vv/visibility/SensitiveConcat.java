package org.owasp.untrust.vv.visibility;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import org.owasp.untrust.valuedescriptors.foundation.ExposableValue;
import org.owasp.untrust.valuedescriptors.foundation.PubliclyRepresentable;

public class SensitiveConcat implements CharSequence, Appendable, ExposableValue<String>, PubliclyRepresentable {
    private final List<String> exposedParts = new ArrayList<>();
    private final List<String> publicParts = new ArrayList<>();
    private final Optional<Function<String, String>> elementTransform;

    public SensitiveConcat() {
        this.elementTransform = Optional.empty();
    }

    public SensitiveConcat(int capacity) {
        this();
    }

    public SensitiveConcat(String str) {
        this();
        append(str);
    }

    public SensitiveConcat(CharSequence seq) {
        this();
        append(seq);
    }

    public SensitiveConcat(Function<String, String> elementTransform) {
        this.elementTransform = Optional.of(elementTransform);
    }

    public SensitiveConcat(Function<String, String> elementTransform, int capacity) {
        this.elementTransform = Optional.of(elementTransform);
    }

    public SensitiveConcat(Function<String, String> elementTransform, String str) {
        this(elementTransform);
        append(str);
    }

    public SensitiveConcat append(Object obj) {
        if (obj instanceof PubliclyRepresentable publiclyRepresentable) {
            return append(publiclyRepresentable);
        }

        return append(String.valueOf(obj));
    }

    public SensitiveConcat append(PubliclyRepresentable value) {
        String publicValue = value.toPublicString();
        publicParts.add(transform(publicValue));

        if (value instanceof ExposableValue<?> exposableValue) {
            exposedParts.add(transform(String.valueOf(exposableValue.exposeUnchecked())));
        } else {
            exposedParts.add(transform(publicValue));
        }

        return this;
    }

    @Override
    public SensitiveConcat append(CharSequence seq) {
        return append(String.valueOf(seq));
    }

    @Override
    public SensitiveConcat append(CharSequence seq, int start, int end) {
        return append(String.valueOf(seq).subSequence(start, end));
    }

    public SensitiveConcat append(String value) {
        String transformed = transform(value);
        exposedParts.add(transformed);
        publicParts.add(transformed);
        return this;
    }

    @Override
    public SensitiveConcat append(char c) {
        return append(String.valueOf(c));
    }

    public SensitiveConcat appendCodePoint(int codePoint) {
        return append(new String(Character.toChars(codePoint)));
    }

    public SensitiveConcat pushPrefix(String prefix) {
        String transformedPrefix = transform(prefix);
        exposedParts.add(0, transformedPrefix);
        publicParts.add(0, transformedPrefix);
        return this;
    }

    @Override
    public String exposeUnchecked() {
        return combine(exposedParts);
    }

    @Override
    public String toPublicString() {
        return combine(publicParts);
    }

    @Override
    public String toString() {
        return toPublicString();
    }

    @Override
    public int length() {
        return exposeUnchecked().length();
    }

    @Override
    public char charAt(int index) {
        return exposeUnchecked().charAt(index);
    }

    @Override
    public CharSequence subSequence(int start, int end) {
        return exposeUnchecked().subSequence(start, end);
    }

    private String transform(String value) {
        return elementTransform.map(transform -> transform.apply(value)).orElse(value);
    }

    private static String combine(List<String> parts) {
        int length = 0;
        for (String part : parts) {
            length += part.length();
        }

        char[] combined = new char[length];
        int offset = 0;
        for (String part : parts) {
            part.getChars(0, part.length(), combined, offset);
            offset += part.length();
        }
        return String.valueOf(combined);
    }
}
