package org.owasp.untrust.vv.pii;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

public class PiiConcat implements CharSequence, Appendable {
    private static final class PiiLocation {
        private int offset;
        private final int length;
        private final String altId;

        private PiiLocation(int offset, int length, String altId) {
            this.offset = offset;
            this.length = length;
            this.altId = altId;
        }

        private int offset() {
            return offset;
        }

        private int length() {
            return length;
        }

        private String altId() {
            return altId;
        }

        private void push(int howMuch) {
            offset += howMuch;
        }
    }

    private final StringBuilder stringBuilder = new StringBuilder();
    private final List<PiiLocation> piiLocations = new ArrayList<>();
    private final Function<String, String> elementTransform;

    public PiiConcat() {
        this((Function<String, String>) null);
    }

    public PiiConcat(int capacity) {
        this.stringBuilder.ensureCapacity(capacity);
        this.elementTransform = null;
    }

    public PiiConcat(String str) {
        this();
        append(str);
    }

    public PiiConcat(CharSequence seq) {
        this();
        append(seq);
    }

    public PiiConcat(Function<String, String> elementTransform) {
        this.elementTransform = elementTransform;
    }

    public PiiConcat(Function<String, String> elementTransform, int capacity) {
        this.elementTransform = elementTransform;
        this.stringBuilder.ensureCapacity(capacity);
    }

    public PiiConcat(Function<String, String> elementTransform, String str) {
        this(elementTransform);
        append(str);
    }

    public PiiConcat append(Object obj) {
        return append(String.valueOf(obj));
    }

    @Override
    public PiiConcat append(CharSequence seq) {
        return append(String.valueOf(seq));
    }

    @Override
    public PiiConcat append(CharSequence seq, int start, int end) {
        return append(String.valueOf(seq).subSequence(start, end));
    }

    public PiiConcat append(String nonclassifiedString) {
        stringBuilder.append(transform(nonclassifiedString));
        return this;
    }

    public PiiConcat append(StringBuffer sb) {
        return append(String.valueOf(sb));
    }

    public PiiConcat append(char[] str) {
        return append(String.valueOf(str));
    }

    public PiiConcat append(char[] str, int offset, int len) {
        return append(String.valueOf(str, offset, len));
    }

    public PiiConcat append(boolean b) {
        return append(String.valueOf(b));
    }

    @Override
    public PiiConcat append(char c) {
        return append(String.valueOf(c));
    }

    public PiiConcat append(int i) {
        return append(String.valueOf(i));
    }

    public PiiConcat append(long lng) {
        return append(String.valueOf(lng));
    }

    public PiiConcat append(float f) {
        return append(String.valueOf(f));
    }

    public PiiConcat append(double d) {
        return append(String.valueOf(d));
    }

    public PiiConcat appendCodePoint(int codePoint) {
        return append(new String(Character.toChars(codePoint)));
    }

    public PiiConcat pushPrefix(String prefix) {
        String transformedPrefix = transform(prefix);

        for (PiiLocation location : piiLocations) {
            location.push(transformedPrefix.length());
        }

        stringBuilder.insert(0, transformedPrefix);
        return this;
    }

    public <TValue> PiiConcat append(Pii<TValue> pii) {
        return appendPii(pii, pii.toString());
    }

    public String exposeUnchecked() {
        return stringBuilder.toString();
    }

    @Override
    public int length() {
        return stringBuilder.length();
    }

    public int capacity() {
        return stringBuilder.capacity();
    }

    public void ensureCapacity(int minimumCapacity) {
        stringBuilder.ensureCapacity(minimumCapacity);
    }

    public void trimToSize() {
        stringBuilder.trimToSize();
    }

    @Override
    public char charAt(int index) {
        return stringBuilder.charAt(index);
    }

    public int codePointAt(int index) {
        return stringBuilder.codePointAt(index);
    }

    public int codePointBefore(int index) {
        return stringBuilder.codePointBefore(index);
    }

    public int codePointCount(int beginIndex, int endIndex) {
        return stringBuilder.codePointCount(beginIndex, endIndex);
    }

    public int offsetByCodePoints(int index, int codePointOffset) {
        return stringBuilder.offsetByCodePoints(index, codePointOffset);
    }

    public void getChars(int srcBegin, int srcEnd, char[] dst, int dstBegin) {
        stringBuilder.getChars(srcBegin, srcEnd, dst, dstBegin);
    }

    public String substring(int start) {
        return stringBuilder.substring(start);
    }

    public String substring(int start, int end) {
        return stringBuilder.substring(start, end);
    }

    @Override
    public CharSequence subSequence(int start, int end) {
        return stringBuilder.subSequence(start, end);
    }

    public int indexOf(String str) {
        return stringBuilder.indexOf(str);
    }

    public int indexOf(String str, int fromIndex) {
        return stringBuilder.indexOf(str, fromIndex);
    }

    public int lastIndexOf(String str) {
        return stringBuilder.lastIndexOf(str);
    }

    public int lastIndexOf(String str, int fromIndex) {
        return stringBuilder.lastIndexOf(str, fromIndex);
    }

    @Override
    public String toString() {
        StringBuilder loggableString = new StringBuilder();
        int copyPosition = 0;

        for (PiiLocation piiLocation : piiLocations) {
            int nonPiiLength = piiLocation.offset() - copyPosition;
            loggableString.append(stringBuilder, copyPosition, copyPosition + nonPiiLength);
            loggableString.append(piiLocation.altId());
            copyPosition = piiLocation.offset() + piiLocation.length();
        }

        loggableString.append(stringBuilder, copyPosition, stringBuilder.length());
        return loggableString.toString();
    }

    private <TValue> PiiConcat appendPii(Pii<TValue> pii, String altId) {
        int offset = stringBuilder.length();
        stringBuilder.append(transform(String.valueOf(pii.exposeUnchecked())));
        int length = stringBuilder.length() - offset;
        piiLocations.add(new PiiLocation(offset, length, altId));
        return this;
    }

    private String transform(String value) {
        if (elementTransform == null) {
            return value;
        }

        return elementTransform.apply(value);
    }
}
