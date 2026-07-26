package org.owasp.untrust.vv.visibility;

public interface MiddleMaskedValue extends MaskedValue<String> {
    @Override
    default String mask(String value) {
        if (value.length() < 2) {
            return "aa****aa";
        }

        int hiddenLength = Math.max(4, value.length() - 4);
        char[] masked = new char[4 + hiddenLength];
        value.getChars(0, 2, masked, 0);
        for (int i = 2; i < 2 + hiddenLength; i++) {
            masked[i] = '*';
        }
        value.getChars(value.length() - 2, value.length(), masked, 2 + hiddenLength);
        return String.valueOf(masked);
    }
}
