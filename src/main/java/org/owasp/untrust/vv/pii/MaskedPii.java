package org.owasp.untrust.vv.pii;

public interface MaskedPii<T> extends Pii<T> {
    default String toPublicString() {
        String value = exposeUnchecked().toString();
        if (value.length() <= 4) {
            if (value.isEmpty()) {
                return ""; // no problem exposing an empty value
            } else {
                /* STRING CONCAT IS SAFE HERE:
                 * This method is the narrow public renderer for masked PII values. The output context is plain diagnostic/display text, not HTML, SQL, JSON, a URL, or another structured format with an escaping-aware builder in this codebase. Raw concatenation is necessary only to preserve a small prefix/suffix while replacing the hidden portion with a fixed literal mask. User-controlled input is limited to characters copied from the already validated wrapped value, and the mask ensures the full sensitive value is never exposed. The exception is scoped to these two masking return statements.
                 */
                return value.charAt(0) + "***";
            }
        }
        else {
            return value.substring(0, 2) + "***" + value.substring(value.length() - 2);
        }
        /* END STRING CONCAT */
     }  
}
