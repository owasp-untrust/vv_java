package org.owasp.untrust.vv.prebuilt;

import java.util.regex.Pattern;

import com.fasterxml.jackson.annotation.JsonCreator;
import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.vv.foundation.SelfValidating;
import org.owasp.untrust.vv.traits.RegexStringTraits;
import org.owasp.untrust.vv.visibility.secret.PendingSecret;

import static org.owasp.untrust.valuedescriptors.Hardcoded.hardcoded;

public class PendingApiKey
        implements PendingSecret<String, ApiKey>, SelfValidating<String> {
    private static final int DISPLAY_SUFFIX_LENGTH = 4;

    private final String m_value;

    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    protected PendingApiKey(String raw) {
        this.m_value = validate(raw, new Traits());
    }

    public static PendingApiKey from(String raw) {
        return new PendingApiKey(raw);
    }

    public String displayValue() {
        /* STRING CONCAT IS SAFE HERE: This display value intentionally combines only the fixed redaction marker with the final four characters selected by suffix(). The raw API key is never included, no user-controlled delimiter or structure is assembled, and callers need this stable masked form for configuration status displays without exposing the secret. */
        return "****" + suffix();
        /* END STRING CONCAT */
    }

    public String suffix() {
        int start = Math.max(0, m_value.length() - DISPLAY_SUFFIX_LENGTH);
        return m_value.substring(start);
    }

    public static class Traits extends RegexStringTraits {
        private static final Pattern API_KEY =
                Pattern.compile("[A-Za-z0-9_\\-]{20,512}");

        @Override
        public Hardcoded descriptionInErrors() {
            return hardcoded("AI API key");
        }

        @Override
        public Bounds rawBounds() {
            return new Bounds(20, 512);
        }

        @Override
        public Pattern welcomeListRegex() {
            return API_KEY;
        }
    }

    @Override
    public String exposeUnchecked(ExposeHalfBakedValueIntendedForInternalLibraryUseOnlyMarker marker) {
        return m_value;
    }
}
