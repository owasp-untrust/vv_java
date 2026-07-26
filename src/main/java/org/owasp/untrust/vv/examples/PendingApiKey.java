package org.owasp.untrust.vv.examples;

import java.util.regex.Pattern;

import com.fasterxml.jackson.annotation.JsonCreator;
import org.owasp.untrust.vv.foundation.SelfValidating;
import org.owasp.untrust.vv.traits.RegexStringTraits;
import org.owasp.untrust.vv.visibility.secret.PendingSecret;
import org.owasp.untrust.vv.visibility.secret.SecretReference;
import org.owasp.untrust.vv.visibility.secret.SecretStore;
import org.owasp.untrust.valuedescriptors.Hardcoded;

import static org.owasp.untrust.valuedescriptors.Hardcoded.hardcoded;

public final class PendingApiKey
        implements PendingSecret<String, ApiKey>, SelfValidating<String> {

    private final String m_value;

    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    private PendingApiKey(String raw) {
        //super(raw, new Traits());
        this.m_value = validate(raw, new Traits());
    }

    public static PendingApiKey from(String raw) {
        return new PendingApiKey(raw);
    }

    // package private - needed by ApiKey for revalidation
    static final class Traits extends RegexStringTraits {
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
