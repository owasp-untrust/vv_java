package org.owasp.untrust.vv.prebuilt;

import java.net.URI;
import java.util.Locale;
import java.util.Optional;

import org.owasp.untrust.buildmetadata.NonFinalValidatedValue;
import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.foundation.CrossValidatedReceiver;
import org.owasp.untrust.vv.foundation.CrossValidationCandidate;
import org.owasp.untrust.vv.foundation.CrossValidationCandidate.FullyValidated;
import org.owasp.untrust.vv.foundation.ValidatedWrappedValue;
import org.owasp.untrust.vv.traits.BoundedValueTraits;

import static org.owasp.untrust.valuedescriptors.Hardcoded.hardcoded;

/** An HTTP(S) URL pinned to externally validated DNS addresses while retaining its original host for HTTP and TLS. */
@NonFinalValidatedValue("ExternalUrl is a reusable cross-validated value whose subclasses may add URL policy while retaining the required HTTP(S) syntax validation and external-host resolution step.")
public class ExternalUrl extends CrossValidatedReceiver<URI, ExternalUrl> {
    private final ExternalHost externalHost;

    protected ExternalUrl(FullyValidated<URI, ExternalUrl> validated, ExternalHost externalHost) {
        super(validated);
        this.externalHost = externalHost;
    }

    public URI originalUri() {
        return exposeUnchecked();
    }

    public ExternalHost externalHost() {
        return externalHost;
    }

    @Override
    public String toPublicString() {
        return "[external URL]";
    }

    public static final class Candidate extends ValidatedWrappedValue<URI>
            implements CrossValidationCandidate<URI, ExternalUrl> {
        protected Candidate(String raw) {
            super(raw, new Traits());
        }

        public static Candidate from(String raw) {
            return new Candidate(raw);
        }

        public ExternalUrl crossValidate() {
            URI uri = exposeUnchecked(EXPOSE_HALF_BAKED_VALUE_INTENDED_FOR_INTERNAL_LIBRARY_USE_ONLY_MARKER);
            ExternalHost externalHost = ExternalHost.Candidate.from(uri.getHost()).crossValidate();
            FullyValidated<URI, ExternalUrl> validated = crossValidate(value -> Optional.empty());
            return new ExternalUrl(validated, externalHost);
        }

        @Override
        public String toPublicString() {
            return "[external URL candidate]";
        }
    }

    private static final class Traits extends BoundedValueTraits<URI> {
        @Override
        public Hardcoded descriptionInErrors() {
            return hardcoded("http or https URL");
        }

        @Override
        public Optional<ValidationException> findValidationProblemInRaw(String raw) {
            // ALLOW NULL LITERAL: This public candidate accepts route and configuration input where a missing value may still be represented by null. Reject it before URI parsing exposes legacy parser behavior to callers.
            if (raw == null || raw.isBlank()) {
                return Optional.of(new ValidationException(raw, "URL must not be blank.", "http or https URL"));
            }
            return super.findValidationProblemInRaw(raw);
        }

        @Override
        public Bounds rawBounds() {
            return new Bounds(1, 8_192);
        }

        @Override
        public URI parse(String raw) {
            return URI.create(raw);
        }

        @Override
        public URI normalize(URI parsed) {
            return parsed.normalize();
        }

        @Override
        public Optional<ValidationException> findValidationProblemInNormalizedValue(URI uri) {
            String scheme = uri.getScheme();
            // ALLOW NULL LITERAL: URI uses null for an absent scheme or host. This trait converts those parser sentinels into stable validation errors before the DNS cross-validation phase.
            if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
                return Optional.of(new ValidationException(uri, "URL must use HTTP or HTTPS.", "http or https URL"));
            }
            String host = uri.getHost();
            // ALLOW NULL LITERAL: URI uses null for an absent host even when a scheme is present. This trait converts that parser sentinel into a stable validation error before the DNS cross-validation phase can begin.
            if (host == null || host.isBlank()) {
                return Optional.of(new ValidationException(uri, "URL must include a host.", "http or https URL"));
            }
            if (uri.getRawAuthority().contains("@")) {
                return Optional.of(new ValidationException(uri, "URL must not contain user info.", "URL without user info"));
            }
            return Optional.empty();
        }
    }
}
