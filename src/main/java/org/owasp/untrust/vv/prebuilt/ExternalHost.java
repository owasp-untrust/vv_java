package org.owasp.untrust.vv.prebuilt;

import java.net.IDN;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import org.owasp.untrust.buildmetadata.NonFinalValidatedValue;
import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.foundation.CrossValidatedReceiver;
import org.owasp.untrust.vv.foundation.CrossValidationCandidate;
import org.owasp.untrust.vv.foundation.CrossValidationCandidate.FullyValidated;
import org.owasp.untrust.vv.foundation.ValidatedWrappedValue;
import org.owasp.untrust.vv.traits.RegexStringTraits;

import static org.owasp.untrust.valuedescriptors.Hardcoded.hardcoded;

/** A DNS host whose complete resolution set has been checked as externally routable. */
@NonFinalValidatedValue("ExternalHost is a reusable cross-validated value whose subclasses may add domain-specific DNS policy while retaining the required syntactic validation and complete external-address resolution.")
public class ExternalHost extends CrossValidatedReceiver<String, ExternalHost> {
    private final List<ExternalIp> resolvedIps;

    protected ExternalHost(FullyValidated<String, ExternalHost> validated, List<ExternalIp> resolvedIps) {
        super(validated);
        this.resolvedIps = List.copyOf(resolvedIps);
    }

    public String originalHost() {
        return exposeUnchecked();
    }

    public List<ExternalIp> resolvedIps() {
        return resolvedIps;
    }

    @Override
    public String toPublicString() {
        return originalHost();
    }

    public static final class Candidate extends ValidatedWrappedValue<String>
            implements CrossValidationCandidate<String, ExternalHost> {
        protected Candidate(String raw) {
            super(raw, new Traits());
        }

        public static Candidate from(String raw) {
            return new Candidate(raw);
        }

        public ExternalHost crossValidate() {
            String host = exposeUnchecked(EXPOSE_HALF_BAKED_VALUE_INTENDED_FOR_INTERNAL_LIBRARY_USE_ONLY_MARKER);
            List<ExternalIp> resolvedIps = resolve(host);
            FullyValidated<String, ExternalHost> validated = crossValidate(value -> Optional.empty());
            return new ExternalHost(validated, resolvedIps);
        }

        @Override
        public String toPublicString() {
            return "[external host candidate]";
        }

        private static List<ExternalIp> resolve(String host) {
            try {
                List<ExternalIp> addresses = Arrays.stream(InetAddress.getAllByName(host))
                        .map(ExternalIp::fromResolvedAddress)
                        .toList();
                if (addresses.isEmpty()) {
                    throw new ValidationException(host, "Host did not resolve to an address.", "external DNS host");
                }
                return addresses;
                // LOCAL CATCH REASON:
                // DNS resolution is the external operation owned by this cross-validation candidate. Converting its checked lookup failure into ValidationException keeps transport-specific DNS errors out of application code while preserving a stable validation boundary.
            } catch (UnknownHostException exception) {
                throw new ValidationException(host, "Host could not be resolved.", "external DNS host");
            }
        }
    }

    private static final class Traits extends RegexStringTraits {
        private static final Pattern DNS_HOST = Pattern.compile(
                "(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?");

        @Override
        public Hardcoded descriptionInErrors() {
            return hardcoded("DNS host name");
        }

        @Override
        public Optional<ValidationException> findValidationProblemInRaw(String raw) {
            // ALLOW NULL LITERAL: This public candidate accepts data from URL parsers and route binding, both of which use null to denote a missing host. Convert that legacy sentinel to a validation failure at the boundary.
            if (raw == null || raw.isBlank()) {
                return Optional.of(new ValidationException(raw, "Host must not be blank.", "DNS host name"));
            }
            return super.findValidationProblemInRaw(raw);
        }

        @Override
        public Bounds rawBounds() {
            return new Bounds(1, 253);
        }

        @Override
        public String reformatString(String raw) {
            return IDN.toASCII(raw, IDN.USE_STD3_ASCII_RULES);
        }

        @Override
        protected String normalizeReformattedString(String reformatted) {
            return reformatted.toLowerCase(java.util.Locale.ROOT);
        }

        @Override
        public Pattern welcomeListRegex() {
            return DNS_HOST;
        }
    }
}
