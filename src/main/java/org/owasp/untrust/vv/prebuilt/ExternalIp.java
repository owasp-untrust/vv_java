package org.owasp.untrust.vv.prebuilt;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.Optional;

import org.apache.commons.validator.routines.InetAddressValidator;
import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.foundation.ExposableValidatedWrappedValue;
import org.owasp.untrust.vv.foundation.ValidationTraits;

import com.fasterxml.jackson.annotation.JsonCreator;

import static org.owasp.untrust.valuedescriptors.Hardcoded.hardcoded;

/** A literal, globally routable IP address suitable as an outbound network destination. */
public final class ExternalIp extends ExposableValidatedWrappedValue<String> {
    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    public ExternalIp(String raw) {
        super(raw, new Traits());
    }

    public static ExternalIp from(String raw) {
        return new ExternalIp(raw);
    }

    public static ExternalIp fromResolvedAddress(InetAddress address) {
        return new ExternalIp(address.getHostAddress());
    }

    public InetAddress asInetAddress() throws UnknownHostException {
        return InetAddress.getByName(exposeUnchecked());
    }

    public static final class Traits implements ValidationTraits<String> {
        private static final InetAddressValidator ADDRESS_VALIDATOR = InetAddressValidator.getInstance();

        @Override
        public Hardcoded descriptionInErrors() {
            return hardcoded("external IP address");
        }

        @Override
        public Optional<ValidationException> findValidationProblemInRaw(String raw) {
            if (ADDRESS_VALIDATOR.isValid(raw)) {
                return Optional.empty();
            }
            return Optional.of(new ValidationException(raw, "An IP address literal is required.", "IPv4 or IPv6 literal"));
        }

        @Override
        public String parse(String raw) {
            return raw;
        }

        @Override
        public String normalize(String parsed) {
            return parsed.toLowerCase(Locale.ROOT);
        }

        @Override
        public Optional<ValidationException> findValidationProblemInNormalizedValue(String ipLiteral) {
            try {
                InetAddress address = InetAddress.getByName(ipLiteral);
                if (isExternal(address)) {
                    return Optional.empty();
                }
                // LOCAL CATCH REASON:
                // InetAddress has a checked exception even for an already syntax-validated literal. This value-object boundary must convert that JDK-only failure into its stable validation result rather than leak a networking API detail to every caller.
            } catch (UnknownHostException ignored) {
                // The literal was validated before resolution; this is only a JDK API bridge.
            }
            return Optional.of(new ValidationException(ipLiteral, "IP address must be globally routable.", "external unicast address"));
        }

        private static boolean isExternal(InetAddress address) {
            byte[] bytes = address.getAddress();
            if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                    || address.isSiteLocalAddress() || address.isMulticastAddress() || isUniqueLocalIpv6(bytes)) {
                return false;
            }
            return bytes.length != 4 || isExternalIpv4(bytes);
        }

        private static boolean isExternalIpv4(byte[] bytes) {
            int first = Byte.toUnsignedInt(bytes[0]);
            int second = Byte.toUnsignedInt(bytes[1]);
            return first != 0 && first != 10 && first != 127
                    && !(first == 100 && second >= 64 && second <= 127)
                    && !(first == 169 && second == 254)
                    && !(first == 172 && second >= 16 && second <= 31)
                    && !(first == 192 && (second == 0 || second == 168))
                    && !(first == 198 && (second == 18 || second == 19 || second == 51))
                    && !(first == 203 && second == 0)
                    && first < 224;
        }

        private static boolean isUniqueLocalIpv6(byte[] bytes) {
            return bytes.length == 16 && (Byte.toUnsignedInt(bytes[0]) & 0xfe) == 0xfc;
        }
    }
}
