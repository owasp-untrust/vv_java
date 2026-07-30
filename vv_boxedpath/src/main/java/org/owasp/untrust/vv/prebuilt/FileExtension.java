package org.owasp.untrust.vv.prebuilt;

import java.util.Optional;

import org.owasp.untrust.boxedpath.BoxedPath;
import org.owasp.untrust.buildmetadata.NonFinalValidatedValue;
import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.vv.SingleLine;
import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.traits.BoundedValueTraits;

import static org.owasp.untrust.valuedescriptors.Hardcoded.hardcoded;

@NonFinalValidatedValue("File-extension subclasses may narrow the allow-list for a file domain while retaining the fixed 3-4 character extension shape and normalized dot-free representation.")
public class FileExtension extends SingleLine {
    public FileExtension(String raw) {
        this(raw, new Traits());
    }

    public FileExtension(BoxedPath path) {
        this(extensionFrom(path));
    }

    protected <T extends Traits> FileExtension(String raw, T traits) {
        super(withoutLeadingDot(raw), traits);
    }

    public static final FileExtension from(String raw) {
        return new FileExtension(raw);
    }

    public static final FileExtension from(BoxedPath path) {
        return new FileExtension(path);
    }

    public final String withDot() {
        /* STRING CONCAT IS SAFE HERE:
         * A FileExtension has already validated a short ASCII alphanumeric suffix, and this method only emits its conventional filename form. There is no path, URL, query, markup, or command context here: callers receive exactly one dot followed by the typed extension value, with no user-controlled structure left to interpret.
         */
        return "." + exposeUnchecked();
        /* END STRING CONCAT */
    }

    private static String withoutLeadingDot(String raw) {
        return raw.startsWith(".") ? raw.substring(1) : raw;
    }

    private static String extensionFrom(BoxedPath path) {
        String filename = path.getFileName().toString();
        int dot = filename.lastIndexOf('.');
        if (dot <= 0 || dot == filename.length() - 1) {
            return "";
        }
        return filename.substring(dot + 1);
    }

    public static class Traits extends SingleLine.Traits {
        @Override
        public final Hardcoded descriptionInErrors() {
            return hardcoded("file extension");
        }

        @Override
        public BoundedValueTraits.Bounds rawBounds() {
            return new BoundedValueTraits.Bounds(3, 4);
        }

        @Override
        protected final Optional<ValidationException> findExtraValidationProblemInLineText(String normalized) {
            if (normalized.matches("[A-Za-z0-9]{3,4}")) {
                return Optional.empty();
            }
            return Optional.of(new ValidationException(
                    normalized,
                    "File extensions must contain 3 to 4 ASCII letters or digits.",
                    "3-4 ASCII alphanumeric characters"));
        }
    }
}
