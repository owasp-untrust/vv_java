package org.owasp.untrust.vv.traits;

import java.text.Normalizer;
import java.util.Optional;

import com.ibm.icu.text.BreakIterator;
import com.ibm.icu.text.UnicodeSet;
import org.owasp.untrust.buildmetadata.StringConcatenationSafe;
import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.vv.exceptions.ValidationException;

import static org.owasp.untrust.valuedescriptors.Hardcoded.hardcoded;

@StringConcatenationSafe("Line text validation messages and descriptions are assembled from fixed developer-authored fragments and Hardcoded labels. The user supplied text remains separate structured ValidationException data and is not embedded in the message.")
public abstract class LineTextTraits extends BoundedAnyContentStringTraits {
    private static final UnicodeSet RGI_EMOJI = new UnicodeSet("[:RGI_Emoji:]").freeze();

    public abstract boolean allowNewlines();

    public abstract boolean allowEmoji();

    public abstract boolean requirePathSafeText();

    @Override
    protected final String normalizeReformattedString(String reformatted) {
        return Normalizer.normalize(reformatted, Normalizer.Form.NFC);
    }

    @Override
    public final Optional<ValidationException> findValidationProblemInNormalizedValue(String normalized) {
        Optional<ValidationException> boundedProblem = super.findValidationProblemInNormalizedValue(normalized);
        if (boundedProblem.isPresent()) {
            return boundedProblem;
        }

        if (requirePathSafeText()) {
            Optional<ValidationException> pathProblem = findPathSafeTextProblem(normalized);
            if (pathProblem.isPresent()) {
                return pathProblem;
            }
        }

        BreakIterator characterIterator = BreakIterator.getCharacterInstance();
        characterIterator.setText(normalized);

        int start = characterIterator.first();
        for (int end = characterIterator.next(); end != BreakIterator.DONE; start = end, end = characterIterator.next()) {
            String cluster = normalized.substring(start, end);
            if (!isAllowedCluster(cluster)) {
                return Optional.of(new ValidationException(
                        normalized,
                        descriptionInErrors().concat(hardcoded(": Value contains a disallowed character or emoji sequence.")).value(),
                        Optional.empty()));
            }
        }

        return findExtraValidationProblemInLineText(normalized);
    }

    protected abstract Optional<ValidationException> findExtraValidationProblemInLineText(String normalized);

    private boolean isAllowedCluster(String cluster) {
        if (allowEmoji() && RGI_EMOJI.contains(cluster)) {
            return true;
        }

        return isAllowedTextualCluster(cluster);
    }

    private boolean isAllowedTextualCluster(String cluster) {
        boolean hasTextualBase = false;

        int[] codePoints = cluster.codePoints().toArray();
        for (int codePoint : codePoints) {
            if (isEmojiCombiningCodePoint(codePoint)) {
                return false;
            }

            if (requirePathSafeText() && isForbiddenPathCodePoint(codePoint)) {
                return false;
            }

            if (isCombiningMark(codePoint)) {
                continue;
            }

            if (!isAllowedTextualBaseCodePoint(codePoint)) {
                return false;
            }

            hasTextualBase = true;
        }

        return hasTextualBase;
    }

    private boolean isAllowedTextualBaseCodePoint(int codePoint) {
        if (codePoint == ' ') {
            return true;
        }

        if (allowNewlines() && codePoint == '\n') {
            return true;
        }

        int type = Character.getType(codePoint);
        return type == Character.UPPERCASE_LETTER
                || type == Character.LOWERCASE_LETTER
                || type == Character.TITLECASE_LETTER
                || type == Character.MODIFIER_LETTER
                || type == Character.OTHER_LETTER
                || type == Character.DECIMAL_DIGIT_NUMBER
                || type == Character.LETTER_NUMBER
                || type == Character.OTHER_NUMBER
                || type == Character.CONNECTOR_PUNCTUATION
                || type == Character.DASH_PUNCTUATION
                || type == Character.START_PUNCTUATION
                || type == Character.END_PUNCTUATION
                || type == Character.INITIAL_QUOTE_PUNCTUATION
                || type == Character.FINAL_QUOTE_PUNCTUATION
                || type == Character.OTHER_PUNCTUATION
                || isAllowedSymbol(type);
    }

    private boolean isAllowedSymbol(int type) {
        return type == Character.MATH_SYMBOL || type == Character.CURRENCY_SYMBOL;
    }

    private Optional<ValidationException> findPathSafeTextProblem(String normalized) {
        String[] pathSegments = normalized.split("[/\\\\]", -1);
        for (String segment : pathSegments) {
            if (segment.equals(".") || segment.equals("..")) {
                return Optional.of(new ValidationException(
                        normalized,
                        descriptionInErrors().concat(hardcoded(": Path segments must not be '.' or '..'.")).value(),
                        Optional.empty()));
            }
        }

        return Optional.empty();
    }

    private static boolean isForbiddenPathCodePoint(int codePoint) {
        return codePoint == '<'
                || codePoint == '>'
                || codePoint == ':'
                || codePoint == '"'
                || codePoint == '|'
                || codePoint == '?'
                || codePoint == '*';
    }

    private static boolean isCombiningMark(int codePoint) {
        int type = Character.getType(codePoint);
        return type == Character.NON_SPACING_MARK
                || type == Character.ENCLOSING_MARK
                || type == Character.COMBINING_SPACING_MARK;
    }

    private static boolean isEmojiCombiningCodePoint(int codePoint) {
        return codePoint == 0x20E3 || isVariationSelector(codePoint);
    }

    private static boolean isVariationSelector(int codePoint) {
        return (codePoint >= 0xFE00 && codePoint <= 0xFE0F)
                || (codePoint >= 0xE0100 && codePoint <= 0xE01EF);
    }

    protected static Hardcoded lineTextDescription(String lineMode, String emojiMode) {
        return Hardcoded.of(lineMode).concat(Hardcoded.of(" ")).concat(Hardcoded.of(emojiMode));
    }
}
