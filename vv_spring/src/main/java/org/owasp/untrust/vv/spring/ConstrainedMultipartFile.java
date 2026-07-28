package org.owasp.untrust.vv.spring;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.owasp.untrust.boxedpath.BoxedPath;
import org.owasp.untrust.vv.UploadContentType;
import org.owasp.untrust.vv.UploadFilename;
import org.owasp.untrust.vv.UploadPartName;
import org.owasp.untrust.vv.exceptions.ValidationException;
import org.springframework.core.io.Resource;
import org.springframework.web.multipart.MultipartFile;

/**
 * A validated MultipartFile boundary wrapper. MIME metadata is still declarative and must not be
 * treated as proof of the uploaded bytes' actual format.
 */
public final class ConstrainedMultipartFile {
    private final MultipartFile multipartFile;
    private final UploadPartName name;
    private final UploadFilename originalFilename;
    private final UploadContentType contentType;

    public ConstrainedMultipartFile(
            MultipartFile multipartFile,
            int maximumFilenameLength,
            long minimumSize,
            long maximumSize,
            Map<String, ? extends Collection<String>> allowedExtensionsByContentType) {

        if (minimumSize < 0 || maximumSize < minimumSize) {
            throw new IllegalArgumentException("File size bounds must be non-negative and ordered.");
        }

        this.multipartFile = multipartFile;
        Map<String, Set<String>> allowedExtensions = normalizeAllowedExtensions(allowedExtensionsByContentType);

        String rawContentType = requireExternalMetadata(this.multipartFile.getContentType(), "Upload content type is required.");
        String normalizedContentType = rawContentType.toLowerCase(Locale.ROOT);
        if (!allowedExtensions.containsKey(normalizedContentType)) {
            throw invalidUpload("Upload content type is not allowed.");
        }
        Set<String> allowedExtensionsForContentType = allowedExtensions.get(normalizedContentType);

        this.originalFilename = new UploadFilename(
                requireExternalMetadata(this.multipartFile.getOriginalFilename(), "Upload filename is required."),
                maximumFilenameLength);
        String extension = filenameExtension(originalFilename.exposeUnchecked());
        if (!allowedExtensionsForContentType.contains(extension)) {
            throw invalidUpload("Upload filename extension is not allowed for its content type.");
        }

        long size = this.multipartFile.getSize();
        if (size < minimumSize || size > maximumSize) {
            throw invalidUpload("Upload size is outside the permitted range.");
        }

        this.name = new UploadPartName(this.multipartFile.getName());
        this.contentType = new UploadContentType(rawContentType);
    }

    public UploadPartName getName() {
        return name;
    }

    public UploadFilename getOriginalFilename() {
        return originalFilename;
    }

    public UploadContentType getContentType() {
        return contentType;
    }

    public boolean isEmpty() {
        return multipartFile.isEmpty();
    }

    public long getSize() {
        return multipartFile.getSize();
    }

    public byte[] getBytes() throws IOException {
        return multipartFile.getBytes();
    }

    public InputStream getInputStream() throws IOException {
        return multipartFile.getInputStream();
    }

    public Resource getResource() {
        return multipartFile.getResource();
    }

    public void transferTo(BoxedPath destination) throws IOException {
        multipartFile.transferTo(destination);
    }

    private static String requireExternalMetadata(String value, String message) {
        // ALLOW NULL LITERAL: Spring MultipartFile metadata is supplied by external browser and multipart-parser implementations, whose documented contract permits omitted original filenames and content types. This boundary adapter converts that legacy nullable metadata into a stable upload validation failure before any value is stored or trusted.
        if (value == null || value.isBlank()) {
            throw invalidUpload(message);
        }
        return value;
    }

    private static Map<String, Set<String>> normalizeAllowedExtensions(
            Map<String, ? extends Collection<String>> allowedExtensionsByContentType) {

        if (allowedExtensionsByContentType.isEmpty()) {
            throw new IllegalArgumentException("At least one allowed content type is required.");
        }

        Map<String, Set<String>> normalized = new LinkedHashMap<>();
        allowedExtensionsByContentType.forEach((contentType, extensions) -> {
            String normalizedContentType = contentType.toLowerCase(Locale.ROOT);
            if (extensions.isEmpty()) {
                throw new IllegalArgumentException("Each content type must define at least one extension.");
            }

            Set<String> normalizedExtensions = new LinkedHashSet<>();
            for (String extension : extensions) {
                String normalizedExtension = normalizeExtension(extension);
                normalizedExtensions.add(normalizedExtension);
            }
            if (normalized.containsKey(normalizedContentType)) {
                throw new IllegalArgumentException("Content types must not differ only by case.");
            }
            normalized.put(normalizedContentType, Set.copyOf(normalizedExtensions));
        });
        return Map.copyOf(normalized);
    }

    private static String filenameExtension(String filename) {
        int separator = filename.lastIndexOf('.');
        if (separator <= 0 || separator == filename.length() - 1) {
            throw invalidUpload("Upload filename must have an extension.");
        }
        return normalizeExtension(filename.substring(separator + 1));
    }

    private static String normalizeExtension(String extension) {
        String candidate = extension.trim();
        if (candidate.startsWith(".")) {
            candidate = candidate.substring(1);
        }
        if (!candidate.matches("[A-Za-z0-9]+")) {
            throw new IllegalArgumentException("Upload extensions must contain only ASCII letters and digits.");
        }
        return candidate.toLowerCase(Locale.ROOT);
    }

    private static ValidationException invalidUpload(String message) {
        return new ValidationException(Optional.empty(), Optional.empty(), List.of(message), Optional.empty());
    }
}
