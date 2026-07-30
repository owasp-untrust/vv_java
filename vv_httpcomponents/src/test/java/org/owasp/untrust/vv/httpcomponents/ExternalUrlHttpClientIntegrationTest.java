package org.owasp.untrust.vv.httpcomponents;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.prebuilt.ExternalUrl;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExternalUrlHttpClientIntegrationTest {
    @Test
    void fetchesGoogleThroughThePinnedExternalUrl() {
        assertSuccessfulExternalFetch("https://www.google.com/");
    }

    @Test
    void fetchesYnetThroughThePinnedExternalUrl() {
        assertSuccessfulExternalFetch("https://www.ynet.co.il/");
    }

    @Test
    void rejectsLocalhostBeforeAnyConnectionIsAttempted() {
        assertThrows(ValidationException.class, () -> ExternalUrl.Candidate.from("http://localhost/").crossValidate());
    }

    private static void assertSuccessfulExternalFetch(String rawUrl) {
        assertDoesNotThrow(() -> {
            try (ExternalUrlHttpClient client = ExternalUrlHttpClient.builder()
                    .maxBodyBytes(512 * 1024)
                    .connectTimeout(Duration.ofSeconds(10))
                    .responseTimeout(Duration.ofSeconds(15))
                    .build()) {
                ExternalUrlHttpClient.ExternalHttpResponse response = client.get(ExternalUrl.Candidate.from(rawUrl).crossValidate());
                assertTrue(response.statusCode() >= 100 && response.statusCode() < 600);
            }
        });
    }
}
