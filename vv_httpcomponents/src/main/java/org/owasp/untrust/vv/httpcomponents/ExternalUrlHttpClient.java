package org.owasp.untrust.vv.httpcomponents;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpHead;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.util.Timeout;
import org.owasp.untrust.vv.prebuilt.ExternalHost;
import org.owasp.untrust.vv.prebuilt.ExternalIp;
import org.owasp.untrust.vv.prebuilt.ExternalUrl;

/**
 * Blocking Apache HttpClient transport that connects only to the DNS answers
 * captured by an {@link ExternalUrl}, while retaining its original host for
 * HTTP Host and HTTPS SNI/certificate validation.
 */
public final class ExternalUrlHttpClient implements AutoCloseable {
    private static final String DEFAULT_ACCEPT = "text/html,application/xhtml+xml";
    private static final String DEFAULT_USER_AGENT = "OWASP-Untrust-ExternalUrlHttpClient/1.0";

    private final int maxBodyBytes;
    private final CloseableHttpClient client;
    private final PinnedDnsResolver dnsResolver;

    public ExternalUrlHttpClient(int maxBodyBytes) {
        this(builder().maxBodyBytes(maxBodyBytes));
    }

    private ExternalUrlHttpClient(Builder builder) {
        this.maxBodyBytes = builder.maxBodyBytes;
        this.dnsResolver = new PinnedDnsResolver();
        PoolingHttpClientConnectionManager connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
                .setDnsResolver(dnsResolver)
                .setDefaultConnectionConfig(ConnectionConfig.custom()
                        .setConnectTimeout(timeout(builder.connectTimeout))
                        .build())
                .setMaxConnTotal(builder.maxConnections)
                .setMaxConnPerRoute(builder.maxConnectionsPerRoute)
                .build();
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(timeout(builder.connectionRequestTimeout))
                .setResponseTimeout(timeout(builder.responseTimeout))
                .build();
        this.client = HttpClients.custom()
                .setConnectionManager(connectionManager)
                .setDefaultRequestConfig(requestConfig)
                .disableRedirectHandling()
                .setUserAgent(builder.userAgent)
                .build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public ExternalHttpResponse get(ExternalUrl externalUrl) throws IOException {
        return execute(externalUrl, ExternalHttpRequest.get());
    }

    public ExternalHttpResponse head(ExternalUrl externalUrl) throws IOException {
        return execute(externalUrl, ExternalHttpRequest.head());
    }

    public ExternalHttpResponse execute(ExternalUrl externalUrl, ExternalHttpRequest request) throws IOException {
        dnsResolver.pin(externalUrl.externalHost());
        ClassicHttpRequest apacheRequest = request.apacheRequestFor(externalUrl);
        return client.execute(apacheRequest, response -> new ExternalHttpResponse(
                    response.getCode(),
                    responseHeaders(response.getHeaders()),
                    responseBody(response.getEntity())));
    }

    private byte[] responseBody(HttpEntity entity) throws IOException {
        // ALLOW NULL LITERAL: Apache represents a legal body-less HTTP response with a null entity. This narrow adapter turns it into an empty immutable response body before callers inspect preview metadata.
        if (entity == null) {
            return new byte[0];
        }
        try (InputStream body = entity.getContent()) {
            byte[] bytes = body.readNBytes(Math.incrementExact(maxBodyBytes));
            if (bytes.length > maxBodyBytes) {
                throw new IOException("Response body is too large.");
            }
            return bytes;
        }
    }

    private static Map<String, List<String>> responseHeaders(Header[] headers) {
        Map<String, List<String>> grouped = new LinkedHashMap<>();
        Arrays.stream(headers).forEach(header -> grouped.merge(
                header.getName().toLowerCase(Locale.ROOT),
                List.of(header.getValue()),
                (existing, next) -> {
                    java.util.ArrayList<String> values = new java.util.ArrayList<>(existing);
                    values.addAll(next);
                    return List.copyOf(values);
                }));
        return Map.copyOf(grouped);
    }

    private static Timeout timeout(Duration value) {
        return Timeout.ofMilliseconds(value.toMillis());
    }

    @Override
    public void close() throws IOException {
        client.close();
    }

    public record ExternalHttpResponse(int statusCode, Map<String, List<String>> headers, byte[] body) {
        public ExternalHttpResponse {
            headers = Map.copyOf(headers);
            body = body.clone();
        }

        public String firstHeaderValue(String headerName) {
            return headers.getOrDefault(headerName.toLowerCase(Locale.ROOT), List.of()).stream().findFirst().orElse("");
        }

        public String location() {
            return firstHeaderValue("location");
        }

        public String contentType() {
            return firstHeaderValue("content-type");
        }

        @Override
        public byte[] body() {
            return body.clone();
        }
    }

    public record ExternalHttpRequest(Method method, Map<String, String> headers, byte[] body) {
        public ExternalHttpRequest {
            headers = Map.copyOf(headers);
            body = body.clone();
        }

        public static ExternalHttpRequest get() {
            return new ExternalHttpRequest(Method.GET, Map.of("Accept", DEFAULT_ACCEPT), new byte[0]);
        }

        public static ExternalHttpRequest head() {
            return new ExternalHttpRequest(Method.HEAD, Map.of(), new byte[0]);
        }

        public static ExternalHttpRequest post(byte[] body) {
            return new ExternalHttpRequest(Method.POST, Map.of(), body);
        }

        public ExternalHttpRequest withHeader(String name, String value) {
            if ("host".equalsIgnoreCase(name)) throw new IllegalArgumentException("Host header is controlled by ExternalUrl.");
            Map<String, String> amended = new LinkedHashMap<>(headers);
            amended.put(name, value);
            return new ExternalHttpRequest(method, amended, body);
        }

        private ClassicHttpRequest apacheRequestFor(ExternalUrl externalUrl) {
            ClassicHttpRequest request = switch (method) {
                case GET -> new HttpGet(externalUrl.originalUri());
                case HEAD -> new HttpHead(externalUrl.originalUri());
                case POST -> new HttpPost(externalUrl.originalUri());
            };
            if (request instanceof HttpPost post) {
                post.setEntity(new ByteArrayEntity(body, ContentType.APPLICATION_OCTET_STREAM));
            }
            headers.forEach(request::setHeader);
            return request;
        }
    }

    public enum Method {
        GET,
        HEAD,
        POST
    }

    public static final class Builder {
        private int maxBodyBytes = 2_000_000;
        private Duration connectTimeout = Duration.ofSeconds(5);
        private Duration connectionRequestTimeout = Duration.ofSeconds(5);
        private Duration responseTimeout = Duration.ofSeconds(8);
        private int maxConnections = 100;
        private int maxConnectionsPerRoute = 20;
        private String userAgent = DEFAULT_USER_AGENT;

        public Builder maxBodyBytes(int value) {
            if (value < 1 || value == Integer.MAX_VALUE) throw new IllegalArgumentException("maxBodyBytes must be positive and below Integer.MAX_VALUE.");
            maxBodyBytes = value;
            return this;
        }

        public Builder connectionRequestTimeout(Duration value) {
            connectionRequestTimeout = positiveDuration(value);
            return this;
        }

        public Builder connectTimeout(Duration value) {
            connectTimeout = positiveDuration(value);
            return this;
        }

        public Builder responseTimeout(Duration value) {
            responseTimeout = positiveDuration(value);
            return this;
        }

        public Builder maxConnections(int value) {
            if (value < 1) throw new IllegalArgumentException("maxConnections must be positive.");
            maxConnections = value;
            return this;
        }

        public Builder maxConnectionsPerRoute(int value) {
            if (value < 1) throw new IllegalArgumentException("maxConnectionsPerRoute must be positive.");
            maxConnectionsPerRoute = value;
            return this;
        }

        public Builder userAgent(String value) {
            if (value.isBlank()) throw new IllegalArgumentException("userAgent must not be blank.");
            userAgent = value;
            return this;
        }

        public ExternalUrlHttpClient build() {
            return new ExternalUrlHttpClient(this);
        }

        private static Duration positiveDuration(Duration value) {
            if (value.isZero() || value.isNegative()) throw new IllegalArgumentException("Timeout must be positive.");
            return value;
        }
    }

    private static final class PinnedDnsResolver implements DnsResolver {
        private static final int MAX_PINNED_HOSTS = 1_024;
        private final Map<String, ExternalHost> pinnedHosts = Collections.synchronizedMap(
                new LinkedHashMap<>(MAX_PINNED_HOSTS, 0.75f, true) {
                    @Override
                    protected boolean removeEldestEntry(Map.Entry<String, ExternalHost> eldest) {
                        return size() > MAX_PINNED_HOSTS;
                    }
                });

        private void pin(ExternalHost host) {
            pinnedHosts.put(host.originalHost().toLowerCase(Locale.ROOT), host);
        }

        @Override
        public InetAddress[] resolve(String host) throws UnknownHostException {
            ExternalHost externalHost = pinnedHosts.get(host.toLowerCase(Locale.ROOT));
            // ALLOW NULL LITERAL: ConcurrentMap.get uses null to represent an absent DNS pin. The resolver must reject that legacy collection sentinel before Apache can ask system DNS for an unreviewed destination.
            if (externalHost == null) {
                throw new UnknownHostException("ExternalUrlHttpClient received an unpinned host.");
            }
            return externalHost.resolvedIps().stream().map(this::toInetAddress).toArray(InetAddress[]::new);
        }

        @Override
        public String resolveCanonicalHostname(String host) throws UnknownHostException {
            ExternalHost externalHost = pinnedHosts.get(host.toLowerCase(Locale.ROOT));
            // ALLOW NULL LITERAL: ConcurrentMap.get uses null to represent an absent DNS pin. The resolver must reject that legacy collection sentinel before Apache can accept an unreviewed canonical host.
            if (externalHost == null) {
                throw new UnknownHostException("ExternalUrlHttpClient received an unpinned host.");
            }
            return externalHost.originalHost();
        }

        private InetAddress toInetAddress(ExternalIp ip) {
            try {
                return ip.asInetAddress();
                // LOCAL CATCH REASON: ExternalIp has validated this literal, but Apache's resolver requires InetAddress and the JDK exposes literal conversion as checked. This bridge turns an impossible-after-validation failure into an internal defect.
            } catch (UnknownHostException exception) {
                throw new IllegalStateException("Validated IP literal could not be converted.", exception);
            }
        }
    }
}
