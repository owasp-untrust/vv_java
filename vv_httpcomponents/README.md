# vv_httpcomponents

`vv_httpcomponents` is a production-oriented, blocking Apache HttpClient 5
transport for `ExternalUrl`. It prevents DNS rebinding by connecting only to
the externally validated address set already captured by `ExternalUrl`, while
the original URL hostname remains in the request URI for HTTP `Host` and HTTPS
SNI/certificate validation.

## Dependency

```kotlin
dependencies {
    implementation("org.owasp.untrust:vv_httpcomponents:0.1.0")
}
```

For local development, include the `vv` composite build once:

```kotlin
// settings.gradle.kts
includeBuild("../vv")
```

## Usage

```java
try (ExternalUrlHttpClient client = ExternalUrlHttpClient.builder()
        .maxBodyBytes(2_000_000)
        .connectTimeout(Duration.ofSeconds(5))
        .connectionRequestTimeout(Duration.ofSeconds(5))
        .responseTimeout(Duration.ofSeconds(8))
        .build()) {
    ExternalUrl url = ExternalUrl.Candidate
            .from("https://www.example.com/preview")
            .crossValidate();
    ExternalUrlHttpClient.ExternalHttpResponse response = client.get(url);
}
```

The response exposes its status code, case-insensitive response headers, and a
defensively copied bounded byte body. Redirect handling is disabled: validate
each redirect target with `ExternalUrl.Candidate.from(location).crossValidate()`
and issue a new request.

## Security Contract

- `GET`, `HEAD`, and explicit byte-body `POST` requests are supported. A POST
  still requires an `ExternalUrl`; keep request data minimal and use it only
  for a deliberately trusted external integration such as a configured AI API.
- Each destination must be a cross-validated `ExternalUrl`, never a raw URI,
  hostname, or `ExternalUrl.Candidate`.
- DNS is resolved by `ExternalUrl.Candidate.crossValidate()` before the request
  and is never repeated by Apache against system DNS for that request.
- The client owns a reusable Apache connection pool and must be closed when its
  application lifetime ends. Its DNS-pin cache is bounded and fails closed if a
  request needs a pin that is no longer retained.
- Choose a bounded body size and timeouts appropriate to the feature. Link
  previews should reject oversized or non-successful responses at their domain
  layer.
