# vv_java

Validated value primitives for OWASP Untrust Java applications.

This library provides base classes, traits, exceptions, and helper types for turning raw strings into strongly typed validated values. The goal is to make validation explicit, reusable, and difficult to accidentally bypass.

## Coordinates

Current Gradle metadata:

```kotlin
group = "org.owasp.untrust"
version = "0.1.0"
```

Expected dependency once published:

```kotlin
dependencies {
    implementation("org.owasp.untrust:vv:0.1.0")
}
```

Spring-specific adapters live in a separate optional module so the core
validated-value library does not depend on Spring:

```kotlin
dependencies {
    implementation("org.owasp.untrust:vv_spring:0.1.0")
}
```

`ConstrainedMultipartFile` is in `vv_spring`, because it wraps Spring Web's
`MultipartFile`. It validates filename, declared content type, filename
extension, and byte-size bounds at the route boundary. Its filename and metadata
accessors return vv types rather than raw strings.

For local development before all libraries are published:

```kotlin
// settings.gradle.kts
includeBuild("../BuildGates")
includeBuild("../ValueDescriptors")
```

## Requirements

- JDK 21
- Gradle wrapper included in this repository
- `buildgates_java`
- `valuedescriptor_java`
- SLF4J API
- Spring Security core
- Jakarta Servlet API

Optional `vv_spring` module:

- Spring Vault Core

## Prebuilt Values

The `org.owasp.untrust.vv.prebuilt` package contains reusable validated values
that are production-ready enough to use directly when their policy matches your
domain:

- `PendingApiKey`
- `ApiKey`
- `CreditCard`

Use these instead of copying example code when the built-in validation and
public rendering match the application requirement.

## Secret Values And `vv_spring`

The core `vv` module contains the generic secret-value model. The optional
`vv_spring` module supplies a Spring Vault-backed `SecretStore<String>` adapter.
Use this split when an application wants route-bound secret values without
making the core validation library depend on Spring.

`PendingApiKey` and `ApiKey` in `org.owasp.untrust.vv.prebuilt` provide the
standard API-key shape:

- `PendingApiKey` represents the untrusted route/binding value.
- `PendingApiKey.from(String)` supports framework deserialization from a raw
  string.
- `PendingApiKey` validates the raw API key and implements `PendingSecret`.
- Calling the inherited pending-secret `hide(...)` method creates a
  `SecretValueInitializer`.
- `ApiKey` extends `SecretValue<String>` and accepts that initializer in its
  constructor.
- `ApiKey` stores only the secret reference/display value pair as its public
  object state. Reading the actual secret goes through the configured
  `SecretStore<String>`.

With Spring Vault:

```java
import org.owasp.untrust.vv.prebuilt.ApiKey;
import org.owasp.untrust.vv.prebuilt.PendingApiKey;
import org.owasp.untrust.vv.visibility.secret.SecretReference;
import org.owasp.untrust.vv.visibility.secret.SecretValueInitializer;
import org.owasp.untrust.vv.visibility.secret.vault.SpringVaultStringSecretStore;
import org.springframework.vault.core.VaultOperations;

public final class AiCredentialService {
    private final SpringVaultStringSecretStore secretStore;

    public AiCredentialService(VaultOperations vaultOperations) {
        this.secretStore = new SpringVaultStringSecretStore(
                vaultOperations,
                "secret");
    }

    public ApiKey storeUserApiKey(
            SecretReference reference,
            PendingApiKey pendingApiKey,
            String displayValue) {

        SecretValueInitializer<String, ApiKey> initializer =
                pendingApiKey.hide(
                        secretStore,
                        reference,
                        displayValue);

        return new ApiKey(initializer);
    }
}
```

In application code, use `PendingApiKey` directly when all configured AI
providers accept the same key character policy. If a provider needs stricter
rules, create a small route-specific subclass or sibling pending type and keep
the final stored value as `ApiKey`.
If the UI needs a masked suffix such as `****1234`, compute it in the
domain-specific pending type or the immediate route/service boundary before
calling `hide(...)`; do not expose the raw secret again later merely to create a
display value.

Avoid:

- returning the full API key from any HTTP response;
- logging the full API key;
- storing the raw API key in ordinary application DTOs;
- passing a primitive `String` API key through service layers after binding;
- putting Spring Vault dependencies in the core `vv` module.

Build:

```powershell
.\gradlew.bat build
```

On Unix-like shells:

```bash
./gradlew build
```

## Design Model

A validated value should be constructed from untrusted raw input exactly once, then passed through the rest of the application as a typed object.

The basic validation pipeline is:

1. Check raw string constraints that are independent of parsing.
2. Parse the raw string into a typed value.
3. Normalize the parsed value.
4. Check constraints on the normalized value.
5. Store only the validated value inside the wrapper.

`ValidatedValue<T, Traits>` implements this pipeline. A concrete value class supplies a `ValidationTraits<T>` implementation.

## Core Types

### `ValidatedValue<T, Traits>`

Base class for domain-specific validated values.

Typical subclass shape:

```java
public final class TaskName extends ValidatedValue<String, TaskName.Traits> {
    public TaskName(String raw) throws ValidationException {
        super(raw, new Traits());
    }

    public static final class Traits extends PrintableUnicodeStringTraits {
        @Override
        public Hardcoded descriptionInErrors() {
            return Hardcoded.hardcoded("task name");
        }

        @Override
        public Bounds bounds() {
            return new Bounds(1, 100);
        }

        @Override
        public String reformatString(String raw) {
            return raw.trim();
        }

        @Override
        public Optional<ValidationException> findExtraValidationProblemInPrintableValue(String value) {
            return Optional.empty();
        }
    }
}
```

Use a concrete validated value at the boundary:

```java
TaskName taskName = new TaskName(request.name());
taskService.createTask(taskName);
```

Do not keep passing the original raw string deeper into the application.

### Alphanumeric username with `SingleLine`

Extend `SingleLine` when the value must remain a single line, and add only the
domain-specific allow-list. The base class keeps the single-line text policy;
the concrete value owns its bounds definition.

```java
import java.util.Optional;
import java.util.regex.Pattern;

import com.fasterxml.jackson.annotation.JsonCreator;
import org.owasp.untrust.valuedescriptors.Hardcoded;
import org.owasp.untrust.vv.SingleLine;
import org.owasp.untrust.vv.exceptions.ValidationException;
import org.owasp.untrust.vv.traits.BoundedValueTraits;

public class Username extends SingleLine {
    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    public Username(String raw) {
        super(raw, new UsernameTraits());
    }

    public static Username from(String raw) {
        return new Username(raw);
    }

    private static class UsernameTraits extends SingleLine.Traits {
        private static final Pattern ALPHANUMERIC = Pattern.compile("[A-Za-z0-9]{3,32}");

        @Override
        public BoundedValueTraits.Bounds rawBounds() {
            return new BoundedValueTraits.Bounds(3, 32);
        }

        @Override
        protected Optional<ValidationException> findExtraValidationProblemInLineText(String value) {
            if (ALPHANUMERIC.matcher(value).matches()) {
                return Optional.empty();
            }

            return Optional.of(new ValidationException(
                    value,
                    Hardcoded.hardcoded("Username must contain only ASCII letters and digits.").value(),
                    ALPHANUMERIC));
        }
    }
}
```

### `ValidationTraits<T>`

Defines validation behavior:

- `descriptionInErrors()`
- `parse(String raw)`
- `normalize(T parsed)`
- `findValidationProblemInRaw(String raw)`
- `findValidationProblemInNormalizedValue(T normalized)`

Raw validation should handle cheap, parser-independent checks such as length limits. Let parsing validate format where possible.

### `ValidationException`

Thrown when input fails validation. It preserves:

- optional raw value
- optional parsed value
- validation error messages
- optional additional value such as a min/max bound

Use this for validation failures, not for authorization or persistence failures.

### `ViewableUuidValue`

Validated wrapper for UUID strings.

Example:

```java
ViewableUuidValue id = new ViewableUuidValue("123e4567-e89b-12d3-a456-426614174000");
UUID raw = id.exposeUnchecked();
```

`ViewableUuidValue` is intentionally non-final because UUID-backed identifiers may share parsing behavior.

## Trait Helpers

### `BoundedAnyContentStringTraits`

For strings with length limits but no content restrictions.

Use when any content is allowed and only size/normalization matters.

### `PrintableUnicodeStringTraits`

For strings that must contain printable Unicode characters.

Use for names, labels, descriptions, comments, and other human-entered text where control characters should be rejected.

### `RegexStringTraits`

For printable strings that must match a welcome-list regex.

Example:

```java
public final class Username extends ValidatedValue<String, Username.Traits> {
    public Username(String raw) throws ValidationException {
        super(raw, new Traits());
    }

    public static final class Traits extends RegexStringTraits {
        private static final Pattern USERNAME = Pattern.compile("[A-Za-z0-9_]{3,32}");

        @Override
        public Hardcoded descriptionInErrors() {
            return Hardcoded.hardcoded("username");
        }

        @Override
        public Bounds bounds() {
            return new Bounds(3, 32);
        }

        @Override
        public Pattern welcomeListRegex() {
            return USERNAME;
        }

        @Override
        public Optional<ValidationException> findExtraValidationProblem(String value) {
            return Optional.empty();
        }
    }
}
```

Prefer welcome-list patterns over block-list patterns.

### `BoundedValueTraits<T>`

For parsed values that have both raw string length bounds and typed value bounds.

Use for numbers, dates, times, and other ordered values.

### `EnumValidationTraits<E>`

For case-insensitive parsing of enum constants.

Example:

```java
enum DatabaseType {
    MYSQL,
    POSTGRES
}

EnumValidationTraits<DatabaseType> traits =
    new EnumValidationTraits<>(DatabaseType.class, Hardcoded.hardcoded("database type"));
```

### `RareTraitsCaseWhereParsingIsTheWholeValidation<T>`

For rare cases where parsing fully validates the domain.

Use sparingly. Supply a clear justification in code comments or annotations. UUID parsing is a typical example.

### `CustomValidationForRareCasesTraits<T>`

Escape hatch for specialized validation that does not fit the common trait shapes.

Prefer the more specific traits when possible.

## PII Rendering Interfaces

### `Pii<T>`

Marker interface for wrapped PII values that must define public rendering.

### `ErasedPii<T>`

Always renders as:

```text
****
```

### `MaskedPii<T>`

Renders a partial value while hiding the middle.

Examples:

```text
a      -> a***
abcd   -> a***
abcdef -> ab***ef
```

Use masking only when revealing a prefix/suffix is acceptable for the data category.

## Entity Authorization Helpers

`Entity<Snapshot>` and `DataAccess<Snapshot>` provide a small authorization pattern around entity IDs:

- parse and validate the entity UUID
- load a snapshot by ID
- apply an authorization justification function
- return `AuthorizedAccess<Snapshot>` only after authorization succeeds
- optionally hide existence with `DisclosurePolicy.HIDE_EXISTENCE`

Example shape:

```java
Entity<TaskSnapshot> entity = new Entity<>(taskIdFromRoute);

AuthorizedAccess<TaskSnapshot> access = entity.authorize(
    authentication,
    taskRepository::findSnapshotById,
    (auth, snapshot) -> snapshot.owner().equals(auth.getName())
        ? Optional.of("task owner")
        : Optional.empty()
);
```

Use the returned `AuthorizedAccess` as the proof that the entity was both found and authorized.

## What Not To Do

- Do not pass raw request strings past the boundary where a validated value should be created.
- Do not call `exposeUnchecked()` unless the receiving API genuinely needs the raw typed value.
- Do not validate parser-specific format manually when the parser can do it more correctly.
- Do not use block lists for validation when a welcome-list trait is appropriate.
- Do not make a validated value non-final unless there is a documented security reason.
- Do not use `RareTraitsCaseWhereParsingIsTheWholeValidation` just because it is shorter to implement.
- Do not log raw PII values.
- Do not use `MaskedPii` when full erasure is required.
- Do not catch `ValidationException` and continue with the original raw value.
- Do not treat successful validation as authorization. Validation and authorization are separate decisions.

Bad:

```java
String rawTaskId = request.getParameter("taskId");
taskRepository.load(rawTaskId);
```

Better:

```java
ViewableUuidValue taskId = new ViewableUuidValue(request.getParameter("taskId"));
taskRepository.load(taskId);
```

Bad:

```java
LOGGER.info("User email is {}", email.exposeUnchecked());
```

Better:

```java
LOGGER.info("User email is {}", email.toPublicString());
```

## Repository Notes

This repository is intended to become:

```text
https://github.com/owasp-untrust/vv_java
```

Dependency order:

1. `buildgates_java`
2. `valuedescriptor_java`
3. `vv_java`

Publish `buildgates_java` and `valuedescriptor_java` before publishing this repository.
