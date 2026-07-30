# vv_boxedpath

`vv_boxedpath` contains validated values that depend on the `BoxedPath` path
sandbox library. It is separate from core `vv` so applications that do not
handle files do not acquire a filesystem-path dependency.

## Dependency

```kotlin
dependencies {
    implementation("org.owasp.untrust:vv_boxedpath:0.1.0")
}
```

For local composite-build development, include the `vv` repository once; its
Gradle build contains the core, Spring, and boxed-path modules.

```kotlin
// settings.gradle.kts
includeBuild("../vv")
```

## FileExtension

`org.owasp.untrust.vv.prebuilt.FileExtension` accepts an extension with or
without a leading dot and permits only three or four ASCII letters or digits.
It can also be created from a `BoxedPath` by extracting that path's final
extension.

```java
FileExtension imageExtension = new FileExtension(".PNG");
FileExtension storedExtension = new FileExtension(storedFile);
```

Use `withDot()` when a filename suffix is needed. Do not build a storage path
from an uploaded filename; pass `FileExtension` to
`ConstrainedMultipartFile.toFile(...)` with a server-controlled `BoxedPath`
directory instead.
