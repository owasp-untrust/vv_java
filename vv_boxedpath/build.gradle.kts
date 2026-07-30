plugins {
    `java-library`
    id("org.owasp.untrust.build-gates")
}

group = "org.owasp.untrust"
version = "0.1.0"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    api(project(":"))
    implementation("org.owasp.untrust:buildmetadata:0.1.0")
    api("io.github.owasp-untrust:untrust-boxedpath:0.3")
}
