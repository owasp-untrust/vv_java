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
    api("org.springframework:spring-web:7.0.3")
    api("org.springframework.vault:spring-vault-core:4.1.0")
    api("io.github.owasp-untrust:untrust-boxedpath:0.3")
}
