plugins {
    `java-library`
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
    api("org.springframework.vault:spring-vault-core:4.1.0")
}
