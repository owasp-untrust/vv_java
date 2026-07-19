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
    api("org.owasp.untrust:valuedescriptors:0.1.0")
    implementation("org.owasp.untrust:buildmetadata:0.1.0")
    implementation("commons-validator:commons-validator:1.10.1")
    implementation("com.ibm.icu:icu4j:78.1")
    implementation("org.slf4j:slf4j-api:2.0.17")
    implementation("org.springframework.security:spring-security-core:7.0.5")
    implementation("jakarta.servlet:jakarta.servlet-api:6.1.0")
}
