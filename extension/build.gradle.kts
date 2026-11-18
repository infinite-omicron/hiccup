plugins {
    java
}

// Set by `make` / CI from the git tag, e.g. -PhiccupVersion=v0.2.0.
version = (findProperty("hiccupVersion") as String?) ?: "dev"

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.7")
    implementation("com.google.code.gson:gson:2.15.0")
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release.set(17)
}

tasks.jar {
    archiveFileName.set("hiccup-burp.jar")
    manifest {
        attributes("Implementation-Title" to "hiccup-burp", "Implementation-Version" to project.version)
    }
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().filter { it.isDirectory }.map { it } +
        configurations.runtimeClasspath.get().filter { !it.isDirectory }.map { zipTree(it) }) {
        exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA", "META-INF/versions/**", "module-info.class")
    }
}
