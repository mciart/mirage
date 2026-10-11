import java.util.Base64
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Optional built-in default server (private builds only). The TOML path comes from, in order:
// gradle property `mirage.defaultConfigFile`, env MIRAGE_DEFAULT_CONFIG_FILE, or the
// `mirage.defaultConfigFile` key in local.properties. The file contents are base64-encoded
// into BuildConfig.DEFAULT_CONFIG_B64 ("" when no path is configured, e.g. in CI).
val defaultConfigB64: String = run {
    val fromLocal = Properties().let { props ->
        val f = rootProject.file("local.properties")
        if (f.exists()) f.inputStream().use { props.load(it) }
        props.getProperty("mirage.defaultConfigFile")
    }
    val path = ((findProperty("mirage.defaultConfigFile") as String?)
        ?: System.getenv("MIRAGE_DEFAULT_CONFIG_FILE")
        ?: fromLocal)?.trim()
    if (path.isNullOrEmpty()) {
        ""
    } else {
        val file = rootProject.file(path)
        if (!file.isFile) {
            throw GradleException("mirage.defaultConfigFile does not exist: ${file.absolutePath}")
        }
        Base64.getEncoder().encodeToString(file.readBytes())
    }
}

// Release version, overridable from CI: -PversionName=1.0.0 -PversionCode=10000
val appVersionName: String = (findProperty("versionName") as String?) ?: "1.0.0"
val appVersionCode: Int = (findProperty("versionCode") as String?)?.toInt() ?: 1

// Release signing comes from the environment (CI). All three must be set, otherwise the release
// build stays unsigned. ANDROID_KEYSTORE_PASSWORD is used for both the store and the key.
val releaseKeystoreFile: String = System.getenv("ANDROID_KEYSTORE_FILE").orEmpty()
val releaseKeystorePassword: String = System.getenv("ANDROID_KEYSTORE_PASSWORD").orEmpty()
val releaseKeyAlias: String = System.getenv("ANDROID_KEY_ALIAS").orEmpty()
val hasReleaseSigning: Boolean =
    releaseKeystoreFile.isNotEmpty() && releaseKeystorePassword.isNotEmpty() && releaseKeyAlias.isNotEmpty()

android {
    namespace = "com.mirage.vpn"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.mirage.vpn"
        minSdk = 24
        targetSdk = 34
        versionCode = appVersionCode
        versionName = appVersionName

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }

        buildConfigField("String", "DEFAULT_CONFIG_B64", "\"$defaultConfigB64\"")
    }

    signingConfigs {
        create("release") {
            if (hasReleaseSigning) {
                storeFile = file(releaseKeystoreFile)
                storeType = "pkcs12"
                storePassword = releaseKeystorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeystorePassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        buildConfig = true
        compose = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
    }

    sourceSets {
        getByName("main") {
            // CI drops libmirage_ffi.so into src/main/jniLibs/<abi>/
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.06.00")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.3")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core")

    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("com.google.android.gms:play-services-code-scanner:16.1.0")

    debugImplementation("androidx.compose.ui:ui-tooling")

    // Instrumentation tests (connectedDebugAndroidTest)
    androidTestImplementation(composeBom)
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:rules:1.6.1")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
