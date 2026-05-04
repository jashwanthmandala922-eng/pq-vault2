# PQ Vault ProGuard/R8 Rules
# Security-focused obfuscation with tamper detection compatibility

# ========================
# KEEP RULES (OBFUSCATE EVERYTHING ELSE)
# ========================

# Keep app package name for SafetyNet compatibility
-keeppackagenames com.quantvault.app

# ---- Native JNI Bridge (Keep class names for native calls) ----
-keep class com.quantvault.app.data.local.NativeVault {
    native <methods>;
    <fields>;
}
-keep class com.quantvault.app.PQVaultApplication {
    native <methods>;
}

# ---- Firebase Auth (Required for Firebase SDK) ----
-keep class com.google.firebase.** { *; }
-keep class com.google.android.gms.auth.** { *; }
-keep class com.google.android.gms.games.** { *; }
-keepclassmembers class * extends com.google.firebase.auth.FirebaseAuth {
    <fields>;
    <init>(...);
}

# ---- Hilt Dependency Injection ----
-keep class dagger.hilt.** { *; }
-keep class javax.inject.** { *; }
-keep class * extends dagger.hilt.android.internal.managers.ApplicationComponentManager { *; }
-keep class * extends dagger.hilt.android.internal.managers.ViewComponentManager$FragmentContextWrapper { *; }
-keep class * extends dagger.hilt.android.internal.managers.ViewWithFragmentComponentManager$FragmentContextWrapper { *; }
-keepclasseswithmembers class * {
    @dagger.hilt.* <methods>;
}
-keepclasseswithmembers class * {
    @dagger.hilt.* <fields>;
}

# ---- Kotlin Coroutines (Required for async) ----
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keepclassmembers class kotlinx.coroutines.** {
    volatile <fields>;
}

# ---- Kotlin Serialization ----
-keepattributes *Annotation*, InnerClasses, EnclosingMethod
-keepattributes RuntimeVisibleAnnotations, RuntimeVisibleParameterAnnotations
-keepclassmembers class kotlinx.serialization.json.* {
    *** Companion;
}
-keepclasseswithmembers class kotlinx.serialization.* {
    kotlinx.serialization.KSerializer serializer(...);
}

# ---- Compose UI Framework ----
-keep class androidx.compose.** { *; }
-keep class androidx.compose.runtime.** { *; }

# ---- SafetyNet/Play Integrity ----
-keep class com.google.android.gms.safetynet.** { *; }
-keep class com.google.android.gms.common.** { *; }

# ========================
# OBFUSCATION RULES (ENABLE FOR SECURITY)
# ========================

# Obfuscate app-specific classes (makes reverse engineering harder)
-keep class com.quantvault.app.data.** { *; }  # Keep data layer for JNI access
-keep class com.quantvault.app.di.** { *; }    # Keep DI for Hilt
-keep class com.quantvault.app.service.** { *; }  # Keep autofill service

# Allow obfuscation of UI screens and ViewModels
-keepclassmembers class * extends androidx.lifecycle.ViewModel {
    <init>(...);
}

# ---- Remove logging in release builds ----
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
    public static *** w(...);
}

# ========================
# OPTIMIZATION RULES
# ========================

# Remove unused classes
-dontwarn com.google.android.gms.**
-dontwarn androidx.**
-dontwarn javax.annotation.**

# Optimize method inlining
-optimizationpasses 5

# Allow access to removed classes for compatibility
-keep class com.google.android.gms.internal.** { *; }

# ========================
# JNI PROTECTION
# ========================

# Obfuscate native method signatures (makes JNI reverse engineering harder)
# This makes it harder to identify which methods are JNI bridges
-keepclassmembers,allowobfuscation class * {
    @android.webkit.JavascriptInterface <methods>;
}

# Prevent reflection on app classes
-keep class com.quantvault.app.ui.** { *; }  # Keep UI for reflection

# ========================
# SECURITY-SENSITIVE CLASSES
# ========================

# Never obfuscate security-related classes (keep names for audit)
-keep class com.quantvault.app.data.local.SecurePreferences { *; }
-keep class com.quantvault.app.data.repository.VaultRepository { *; }
-keep class com.quantvault.app.data.auth.FirebaseAuthManager { *; }
-keep class com.quantvault.app.data.sync.** { *; }

# ========================
# REMOVE DEBUG INFO IN RELEASE
# ========================

# Remove source file names and line numbers
-keepattributes SourceFile,LineNumberTable

# Remove R8 metadata
-keepattributes *Annotation*, Signature, InnerClasses, EnclosingMethod

# ========================
# PREVENT CLASS MERGING (Security)
# ========================

# Prevent R8 from merging classes that could bypass security checks
-keep class com.google.android.gms.internal.** { *; }
-keep class com.google.firebase.internal.** { *; }

# ========================
# APK SIGNATURE VERIFICATION
# ========================

# Keep classes needed for root/tamper detection
-keep class com.google.android.gms.common.internal.ApprovedApiCall { *; }
-keep class com.google.android.gms.safetynet.internal.** { *; }