# Keep JNI entry points and the callback interface used by the native library.
-keep class com.mirage.vpn.MirageNative { *; }
-keep interface com.mirage.vpn.MirageCallback { *; }
-keep class * implements com.mirage.vpn.MirageCallback { *; }
