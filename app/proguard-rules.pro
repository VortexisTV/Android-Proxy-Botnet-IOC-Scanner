# Keep kotlinx.serialization generated serializers
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers class io.iocscanner.** {
    *** Companion;
}
-keepclasseswithmembers class io.iocscanner.** {
    kotlinx.serialization.KSerializer serializer(...);
}
