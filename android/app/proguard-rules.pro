# Watchpost release shrinking rules (R8).
# AndroidX (Room, WorkManager), OkHttp and kotlinx-serialization ship their own consumer rules;
# what follows is only what those rules cannot know.

# kotlinx-serialization: our @Serializable classes are always used through their generated
# serializer() (no reflection), keep them as a safety net against over-shrinking.
-keepclassmembers @kotlinx.serialization.Serializable class io.github.erwsim.watchpost.** {
    *** Companion;
    *** INSTANCE;
    kotlinx.serialization.KSerializer serializer(...);
}
-keep,includedescriptorclasses class io.github.erwsim.watchpost.**$$serializer { *; }

# Workers are instantiated by class name by WorkManager (kept by its rules); keep their names
# stable anyway so that work already enqueued before an update still resolves.
-keepnames class * extends androidx.work.ListenableWorker

# Readable crash reports from a device you control.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
