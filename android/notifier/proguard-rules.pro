# Watchpost Notifications release shrinking rules (R8).
# The service, the receiver and the activity are kept by the manifest; nothing uses reflection.

# Readable crash reports from the owner's own device.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
