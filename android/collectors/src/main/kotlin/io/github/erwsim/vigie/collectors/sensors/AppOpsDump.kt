package io.github.erwsim.vigie.collectors.sensors

import android.Manifest
import android.os.Debug
import android.os.ParcelFileDescriptor
import io.github.erwsim.vigie.core.collector.CollectorContext
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.InputStreamReader

/**
 * EXPERIMENTAL attribution of camera/microphone use to an app, through the `DUMP` permission
 * (granted by ADB only) and `Debug.dumpService("appops", …, ["--op", OP])`, i.e. the text of
 * `adb shell dumpsys appops --op CAMERA`, which lists the ops currently running per package
 * ("Running start at: …"). The text format is not an API: it may change with any update, and
 * Samsung or SELinux may refuse the dump. On any doubt, nothing is attributed.
 */
object AppOpsDump {
    private const val MAX_BYTES = 2 * 1024 * 1024

    fun available(ctx: CollectorContext): Boolean = ctx.capabilities.hasPermission(Manifest.permission.DUMP)

    /** Package currently running [op] ("CAMERA", "RECORD_AUDIO"), only if exactly one is found. */
    suspend fun runningPackage(ctx: CollectorContext, op: String, timeoutMs: Long = 3_000): String? {
        if (!available(ctx)) return null
        val text = withTimeoutOrNull(timeoutMs) { dump(ctx.io, op) } ?: return null
        return parseRunning(text, op, exclude = ctx.appContext.packageName).singleOrNull()
    }

    private suspend fun dump(io: CoroutineDispatcher, op: String): String? = withContext(io) {
        val pipe = ParcelFileDescriptor.createPipe()
        val read = pipe[0]
        val write = pipe[1]
        coroutineScope {
            // Read concurrently: the remote side blocks when the pipe buffer (64 KiB) is full.
            val reader = async(io) {
                ParcelFileDescriptor.AutoCloseInputStream(read).use { input ->
                    val buffer = StringBuilder()
                    val chars = CharArray(8192)
                    InputStreamReader(input, Charsets.UTF_8).use { r ->
                        while (true) {
                            val n = r.read(chars)
                            if (n < 0) break
                            if (buffer.length < MAX_BYTES) buffer.appendRange(chars, 0, n)
                        }
                    }
                    buffer.toString()
                }
            }
            val ok = try {
                Debug.dumpService("appops", write.fileDescriptor, arrayOf("--op", op))
            } catch (_: Exception) {
                false
            } finally {
                write.close()
            }
            val text = reader.await()
            if (ok) text else null
        }
    }

    /**
     * Pure parser of `dumpsys appops` output: packages whose [op] block contains a running
     * marker. Package lines look like `    Package com.example:`, op lines like `      CAMERA (allow):`
     * and a running op carries a `Running start at:` line (or `duration=running` on some builds).
     */
    fun parseRunning(text: String, op: String, exclude: String? = null): List<String> {
        val result = LinkedHashSet<String>()
        var pkg: String? = null
        var pkgIndent = -1
        var inOp = false
        var opIndent = -1
        for (raw in text.lineSequence()) {
            if (raw.isBlank()) continue
            val indent = raw.length - raw.trimStart().length
            val line = raw.trim()
            if (inOp && indent <= opIndent) inOp = false
            if (pkg != null && indent <= pkgIndent) {
                pkg = null
                inOp = false
            }
            when {
                line.startsWith("Package ") && line.endsWith(":") -> {
                    pkg = line.removePrefix("Package ").removeSuffix(":").trim()
                    pkgIndent = indent
                }
                pkg != null && (line.startsWith("$op (") || line.startsWith("$op:")) -> {
                    inOp = true
                    opIndent = indent
                }
                inOp && pkg != null && (line.startsWith("Running start at") || line.contains("duration=running")) -> {
                    result += pkg
                }
            }
        }
        if (exclude != null) result.remove(exclude)
        return result.toList()
    }
}
