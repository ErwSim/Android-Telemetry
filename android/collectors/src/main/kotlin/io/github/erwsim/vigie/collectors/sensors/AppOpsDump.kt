package io.github.erwsim.vigie.collectors.sensors

import android.Manifest
import android.os.Debug
import android.os.ParcelFileDescriptor
import io.github.erwsim.vigie.collectors.R
import io.github.erwsim.vigie.collectors.common.str
import io.github.erwsim.vigie.core.collector.CollectorContext
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.InputStreamReader
import java.util.concurrent.atomic.AtomicBoolean

/**
 * EXPERIMENTAL attribution of camera/microphone use to an app, through the `DUMP` permission
 * (granted by ADB only) and `Debug.dumpService("appops", …, ["--op", OP])`, i.e. the text of
 * `adb shell dumpsys appops --op CAMERA`, which lists the ops currently running per package
 * ("Running start at: …"). The text format is not an API: it may change with any update, and
 * Samsung or SELinux may refuse the dump. On any doubt, nothing is attributed.
 */
object AppOpsDump {
    private const val MAX_BYTES = 2 * 1024 * 1024

    /** Carries the French reason into `agent.collector_error`. */
    class UnavailableException(message: String) : Exception(message)

    private val deniedReported = AtomicBoolean(false)

    /**
     * The system service demands BOTH `DUMP` and `PACKAGE_USAGE_STATS` from the caller
     * (`DumpUtils.checkDumpAndUsageStatsPermission`, AOSP): the missing one, or null.
     */
    fun missingPermission(ctx: CollectorContext): String? = listOf(Manifest.permission.DUMP, Manifest.permission.PACKAGE_USAGE_STATS)
        .firstOrNull { !ctx.capabilities.hasPermission(it) }

    fun available(ctx: CollectorContext): Boolean = missingPermission(ctx) == null

    /** French reason why the attribution cannot work, null if it can. */
    fun unavailableReason(ctx: CollectorContext): String? = when (missingPermission(ctx)) {
        null -> null
        Manifest.permission.DUMP -> ctx.str(R.string.sensor_attribution_reason_dump)
        else -> ctx.str(R.string.sensor_attribution_reason_usage_stats)
    }

    /**
     * Call from `start` of a collector whose attribution setting is on: says so (one `agent.collector_error`
     * per start) instead of silently never attributing.
     */
    fun reportIfUnavailable(ctx: CollectorContext, where: String) {
        unavailableReason(ctx)?.let { ctx.reportError(UnavailableException(it), where) }
    }

    /** True if [text] is the service's refusal (`Permission Denial: can't dump appops …`). */
    fun isDenied(text: String): Boolean = text.contains("Permission Denial")

    /** Package currently running [op] ("CAMERA", "RECORD_AUDIO"), only if exactly one is found. */
    suspend fun runningPackage(ctx: CollectorContext, op: String, timeoutMs: Long = 3_000): String? {
        if (!available(ctx)) return null
        val text = withTimeoutOrNull(timeoutMs) { dump(ctx.io, op) } ?: return null
        if (isDenied(text)) {
            // The permissions looked granted but the service refused: say it once, not at every event.
            if (deniedReported.compareAndSet(false, true)) {
                ctx.reportError(UnavailableException(ctx.str(R.string.sensor_attribution_reason_denied)), "attribution")
            }
            return null
        }
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
