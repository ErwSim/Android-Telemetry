package io.github.erwsim.vigie.collectors.ops

import android.os.Debug
import android.os.ParcelFileDescriptor
import io.github.erwsim.vigie.core.collector.CollectorContext
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.io.IOException
import java.io.InputStreamReader

sealed interface DumpResult {
    data class Text(val text: String) : DumpResult

    data class Failed(val failure: OpsFailure, val detail: String? = null) : DumpResult
}

/** The way `dumpsys appops` is run; a fake replaces it in tests. */
interface AppOpsDumpSource {
    suspend fun dump(ctx: CollectorContext, args: List<String>, timeoutMs: Long, maxChars: Int): DumpResult
}

/**
 * `Debug.dumpService("appops", fd, args)` with the `DUMP` permission (granted by ADB): the same text as
 * `adb shell dumpsys appops <args>`. The service also demands `PACKAGE_USAGE_STATS` from the caller
 * (`DumpUtils.checkDumpAndUsageStatsPermission`, AOSP). Not verified on the Samsung (SELinux may refuse).
 *
 * Bounds: [timeoutMs] for the whole dump, [maxChars] of output. The pipe is always drained to its end,
 * even past the bound, otherwise the service would block on a full pipe; an output larger than the bound
 * is reported as truncated, never returned. On a timeout the read end is closed, which makes the service's
 * writes fail instead of blocking forever.
 */
object DebugDumpSource : AppOpsDumpSource {
    override suspend fun dump(ctx: CollectorContext, args: List<String>, timeoutMs: Long, maxChars: Int): DumpResult {
        val pipe = try {
            ParcelFileDescriptor.createPipe()
        } catch (e: IOException) {
            return DumpResult.Failed(OpsFailure.DUMP_FAILED, e.toString())
        }
        val read = pipe[0]
        val write = pipe[1]
        val reader = CompletableDeferred<DumpResult>()
        val writer = CompletableDeferred<Boolean>()
        ctx.scope.launch(ctx.io) {
            reader.complete(readAll(read, maxChars))
        }
        ctx.scope.launch(ctx.io) {
            val ok = try {
                Debug.dumpService("appops", write.fileDescriptor, args.toTypedArray())
            } catch (_: Exception) {
                false
            } finally {
                try {
                    write.close()
                } catch (_: IOException) {
                    // Already closed.
                }
            }
            writer.complete(ok)
        }
        val done = withTimeoutOrNull(timeoutMs) { writer.await() to reader.await() }
        if (done == null) {
            try {
                read.close()
            } catch (_: IOException) {
                // Already closed.
            }
            return DumpResult.Failed(OpsFailure.TIMEOUT)
        }
        val (ok, result) = done
        return if (!ok && (result as? DumpResult.Text)?.text.isNullOrBlank()) DumpResult.Failed(OpsFailure.DUMP_FAILED) else result
    }

    private fun readAll(read: ParcelFileDescriptor, maxChars: Int): DumpResult = try {
        val sb = StringBuilder()
        var truncated = false
        InputStreamReader(ParcelFileDescriptor.AutoCloseInputStream(read), Charsets.UTF_8).use { r ->
            val buffer = CharArray(8192)
            while (true) {
                val n = r.read(buffer)
                if (n < 0) break
                if (!truncated && sb.length + n <= maxChars) sb.appendRange(buffer, 0, n) else truncated = true
            }
        }
        if (truncated) DumpResult.Failed(OpsFailure.TRUNCATED) else DumpResult.Text(sb.toString())
    } catch (e: IOException) {
        DumpResult.Failed(OpsFailure.DUMP_FAILED, e.toString())
    }
}
