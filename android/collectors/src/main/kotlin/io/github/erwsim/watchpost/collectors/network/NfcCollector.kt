package io.github.erwsim.watchpost.collectors.network

import android.content.IntentFilter
import android.content.pm.PackageManager
import android.nfc.NfcAdapter
import io.github.erwsim.watchpost.collectors.R
import io.github.erwsim.watchpost.collectors.common.changed
import io.github.erwsim.watchpost.collectors.common.str
import io.github.erwsim.watchpost.core.collector.Availability
import io.github.erwsim.watchpost.core.collector.Collector
import io.github.erwsim.watchpost.core.collector.CollectorContext
import io.github.erwsim.watchpost.core.collector.Requirement

/** `net.nfc`: NFC switched on or off (public broadcast `ACTION_ADAPTER_STATE_CHANGED`, no cost). */
class NfcCollector : Collector {
    override val id = "nfc"
    override val titleRes = R.string.collector_nfc_title
    override val descriptionRes = R.string.collector_nfc_desc
    override val eventTypes = listOf(TYPE)
    override val requirements = listOf(Requirement.SystemFeature(PackageManager.FEATURE_NFC))

    override fun checkAvailability(ctx: CollectorContext): Availability =
        if (NfcAdapter.getDefaultAdapter(ctx.appContext) != null) {
            Availability.Available
        } else {
            Availability.Unavailable(ctx.str(R.string.collector_nfc_unavailable))
        }

    override suspend fun start(ctx: CollectorContext) {
        val adapter = NfcAdapter.getDefaultAdapter(ctx.appContext) ?: return
        report(ctx, adapter.isEnabled)
        // Sent by the NFC service app (uid nfc, not the system server): needs an exported receiver.
        // Protected broadcast: no other app can forge it.
        ctx.registerReceiver(IntentFilter(NfcAdapter.ACTION_ADAPTER_STATE_CHANGED), exported = true) { intent ->
            when (intent.getIntExtra(NfcAdapter.EXTRA_ADAPTER_STATE, -1)) {
                NfcAdapter.STATE_ON -> report(ctx, true)
                NfcAdapter.STATE_OFF -> report(ctx, false)
            }
        }
    }

    private fun report(ctx: CollectorContext, enabled: Boolean) {
        if (ctx.changed("enabled", enabled.toString())) ctx.emit(TYPE) { put("enabled", enabled) }
    }

    companion object {
        const val TYPE = "net.nfc"
    }
}
