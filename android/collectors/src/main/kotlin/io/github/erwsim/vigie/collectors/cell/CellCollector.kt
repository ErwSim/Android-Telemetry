package io.github.erwsim.vigie.collectors.cell

import android.Manifest
import android.annotation.SuppressLint
import android.content.pm.PackageManager
import android.telephony.AccessNetworkConstants
import android.telephony.CellIdentityNr
import android.telephony.CellInfo
import android.telephony.CellInfoCdma
import android.telephony.CellInfoGsm
import android.telephony.CellInfoLte
import android.telephony.CellInfoNr
import android.telephony.CellInfoTdscdma
import android.telephony.CellInfoWcdma
import android.telephony.NetworkRegistrationInfo
import android.telephony.ServiceState
import android.telephony.TelephonyCallback
import android.telephony.TelephonyManager
import androidx.core.content.edit
import io.github.erwsim.vigie.collectors.R
import io.github.erwsim.vigie.core.collector.Collector
import io.github.erwsim.vigie.core.collector.CollectorContext
import io.github.erwsim.vigie.core.collector.Requirement
import io.github.erwsim.vigie.core.event.Severity

/**
 * `net.cell` (serving cell: technology, MCC/MNC, TAC, cell id, PCI, band, signal, roaming,
 * operator) and `net.cell_security` (`downgrade_2g`).
 *
 * TelephonyCallback only (ServiceState + CellInfo, no SignalStrength listener, no polling). An
 * event when the serving cell or technology changes, at most one per 20 s for cell changes
 * (technology, network and roaming changes always pass). Without precise location, cell
 * identities are hidden by the system: only the technology, operator and roaming are reported,
 * and 2G detection keeps working (it reads the registration state, not the cell).
 *
 * Not detectable without system privileges: null ciphering and identifier disclosure (Android
 * 15+ "cellular network security" APIs are system APIs).
 */
class CellCollector : Collector {
    override val id = "cell"
    override val titleRes = R.string.collector_cell_title
    override val descriptionRes = R.string.collector_cell_desc
    override val eventTypes = listOf(TYPE_CELL, TYPE_SECURITY)
    override val requirements = listOf(
        Requirement.SystemFeature(PackageManager.FEATURE_TELEPHONY_RADIO_ACCESS),
        Requirement.Permission(Manifest.permission.ACCESS_FINE_LOCATION, optional = true),
    )

    // Collectors' thread state, reset at each start.
    private var registrations: List<CellLogic.Registration>? = null
    private var roaming: Boolean? = null
    private var operatorName: String? = null
    private var operatorNumeric: String? = null
    private var serving: CellLogic.ServingCell? = null
    private val filter = CellLogic.ChangeFilter()
    private val downgrade = CellLogic.DowngradeDetector()

    @SuppressLint("MissingPermission") // CellInfo is only requested when ACCESS_FINE_LOCATION is granted.
    override suspend fun start(ctx: CollectorContext) {
        registrations = null
        roaming = null
        serving = null
        filter.reset()
        downgrade.lastTech = ctx.prefs.getString("last_tech", null)
        downgrade.lastAlertMs = ctx.prefs.getLong("last_alert_ms", Long.MIN_VALUE / 2)
        val tm = ctx.appContext.getSystemService(TelephonyManager::class.java) ?: return
        val fine = ctx.capabilities.hasPermission(Manifest.permission.ACCESS_FINE_LOCATION)

        val callback: TelephonyCallback = if (fine) {
            object : TelephonyCallback(), TelephonyCallback.ServiceStateListener, TelephonyCallback.CellInfoListener {
                override fun onServiceStateChanged(ss: ServiceState) = onServiceState(ctx, tm, ss)
                override fun onCellInfoChanged(cells: MutableList<CellInfo>) = onCells(ctx, cells)
            }
        } else {
            object : TelephonyCallback(), TelephonyCallback.ServiceStateListener {
                override fun onServiceStateChanged(ss: ServiceState) = onServiceState(ctx, tm, ss)
            }
        }
        tm.registerTelephonyCallback(ctx.executor, callback)
        ctx.onStop { tm.unregisterTelephonyCallback(callback) }
        if (fine) {
            try {
                tm.allCellInfo?.let { onCells(ctx, it) }
            } catch (_: SecurityException) {
                // Location switched off or permission just revoked: identities stay absent.
            }
        }
    }

    override suspend fun stop(ctx: CollectorContext) {
        registrations = null
        serving = null
    }

    // ServiceState operator getters are annotated with location permissions: they return null
    // (sanitized copy) without them, they never throw. TelephonyManager is the fallback.
    @SuppressLint("MissingPermission")
    private fun onServiceState(ctx: CollectorContext, tm: TelephonyManager, ss: ServiceState) = ctx.guard("service state") {
        registrations = ss.networkRegistrationInfoList
            .filter { it.transportType == AccessNetworkConstants.TRANSPORT_TYPE_WWAN && it.isNetworkRegistered }
            .map {
                CellLogic.Registration(
                    packetSwitched = it.domain and NetworkRegistrationInfo.DOMAIN_PS != 0,
                    circuitSwitched = it.domain and NetworkRegistrationInfo.DOMAIN_CS != 0,
                    tech = CellLogic.techName(it.accessNetworkTechnology),
                    roaming = it.isNetworkRoaming,
                )
            }
        roaming = if (ss.state == ServiceState.STATE_IN_SERVICE) ss.roaming else null
        // Sanitized without location permission; TelephonyManager has the registered operator.
        operatorName = ss.operatorAlphaLong ?: guarded { tm.networkOperatorName }
        operatorNumeric = ss.operatorNumeric ?: guarded { tm.networkOperator }
        publish(ctx)
    }

    private fun onCells(ctx: CollectorContext, cells: List<CellInfo>) = ctx.guard("cell info") {
        serving = cells.filter { it.isRegistered }.mapNotNull(::toServing).maxByOrNull { CellLogic.generation(it.tech) }
        publish(ctx)
    }

    private inline fun guarded(block: () -> String?): String? = try {
        block()?.takeIf { it.isNotBlank() }
    } catch (_: SecurityException) {
        null
    }

    private fun publish(ctx: CollectorContext) {
        if (registrations == null && serving == null) return
        val snapshot = CellLogic.snapshot(registrations, serving, roaming, operatorName, operatorNumeric)
        val now = ctx.clock.nowMillis()
        if (filter.offer(snapshot, ctx.clock.elapsedRealtime())) {
            ctx.emit(TYPE_CELL) { snapshot.writeTo(this, serving?.takeIf { it.tech == snapshot.tech }?.signalDbm) }
        }
        val tech2g = CellLogic.tech2g(registrations, serving)
        val before = downgrade.lastTech
        val alert = downgrade.onState(snapshot.tech, tech2g, now)
        if (alert != null) {
            ctx.sink.emit(TYPE_SECURITY, Severity.WARNING, CellLogic.downgradeData(alert, snapshot))
            ctx.prefs.edit { putLong("last_alert_ms", now) }
        }
        if (downgrade.lastTech != before) ctx.prefs.edit { putString("last_tech", downgrade.lastTech) }
    }

    @Suppress("DEPRECATION") // CellInfoCdma: still reported by some networks abroad.
    private fun toServing(info: CellInfo): CellLogic.ServingCell? {
        val signal = CellLogic.dbm(info.cellSignalStrength.dbm)
        return when (info) {
            is CellInfoLte -> info.cellIdentity.let { id ->
                CellLogic.ServingCell(
                    "lte", id.mccString, id.mncString, CellLogic.valid(id.tac), CellLogic.valid(id.ci)?.toLong(),
                    CellLogic.valid(id.pci), id.bands.firstOrNull(), signal, id.operatorAlphaLong?.toString(),
                )
            }
            is CellInfoNr -> (info.cellIdentity as? CellIdentityNr)?.let { id ->
                CellLogic.ServingCell(
                    "nr", id.mccString, id.mncString, CellLogic.valid(id.tac), CellLogic.valid(id.nci),
                    CellLogic.valid(id.pci), id.bands.firstOrNull(), signal, id.operatorAlphaLong?.toString(),
                )
            }
            is CellInfoGsm -> info.cellIdentity.let { id ->
                CellLogic.ServingCell(
                    "gsm", id.mccString, id.mncString, CellLogic.valid(id.lac), CellLogic.valid(id.cid)?.toLong(),
                    null, null, signal, id.operatorAlphaLong?.toString(),
                )
            }
            is CellInfoWcdma -> info.cellIdentity.let { id ->
                CellLogic.ServingCell(
                    "umts", id.mccString, id.mncString, CellLogic.valid(id.lac), CellLogic.valid(id.cid)?.toLong(),
                    null, null, signal, id.operatorAlphaLong?.toString(),
                )
            }
            is CellInfoTdscdma -> info.cellIdentity.let { id ->
                CellLogic.ServingCell(
                    "td_scdma", id.mccString, id.mncString, CellLogic.valid(id.lac), CellLogic.valid(id.cid)?.toLong(),
                    null, null, signal, id.operatorAlphaLong?.toString(),
                )
            }
            is CellInfoCdma -> CellLogic.ServingCell("cdma", signalDbm = signal)
            else -> null
        }
    }

    companion object {
        const val TYPE_CELL = "net.cell"
        const val TYPE_SECURITY = "net.cell_security"
    }
}
