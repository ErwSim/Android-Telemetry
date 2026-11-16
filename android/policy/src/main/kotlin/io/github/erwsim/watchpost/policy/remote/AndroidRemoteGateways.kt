package io.github.erwsim.watchpost.policy.remote

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import io.github.erwsim.watchpost.policy.WatchpostAdminReceiver

/**
 * [LockScreenGateway] on `DevicePolicyManager` (signatures checked against the android-37.0 SDK):
 * - `lockNow()`: "SecurityException if the calling application does not own an active administrator that
 *   uses USES_POLICY_FORCE_LOCK and does not hold the LOCK_DEVICE permission" → `<force-lock/>` declared
 *   in `res/xml/device_admin.xml`;
 * - `setDeviceOwnerLockScreenInfo(admin, info)`: "May be called by the device owner"; null or empty clears
 *   it and the user's own owner info shows again (developer.android.com, DevicePolicyManager).
 */
class AndroidLockScreenGateway(private val context: Context) : LockScreenGateway {
    private val dpm: DevicePolicyManager get() = checkNotNull(context.getSystemService(DevicePolicyManager::class.java)) { "no DevicePolicyManager" }
    private val admin: ComponentName get() = ComponentName(context, WatchpostAdminReceiver::class.java)

    override fun isDeviceOwner(): Boolean = try {
        dpm.isDeviceOwnerApp(context.packageName)
    } catch (_: Exception) {
        false
    }

    override fun lockNow() = dpm.lockNow()

    override fun setLockScreenInfo(info: String?) = dpm.setDeviceOwnerLockScreenInfo(admin, info)

    override fun lockScreenInfo(): String? = try {
        dpm.deviceOwnerLockScreenInfo?.toString()
    } catch (_: Exception) {
        null
    }
}

/**
 * The factory reset, and the only place of the app that calls it.
 *
 * `DevicePolicyManager.wipeDevice(int)` (API 34): "Ask that the device be wiped and factory reset. The
 * calling Device Owner … must have requested USES_POLICY_WIPE_DATA" (`<wipe-data/>` in
 * `device_admin.xml`). Not `wipeData(int)`: for an app targeting API 34+ it throws IllegalStateException
 * when called on the system user, which is where a Device Owner lives (developer.android.com,
 * DevicePolicyManager#wipeData / #wipeDevice).
 *
 * Flags 0: the factory reset protection (Google account) and the eSIM profiles are kept — a thief cannot
 * reuse the phone without the owner's account, and the owner keeps the line.
 *
 * Constructed only by `PolicyModule.registerCommandExecutors`, behind [WipeExecutor] (see `WipeIsolationTest`).
 */
internal class AndroidFactoryReset(private val context: Context) : FactoryReset {
    override fun wipe() {
        val dpm = checkNotNull(context.getSystemService(DevicePolicyManager::class.java)) { "no DevicePolicyManager" }
        dpm.wipeDevice(0)
    }
}
