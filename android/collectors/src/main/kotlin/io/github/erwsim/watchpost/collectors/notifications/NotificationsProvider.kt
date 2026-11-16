package io.github.erwsim.watchpost.collectors.notifications

import android.content.ContentProvider
import android.content.ContentValues
import android.content.pm.PackageManager
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.Bundle
import android.os.Process
import io.github.erwsim.watchpost.notifier.protocol.BundleValues
import io.github.erwsim.watchpost.notifier.protocol.NotifierProtocol
import io.github.erwsim.watchpost.notifier.protocol.bundleOf

/**
 * Endpoint of the local channel with the companion APK, called with `ContentResolver.call`.
 *
 * Why a provider: a `call` is synchronous, starts the agent's process if it is not running (no
 * background-service start, hence none of the Android 12+ restrictions), needs no binding life
 * cycle, and is protected by `android:permission` (signature level) when the caller acquires the
 * provider. The caller is checked again here ([CallerCheck]): permission held, attributed package
 * and uid are the companion's, signing key identical to ours.
 *
 * `query`/`insert`/`update`/`delete` expose nothing. Nothing is logged (payloads hold third-party
 * content).
 */
class NotificationsProvider : ContentProvider() {
    override fun onCreate(): Boolean = true // The agent is initialised by the Application, after providers.

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        val result = try {
            NotificationsBridge.endpoint.handle(method, BundleValues(extras), callerIsCompanion())
        } catch (_: Exception) {
            NotificationsEndpoint.status(NotifierProtocol.STATUS_INVALID)
        }
        return bundleOf(result)
    }

    private fun callerIsCompanion(): Boolean {
        val context = context ?: return false
        val uid = Binder.getCallingUid()
        val pm = context.packageManager
        return CallerCheck.isCompanion(
            callingPackage = try {
                callingPackage
            } catch (_: SecurityException) {
                null
            },
            packagesForUid = pm.getPackagesForUid(uid),
            holdsPermission = context.checkCallingPermission(NotifierProtocol.PERMISSION) == PackageManager.PERMISSION_GRANTED,
            sameSigningKey = pm.checkSignatures(Process.myUid(), uid) == PackageManager.SIGNATURE_MATCH,
        )
    }

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = null

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0
}
