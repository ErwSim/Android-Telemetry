package io.github.erwsim.vigie.collectors.network

import android.net.NetworkCapabilities
import android.net.wifi.ScanResult
import android.net.wifi.WifiInfo

/** Pure formatting of network values into contract words; placeholder values become null (absent). */
object NetFormat {
    /** Placeholder returned by WifiInfo/ScanResult when the SSID is redacted (no location access). */
    const val UNKNOWN_SSID = "<unknown ssid>"

    /** MAC address returned when the real one is hidden. */
    private val PLACEHOLDER_MACS = setOf("02:00:00:00:00:00", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff")
    private val MAC_REGEX = Regex("^([0-9a-f]{2}:){5}[0-9a-f]{2}$")

    /** Removes the surrounding quotes of a UTF-8 SSID; null for empty/redacted values. Hex SSIDs are kept. */
    fun ssid(raw: String?): String? {
        val s = raw?.trim() ?: return null
        if (s.isEmpty() || s == UNKNOWN_SSID) return null
        val unquoted = if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) s.substring(1, s.length - 1) else s
        return unquoted.takeIf { it.isNotEmpty() && it != UNKNOWN_SSID }
    }

    /** Lowercase `aa:bb:…` MAC, null for placeholders and malformed values. */
    fun mac(raw: String?): String? {
        val m = raw?.trim()?.lowercase() ?: return null
        if (!MAC_REGEX.matches(m) || m in PLACEHOLDER_MACS) return null
        return m
    }

    /** WifiInfo.INVALID_RSSI is -127; anything outside a plausible range is dropped. */
    fun rssi(value: Int): Int? = value.takeIf { it in -126..0 }

    fun frequency(mhz: Int): Int? = mhz.takeIf { it > 0 }

    fun securityName(type: Int): String? = when (type) {
        WifiInfo.SECURITY_TYPE_OPEN -> "open"
        WifiInfo.SECURITY_TYPE_WEP -> "wep"
        WifiInfo.SECURITY_TYPE_PSK -> "psk"
        WifiInfo.SECURITY_TYPE_EAP -> "eap"
        WifiInfo.SECURITY_TYPE_SAE -> "sae"
        WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE_192_BIT -> "eap_wpa3_enterprise_192"
        WifiInfo.SECURITY_TYPE_OWE -> "owe"
        WifiInfo.SECURITY_TYPE_WAPI_PSK -> "wapi_psk"
        WifiInfo.SECURITY_TYPE_WAPI_CERT -> "wapi_cert"
        WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE -> "eap_wpa3_enterprise"
        WifiInfo.SECURITY_TYPE_OSEN -> "osen"
        WifiInfo.SECURITY_TYPE_PASSPOINT_R1_R2 -> "passpoint_r1_r2"
        WifiInfo.SECURITY_TYPE_PASSPOINT_R3 -> "passpoint_r3"
        WifiInfo.SECURITY_TYPE_DPP -> "dpp"
        else -> null
    }

    /** Weakest first: used to report the strongest security an access point offers. */
    private val SECURITY_RANK = listOf(
        "open", "owe", "wep", "wapi_psk", "psk", "sae", "osen", "wapi_cert", "eap", "passpoint_r1_r2",
        "passpoint_r3", "dpp", "eap_wpa3_enterprise", "eap_wpa3_enterprise_192",
    )

    fun strongestSecurity(types: IntArray?): String? =
        types?.toList()?.mapNotNull(::securityName)?.maxByOrNull { SECURITY_RANK.indexOf(it) }

    fun standardName(standard: Int): String? = when (standard) {
        ScanResult.WIFI_STANDARD_LEGACY -> "legacy"
        ScanResult.WIFI_STANDARD_11N -> "11n"
        ScanResult.WIFI_STANDARD_11AC -> "11ac"
        ScanResult.WIFI_STANDARD_11AX -> "11ax"
        ScanResult.WIFI_STANDARD_11AD -> "11ad"
        ScanResult.WIFI_STANDARD_11BE -> "11be"
        else -> null
    }

    /** Contract words for `net.connectivity.transports` (plus a few extra transports, same style). */
    val TRANSPORTS = linkedMapOf(
        NetworkCapabilities.TRANSPORT_WIFI to "wifi",
        NetworkCapabilities.TRANSPORT_CELLULAR to "cellular",
        NetworkCapabilities.TRANSPORT_VPN to "vpn",
        NetworkCapabilities.TRANSPORT_ETHERNET to "ethernet",
        NetworkCapabilities.TRANSPORT_BLUETOOTH to "bluetooth",
        NetworkCapabilities.TRANSPORT_USB to "usb",
        NetworkCapabilities.TRANSPORT_WIFI_AWARE to "wifi_aware",
        NetworkCapabilities.TRANSPORT_LOWPAN to "lowpan",
        NetworkCapabilities.TRANSPORT_THREAD to "thread",
        NetworkCapabilities.TRANSPORT_SATELLITE to "satellite",
    )

    fun transportNames(has: (Int) -> Boolean): List<String> = TRANSPORTS.filterKeys(has).values.toList()
}
