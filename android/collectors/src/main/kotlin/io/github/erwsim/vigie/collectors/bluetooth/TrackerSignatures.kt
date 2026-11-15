package io.github.erwsim.vigie.collectors.bluetooth

/**
 * Pure recognition of item trackers from raw BLE advertising data (`ScanRecord.getBytes()`).
 * Signatures (same as the open-source AirGuard project):
 * - Apple Find My, "separated from owner": manufacturer data, company 0x004C, type 0x12, length
 *   0x19. Device type in bits 4-5 of the status byte: 1 = AirTag, others = other Find My
 *   accessories, AirPods or offline Apple devices (reported as `unknown`).
 * - Samsung SmartTag: service data, UUID 0xFD5A.
 * - Tile: service UUID or service data 0xFEED / 0xFEEC.
 * - Google Find My Device network, "unwanted tracking" mode: service data 0xFEAA, frame 0x41
 *   (reported as `unknown`).
 */
object TrackerSignatures {
    const val APPLE_COMPANY_ID = 0x004C
    const val APPLE_FIND_MY_TYPE = 0x12
    const val APPLE_FIND_MY_SEPARATED_LENGTH = 0x19
    const val UUID_SAMSUNG_SMARTTAG = 0xFD5A
    const val UUID_TILE = 0xFEED
    const val UUID_TILE_ALT = 0xFEEC
    const val UUID_GOOGLE_FMDN = 0xFEAA
    const val FMDN_UNWANTED_TRACKING_FRAME = 0x41

    private const val AD_UUID16_PARTIAL = 0x02
    private const val AD_UUID16_COMPLETE = 0x03
    private const val AD_SERVICE_DATA_16 = 0x16
    private const val AD_MANUFACTURER = 0xFF

    /** Parsed advertising payload (only what tracker recognition needs). */
    data class Advertisement(
        val manufacturerData: Map<Int, ByteArray>,
        val serviceData16: Map<Int, ByteArray>,
        val serviceUuids16: Set<Int>,
    )

    /** Parses AD structures (`length, type, data…`); stops at the first malformed one. */
    fun parse(bytes: ByteArray?): Advertisement {
        val manufacturer = HashMap<Int, ByteArray>()
        val serviceData = HashMap<Int, ByteArray>()
        val uuids = HashSet<Int>()
        if (bytes != null) {
            var i = 0
            while (i < bytes.size) {
                val len = bytes[i].toInt() and 0xFF
                // A zero length marks the end of significant data (padding follows).
                if (len == 0 || i + 1 + len > bytes.size) break
                val type = bytes[i + 1].toInt() and 0xFF
                val data = bytes.copyOfRange(i + 2, i + 1 + len)
                when (type) {
                    AD_MANUFACTURER -> if (data.size >= 2) manufacturer[u16(data, 0)] = data.copyOfRange(2, data.size)
                    AD_SERVICE_DATA_16 -> if (data.size >= 2) serviceData[u16(data, 0)] = data.copyOfRange(2, data.size)
                    AD_UUID16_PARTIAL, AD_UUID16_COMPLETE -> {
                        var j = 0
                        while (j + 1 < data.size) {
                            uuids += u16(data, j)
                            j += 2
                        }
                    }
                }
                i += 1 + len
            }
        }
        return Advertisement(manufacturer, serviceData, uuids)
    }

    /** Contract `kind` (`airtag`/`smarttag`/`tile`/`unknown`), or null if not a tracker signature. */
    fun classify(ad: Advertisement): String? {
        ad.manufacturerData[APPLE_COMPANY_ID]?.let { d ->
            if (d.size >= 3 && (d[0].toInt() and 0xFF) == APPLE_FIND_MY_TYPE && (d[1].toInt() and 0xFF) == APPLE_FIND_MY_SEPARATED_LENGTH) {
                val deviceType = (d[2].toInt() and 0x30) shr 4
                return if (deviceType == 1) "airtag" else "unknown"
            }
        }
        if (UUID_SAMSUNG_SMARTTAG in ad.serviceData16) return "smarttag"
        if (UUID_TILE in ad.serviceData16 || UUID_TILE_ALT in ad.serviceData16 ||
            UUID_TILE in ad.serviceUuids16 || UUID_TILE_ALT in ad.serviceUuids16
        ) {
            return "tile"
        }
        ad.serviceData16[UUID_GOOGLE_FMDN]?.let { d ->
            if (d.isNotEmpty() && (d[0].toInt() and 0xFF) == FMDN_UNWANTED_TRACKING_FRAME) return "unknown"
        }
        return null
    }

    fun classify(bytes: ByteArray?): String? = classify(parse(bytes))

    /** 16-bit Bluetooth SIG UUID → full 128-bit string (for ScanFilter). */
    fun uuid16(short: Int): String = "%08x-0000-1000-8000-00805f9b34fb".format(short)

    private fun u16(b: ByteArray, at: Int): Int = (b[at].toInt() and 0xFF) or ((b[at + 1].toInt() and 0xFF) shl 8)
}
