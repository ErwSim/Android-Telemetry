package io.github.erwsim.watchpost.collectors.ops

/**
 * Extracts of `dumpsys appops` written from the AOSP sources (the exact `print` calls of `AppOpsService.dump`,
 * `dumpStatesLocked`, `UidState` dump, `StringDumpVisitor`, `TimeUtils.formatDuration`), with plausible packages
 * and values. None was captured on a device: they check that the parser reads what the code prints, not what
 * a real device prints.
 */
object OpsSamples {
    /** `--history --op SEND_SMS`, Android 14 / 15 / 16 (legacy registry): same layout. */
    val HISTORY_SEND_SMS = """
Current AppOps Service state:

  History:  mode=HISTORICAL_MODE_ENABLED_ACTIVE

    snapshot:
      begin = 1970-01-01 01:00:00.000  (-20408d4h30m10s500ms)
      end = 1970-01-01 01:07:41.220  (-20408d4h22m29s280ms)

      Uid 1001:
        Package com.android.phone:
          Attribution null:
            SEND_SMS:
              [pers-s] = access=4

      Uid u0a284:
        Package com.example.fastsms:
          Attribution null:
            SEND_SMS:
              [bg-s] = access=37
              [fg-s] = access=2

    snapshot:
      begin = 1970-01-01 01:07:41.220  (-20408d4h22m29s280ms)
      end = 1970-01-01 01:37:41.220  (-20408d3h52m29s280ms)

      Uid u0a284:
        Package com.example.fastsms:
          Attribution null:
            SEND_SMS:
              [cch-s] = access=120, reject=3
              [bg-s] = access=11, duration=1s20ms
        Package com.example.fastsms.helper:
          Attribution sync:
            SEND_SMS:
              [fgsvc-s] = access=5
            READ_SMS:
              [fgsvc-s] = access=99

      Uid u0a301:
        Package org.thoughtcrime.sms:
          Attribution null:
            SEND_SMS:
              [top-s] = access=1
              [top-tp] = access=2
            READ_SMS:
              [top-s] = access=8

    snapshot:
      begin = 1970-01-01 01:37:41.220  (-20408d3h52m29s280ms)
      end = 1970-01-01 03:07:41.220  (-20408d2h22m29s280ms)

      Uid u0a999:
        Package com.example.onlyreads:
          Attribution null:
            READ_SMS:
              [fg-s] = access=3
    """.trimIndent()

    /** Same request on a system whose history is stored elsewhere (Android 16 SQLite registry prints no section). */
    val HISTORY_ABSENT_ANDROID16_SQL = """
Current AppOps Service state:

  User restrictions:
    Restricted ops:
      Op: CAMERA
        User: 0
          Restrictions: [com.android.settings]

    """.trimIndent()

    val HISTORY_DISABLED = """
Current AppOps Service state:

  History:  mode=HISTORICAL_MODE_DISABLED

    snapshot:
      begin = 1970-01-01 01:00:00.000  (-20408d4h30m10s500ms)
      end = 1970-01-01 01:07:41.220  (-20408d4h22m29s280ms)
    """.trimIndent()

    /** The history exists but nobody used the op: legitimate, empty result. */
    val HISTORY_EMPTY_FOR_OP = """
Current AppOps Service state:

  History:  mode=HISTORICAL_MODE_ENABLED_ACTIVE

    snapshot:
      begin = 1970-01-01 01:00:00.000  (-20408d4h30m10s500ms)
      end = 1970-01-01 01:07:41.220  (-20408d4h22m29s280ms)

      Uid u0a77:
        Package com.example.reads:
          Attribution null:
            CAMERA:
              [fg-s] = access=2
    Empty
    """.trimIndent()

    val PERMISSION_DENIED = "Permission Denial: can't dump appops from from pid=12345, uid=10456 due to missing android.permission.DUMP permission"
    val PERMISSION_DENIED_USAGE = "Permission Denial: can't dump appops from from pid=12345, uid=10456 due to missing android.permission.PACKAGE_USAGE_STATS permission"
    val UNKNOWN_OPTION = "Unknown option: --history"
    val UNKNOWN_OP = "Error: Unknown operation string: SEND_SMSS"

    /** `--op SEND_SMS` (current state), Android 14/15/16: uid state, uid modes, package op with Access/Reject. */
    val STATE_SEND_SMS = """
Current AppOps Service state:
  Settings:
    top_state_settle_time=5s0ms
    fg_service_state_settle_time=5s0ms
    bg_state_settle_time=1s0ms

  Uid u0a284:
    state=cch
    capability=
    appWidgetVisible=false
      SEND_SMS: mode=ignore
    Package com.example.fastsms:
      SEND_SMS (allow):
        null=[
          Access: [cch-s] 2026-11-16 13:04:05.123 (-5m3s123ms)
          Access: [bg-s] 2026-11-16 12:58:00.000 (-11m8s246ms)
          Reject: [fg-s]2026-11-15 09:00:00.000 (-1d4h4m5s246ms)
        ]
    Package com.example.fastsms.helper:
      SEND_SMS (allow / switch SEND_SMS=allow):
        sync=[
          Access: [fgsvc-s] 2026-11-16 13:08:00.500 (-3s500ms) duration=2s150ms
        ]
        Running start at: -1s200ms
  Uid u0a301:
    state=top
    capability=
    appWidgetVisible=false
    Package org.thoughtcrime.sms:
      SEND_SMS (allow):
        null=[
          Access: [top-s] 2026-11-16 08:00:00.000 (-5h8m5s246ms)
          Access: [top-tp] 2026-11-16 07:00:00.000 (-6h8m5s246ms) proxy[uid=10300, pkg=org.example.proxy, attributionTag=null]
        ]

  Op mode watchers:
    Op SEND_SMS:
      #0: com.android.server.appop.AppOpsService${'$'}ModeCallback@1a2b3c4

  AppOps policy not set.
    """.trimIndent()
}
