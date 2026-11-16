// Applications fictives mais plausibles (Galaxy S25+, One UI) pour le serveur factice.

export interface MockApp {
  package: string;
  label: string;
  system: boolean;
  installer?: string;
  version_name: string;
  enabled?: boolean;
  suspended?: boolean;
  hidden?: boolean;
  perms: string[];
  /** noms DNS contactés, avec poids */
  hosts: [string, number][];
  /** poids dans le trafic DNS global (0 = n'émet pas de requêtes) */
  dnsWeight: number;
  /** volume horaire moyen en Mio quand le téléphone est actif */
  mibPerHour: number;
  firstInstallDaysAgo: number;
  lastUpdateDaysAgo: number;
}

const P = (...n: string[]) => n.map((x) => `android.permission.${x}`);
const PLAY = 'com.android.vending';
const GALAXY = 'com.sec.android.app.samsungapps';

export const APPS: MockApp[] = [
  {
    package: 'com.google.android.gms', label: 'Services Google Play', system: true, version_name: '25.44.31', perms: P('ACCESS_FINE_LOCATION', 'ACCESS_BACKGROUND_LOCATION', 'READ_CONTACTS', 'READ_PHONE_STATE', 'CAMERA', 'RECORD_AUDIO', 'POST_NOTIFICATIONS', 'BODY_SENSORS'),
    hosts: [['android.clients.google.com', 5], ['play.googleapis.com', 4], ['app-measurement.com', 5], ['firebaseinstallations.googleapis.com', 3], ['www.googleapis.com', 3], ['mtalk.google.com', 4], ['connectivitycheck.gstatic.com', 6], ['clients4.google.com', 3], ['ogs.google.com', 0.5], ['fcm.googleapis.com', 3], ['update.googleapis.com', 1], ['digitalassetlinks.googleapis.com', 1]],
    dnsWeight: 26, mibPerHour: 7, firstInstallDaysAgo: 400, lastUpdateDaysAgo: 6,
  },
  {
    package: PLAY, label: 'Google Play Store', system: true, version_name: '45.2.18', perms: P('ACCESS_FINE_LOCATION', 'POST_NOTIFICATIONS'),
    hosts: [['play-fe.googleapis.com', 4], ['android.apis.google.com', 2], ['play.googleapis.com', 3], ['play-lh.googleusercontent.com', 3], ['ssl.gstatic.com', 2]],
    dnsWeight: 5, mibPerHour: 4, firstInstallDaysAgo: 400, lastUpdateDaysAgo: 3,
  },
  {
    package: 'com.android.chrome', label: 'Chrome', system: false, installer: PLAY, version_name: '142.0.7444.102', perms: P('CAMERA', 'RECORD_AUDIO', 'ACCESS_FINE_LOCATION', 'POST_NOTIFICATIONS', 'READ_MEDIA_IMAGES'),
    hosts: [['www.lemonde.fr', 3], ['fr.wikipedia.org', 3], ['github.com', 3], ['www.google.com', 5], ['news.ycombinator.com', 2], ['www.leboncoin.fr', 2], ['i.ytimg.com', 2], ['fonts.gstatic.com', 3], ['www.googletagmanager.com', 3], ['pagead2.googlesyndication.com', 2], ['stats.g.doubleclick.net', 2], ['cdn.jsdelivr.net', 2], ['www.service-public.fr', 1], ['www.ameli.fr', 1]],
    dnsWeight: 14, mibPerHour: 28, firstInstallDaysAgo: 380, lastUpdateDaysAgo: 4,
  },
  {
    package: 'com.google.android.youtube', label: 'YouTube', system: false, installer: PLAY, version_name: '20.44.38', perms: P('POST_NOTIFICATIONS', 'RECORD_AUDIO'),
    hosts: [['youtubei.googleapis.com', 4], ['rr2---sn-25ge7nzs.googlevideo.com', 6], ['i.ytimg.com', 4], ['www.youtube.com', 3], ['yt3.ggpht.com', 2], ['s.youtube.com', 2]],
    dnsWeight: 6, mibPerHour: 140, firstInstallDaysAgo: 400, lastUpdateDaysAgo: 5,
  },
  {
    package: 'com.google.android.apps.maps', label: 'Maps', system: false, installer: PLAY, version_name: '11.172.0102', perms: P('ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'ACCESS_BACKGROUND_LOCATION', 'POST_NOTIFICATIONS'),
    hosts: [['maps.googleapis.com', 5], ['khms0.googleapis.com', 4], ['lh3.googleusercontent.com', 2], ['clients3.google.com', 2]],
    dnsWeight: 3, mibPerHour: 12, firstInstallDaysAgo: 400, lastUpdateDaysAgo: 8,
  },
  {
    package: 'com.google.android.gm', label: 'Gmail', system: false, installer: PLAY, version_name: '2025.10.19', perms: P('READ_CONTACTS', 'POST_NOTIFICATIONS', 'READ_CALENDAR'),
    hosts: [['gmail.googleapis.com', 3], ['mail.google.com', 2], ['imap.gmail.com', 1]],
    dnsWeight: 2, mibPerHour: 3, firstInstallDaysAgo: 400, lastUpdateDaysAgo: 12,
  },
  {
    package: 'com.google.android.googlequicksearchbox', label: 'Google', system: true, version_name: '16.40.17', perms: P('RECORD_AUDIO', 'ACCESS_FINE_LOCATION', 'READ_CONTACTS', 'POST_NOTIFICATIONS'),
    hosts: [['www.google.com', 4], ['assistant.google.com', 2], ['encrypted-tbn0.gstatic.com', 3]],
    dnsWeight: 3, mibPerHour: 2, firstInstallDaysAgo: 400, lastUpdateDaysAgo: 5,
  },
  {
    package: 'com.google.android.apps.photos', label: 'Photos', system: false, installer: PLAY, version_name: '7.55.0', perms: P('READ_MEDIA_IMAGES', 'READ_MEDIA_VIDEO', 'POST_NOTIFICATIONS'),
    hosts: [['photos.googleapis.com', 3], ['lh3.googleusercontent.com', 3]],
    dnsWeight: 1.5, mibPerHour: 16, firstInstallDaysAgo: 400, lastUpdateDaysAgo: 9,
  },
  {
    package: 'com.samsung.android.mobileservice', label: 'Samsung Experience Service', system: true, version_name: '14.5.01.2', perms: P('READ_CONTACTS', 'READ_PHONE_STATE', 'ACCESS_FINE_LOCATION', 'READ_CALENDAR', 'POST_NOTIFICATIONS'),
    hosts: [['account.samsung.com', 3], ['eu-api.samsungcloud.com', 4], ['api.samsungcloud.com', 3], ['eu-ie-contact.samsungcloud.com', 2], ['dms.ospserver.net', 2]],
    dnsWeight: 8, mibPerHour: 3, firstInstallDaysAgo: 400, lastUpdateDaysAgo: 14,
  },
  {
    package: 'com.samsung.android.game.gos', label: 'Game Optimizing Service', system: true, version_name: '8.1.01.4', perms: [],
    hosts: [['gos-api.gos-gsp.io', 5], ['gos-config.samsungapps.com', 1]],
    dnsWeight: 2.5, mibPerHour: 0.3, firstInstallDaysAgo: 400, lastUpdateDaysAgo: 30,
  },
  {
    package: 'com.sec.android.diagmonagent', label: 'Diagnostic Monitoring Agent', system: true, version_name: '8.0.00.5', perms: P('READ_PHONE_STATE'),
    hosts: [['diagmon-eu.samsungdm.com', 3], ['dc.diagmon.samsung.com', 2]],
    dnsWeight: 1.5, mibPerHour: 0.2, firstInstallDaysAgo: 400, lastUpdateDaysAgo: 40,
  },
  {
    package: 'com.samsung.android.rubin.app', label: 'Personalization Service', system: true, version_name: '6.0.00.3', perms: P('ACTIVITY_RECOGNITION', 'ACCESS_FINE_LOCATION', 'READ_PHONE_STATE'),
    hosts: [['rubin-eu.samsungapps.com', 3], ['config.samsungads.com', 2]],
    dnsWeight: 2, mibPerHour: 0.3, firstInstallDaysAgo: 400, lastUpdateDaysAgo: 22,
  },
  {
    package: GALAXY, label: 'Galaxy Store', system: true, version_name: '6.8.01.9', perms: P('POST_NOTIFICATIONS', 'READ_PHONE_STATE'),
    hosts: [['vas.samsungapps.com', 3], ['galaxystore.samsung.com', 2], ['img.samsungapps.com', 2]],
    dnsWeight: 1.5, mibPerHour: 1.5, firstInstallDaysAgo: 400, lastUpdateDaysAgo: 20,
  },
  {
    package: 'com.osp.app.signin', label: 'Compte Samsung', system: true, version_name: '15.5.00.4', perms: P('READ_CONTACTS'),
    hosts: [['eu-auth.samsungosp.com', 3], ['account.samsung.com', 2]],
    dnsWeight: 1, mibPerHour: 0.1, firstInstallDaysAgo: 400, lastUpdateDaysAgo: 18,
  },
  {
    package: 'com.whatsapp', label: 'WhatsApp', system: false, installer: PLAY, version_name: '2.25.33.76', perms: P('CAMERA', 'RECORD_AUDIO', 'READ_CONTACTS', 'POST_NOTIFICATIONS', 'READ_MEDIA_IMAGES', 'READ_MEDIA_VIDEO'),
    hosts: [['g.whatsapp.net', 8], ['mmg.whatsapp.net', 4], ['media-cdg4-1.cdn.whatsapp.net', 3], ['graph.facebook.com', 2], ['crashlogs.whatsapp.net', 0.3]],
    dnsWeight: 9, mibPerHour: 18, firstInstallDaysAgo: 380, lastUpdateDaysAgo: 2,
  },
  {
    package: 'org.thoughtcrime.securesms', label: 'Signal', system: false, installer: PLAY, version_name: '7.60.4', perms: P('CAMERA', 'RECORD_AUDIO', 'READ_CONTACTS', 'POST_NOTIFICATIONS'),
    hosts: [['chat.signal.org', 5], ['cdn.signal.org', 2], ['storage.signal.org', 1]],
    dnsWeight: 3, mibPerHour: 3, firstInstallDaysAgo: 300, lastUpdateDaysAgo: 7,
  },
  {
    package: 'com.spotify.music', label: 'Spotify', system: false, installer: PLAY, version_name: '9.0.96.1022', perms: P('POST_NOTIFICATIONS', 'BLUETOOTH_CONNECT'),
    hosts: [['spclient.wg.spotify.com', 4], ['audio-ak-spotify-com.akamaized.net', 5], ['apresolve.spotify.com', 2], ['i.scdn.co', 3]],
    dnsWeight: 5, mibPerHour: 55, firstInstallDaysAgo: 360, lastUpdateDaysAgo: 3,
  },
  {
    package: 'com.facebook.katana', label: 'Facebook', system: false, installer: PLAY, version_name: '521.0.0.54.69', perms: P('ACCESS_FINE_LOCATION', 'READ_CONTACTS', 'CAMERA', 'POST_NOTIFICATIONS'),
    hosts: [['graph.facebook.com', 5], ['edge-mqtt.facebook.com', 3], ['scontent.xx.fbcdn.net', 4], ['connect.facebook.net', 2]],
    dnsWeight: 4, mibPerHour: 20, firstInstallDaysAgo: 300, lastUpdateDaysAgo: 10,
  },
  {
    package: 'com.instagram.android', label: 'Instagram', system: false, installer: PLAY, version_name: '395.0.0.35.74', perms: P('CAMERA', 'RECORD_AUDIO', 'POST_NOTIFICATIONS', 'READ_MEDIA_IMAGES'),
    hosts: [['i.instagram.com', 5], ['graph.instagram.com', 2], ['scontent-cdg4-1.cdninstagram.com', 4]],
    dnsWeight: 4, mibPerHour: 30, firstInstallDaysAgo: 300, lastUpdateDaysAgo: 5,
  },
  {
    package: 'com.boursorama.android.clients', label: 'Boursobank', system: false, installer: PLAY, version_name: '6.8.2', perms: P('CAMERA', 'POST_NOTIFICATIONS'),
    hosts: [['api.boursobank.com', 4], ['clients.boursobank.com', 2], ['static.boursobank.com', 1]],
    dnsWeight: 1, mibPerHour: 1, firstInstallDaysAgo: 250, lastUpdateDaysAgo: 15,
  },
  {
    package: 'com.waze', label: 'Waze', system: false, installer: PLAY, version_name: '5.4.0.2', perms: P('ACCESS_FINE_LOCATION', 'ACCESS_BACKGROUND_LOCATION', 'RECORD_AUDIO', 'POST_NOTIFICATIONS'),
    hosts: [['rt.waze.com', 4], ['routing-server.waze.com', 2], ['tiles.waze.com', 2]],
    dnsWeight: 1.5, mibPerHour: 6, firstInstallDaysAgo: 200, lastUpdateDaysAgo: 25,
  },
  {
    package: 'org.fdroid.fdroid', label: 'F-Droid', system: false, installer: 'com.android.shell', version_name: '1.21.1', perms: P('POST_NOTIFICATIONS'),
    hosts: [['f-droid.org', 3], ['cloudflare.f-droid.org', 2]],
    dnsWeight: 0.4, mibPerHour: 0.5, firstInstallDaysAgo: 120, lastUpdateDaysAgo: 60,
  },
  {
    package: 'com.fastcleaner.pro', label: 'Fast Cleaner Pro', system: false, installer: undefined, version_name: '3.2.1', perms: P('READ_CONTACTS', 'ACCESS_FINE_LOCATION', 'RECORD_AUDIO', 'READ_SMS', 'READ_PHONE_STATE', 'CAMERA'),
    hosts: [['ads.unknown-cdn.biz', 5], ['track.sdkmetrics.cc', 4], ['cfg.fastcleaner-cdn.top', 2]],
    dnsWeight: 1.6, mibPerHour: 2, firstInstallDaysAgo: 5, lastUpdateDaysAgo: 5,
  },
  {
    package: 'io.github.erwsim.watchpost', label: 'Vigie Agent', system: false, installer: 'com.android.shell', version_name: '1.0.0', perms: P('ACCESS_FINE_LOCATION', 'ACCESS_BACKGROUND_LOCATION', 'POST_NOTIFICATIONS', 'READ_PHONE_STATE', 'BLUETOOTH_SCAN'),
    hosts: [['ingest.exemple.fr', 6]],
    dnsWeight: 1.2, mibPerHour: 1.2, firstInstallDaysAgo: 9, lastUpdateDaysAgo: 2,
  },
  {
    package: 'fr.sncf.connect', label: 'SNCF Connect', system: false, installer: PLAY, version_name: '4.31.0', perms: P('ACCESS_FINE_LOCATION', 'POST_NOTIFICATIONS', 'CAMERA'),
    hosts: [['api.sncf-connect.com', 3], ['www.sncf-connect.com', 2]],
    dnsWeight: 0.8, mibPerHour: 2, firstInstallDaysAgo: 200, lastUpdateDaysAgo: 18,
  },
  {
    package: 'com.netflix.mediaclient', label: 'Netflix', system: false, installer: PLAY, version_name: '9.30.1', perms: P('POST_NOTIFICATIONS'),
    hosts: [['api-global.netflix.com', 3], ['ipv4-c001-cdg001-ix.1.oca.nflxvideo.net', 5]],
    dnsWeight: 0.8, mibPerHour: 120, firstInstallDaysAgo: 250, lastUpdateDaysAgo: 11,
  },
];

// Applications sans trafic notable (inventaire seulement).
const quiet = (pkg: string, label: string, extra: Partial<MockApp> = {}): MockApp => ({
  package: pkg, label, system: true, version_name: '1.0.0', perms: [], hosts: [], dnsWeight: 0, mibPerHour: 0,
  firstInstallDaysAgo: 400, lastUpdateDaysAgo: 60, ...extra,
});

export const QUIET_APPS: MockApp[] = [
  quiet('android', 'Système Android', { version_name: '16' }),
  quiet('com.android.settings', 'Paramètres', { version_name: '16' }),
  quiet('com.android.systemui', 'Interface système', { version_name: '16' }),
  quiet('com.android.phone', 'Services de téléphonie', { perms: P('READ_PHONE_STATE', 'CALL_PHONE') }),
  quiet('com.android.bluetooth', 'Bluetooth', { perms: P('BLUETOOTH_CONNECT') }),
  quiet('com.android.providers.contacts', 'Stockage des contacts', { perms: P('READ_CONTACTS') }),
  quiet('com.android.providers.media.module', 'Stockage multimédia', { perms: P('READ_MEDIA_IMAGES', 'READ_MEDIA_VIDEO', 'READ_MEDIA_AUDIO') }),
  quiet('com.android.nfc', 'NFC'),
  quiet('com.samsung.android.dialer', 'Téléphone', { perms: P('CALL_PHONE', 'READ_CALL_LOG', 'READ_CONTACTS', 'READ_PHONE_STATE') }),
  quiet('com.samsung.android.messaging', 'Messages', { perms: P('SEND_SMS', 'READ_SMS', 'RECEIVE_SMS', 'READ_CONTACTS') }),
  quiet('com.samsung.android.contacts', 'Contacts', { perms: P('READ_CONTACTS', 'WRITE_CONTACTS') }),
  quiet('com.sec.android.app.camera', 'Appareil photo', { perms: P('CAMERA', 'RECORD_AUDIO', 'ACCESS_FINE_LOCATION') }),
  quiet('com.sec.android.gallery3d', 'Galerie', { perms: P('READ_MEDIA_IMAGES', 'READ_MEDIA_VIDEO') }),
  quiet('com.sec.android.app.launcher', 'One UI Home'),
  quiet('com.samsung.android.app.galaxyfinder', 'Finder'),
  quiet('com.samsung.android.bixby.agent', 'Bixby', { enabled: false, perms: P('RECORD_AUDIO') }),
  quiet('com.samsung.android.bixby.service', 'Bixby Voice Service', { enabled: false }),
  quiet('com.samsung.android.app.watchmanager', 'Galaxy Wearable', { perms: P('BLUETOOTH_SCAN') }),
  quiet('com.samsung.android.calendar', 'Calendrier Samsung', { perms: P('READ_CALENDAR', 'WRITE_CALENDAR') }),
  quiet('com.sec.android.app.clockpackage', 'Horloge'),
  quiet('com.samsung.android.app.notes', 'Samsung Notes'),
  quiet('com.samsung.android.spay', 'Samsung Wallet', { perms: P('ACCESS_FINE_LOCATION') }),
  quiet('com.samsung.android.game.gamehome', 'Game Launcher', { suspended: true }),
  quiet('com.samsung.android.arzone', 'AR Zone', { enabled: false }),
  quiet('com.samsung.android.aremoji', 'AR Emoji', { enabled: false }),
  quiet('com.sec.android.easyMover', 'Smart Switch', { perms: P('READ_CONTACTS') }),
  quiet('com.samsung.android.scloud', 'Samsung Cloud', { enabled: false }),
  quiet('com.samsung.android.forest', 'Bien-être numérique'),
  quiet('com.samsung.android.app.sharelive', 'Quick Share', { perms: P('BLUETOOTH_SCAN', 'NEARBY_WIFI_DEVICES') }),
  quiet('com.facebook.appmanager', 'Facebook App Manager', { enabled: false }),
  quiet('com.facebook.services', 'Facebook Services', { enabled: false }),
  quiet('com.facebook.system', 'Facebook App Installer', { enabled: false }),
  quiet('com.microsoft.skydrive', 'OneDrive', { system: false, installer: GALAXY, version_name: '7.3', perms: P('READ_MEDIA_IMAGES') }),
  quiet('com.amazon.mShop.android.shopping', 'Amazon', { system: false, installer: PLAY, version_name: '29.20', perms: P('CAMERA', 'POST_NOTIFICATIONS') }),
  quiet('com.google.android.apps.docs', 'Drive', { system: false, installer: PLAY, version_name: '2.25.390', perms: P('READ_MEDIA_IMAGES') }),
  quiet('com.google.android.calendar', 'Agenda Google', { system: false, installer: PLAY, version_name: '2025.40', perms: P('READ_CALENDAR', 'READ_CONTACTS') }),
  quiet('com.google.android.apps.messaging', 'Messages Google', { system: false, installer: PLAY, version_name: '20251013', perms: P('READ_SMS', 'SEND_SMS', 'READ_CONTACTS') }),
  quiet('com.google.android.marvin.talkback', 'Accessibilité Android', { version_name: '15.1' }),
  quiet('com.google.android.packageinstaller', 'Installateur de paquets'),
  quiet('com.google.android.webview', 'Android System WebView', { system: false, installer: PLAY, version_name: '142.0.7444.102' }),
  quiet('com.google.android.tts', 'Synthèse vocale', { system: true, version_name: '15.1' }),
  quiet('com.zhiliaoapp.musically', 'TikTok', { system: false, installer: PLAY, version_name: '37.1', enabled: false, perms: P('CAMERA', 'RECORD_AUDIO') }),
];

export const ALL_APPS: MockApp[] = [...APPS, ...QUIET_APPS];

export const ROUTE_PLACES = {
  home: { lat: 48.8603, lon: 2.379 },
  bastille: { lat: 48.8531, lon: 2.3691 },
  chatelet: { lat: 48.8584, lon: 2.347 },
  concorde: { lat: 48.8656, lon: 2.3212 },
  etoile: { lat: 48.8738, lon: 2.295 },
  ladefense: { lat: 48.8918, lon: 2.2362 },
  lunch: { lat: 48.8935, lon: 2.243 },
  bar: { lat: 48.853, lon: 2.3699 },
  versailles: { lat: 48.8049, lon: 2.1204 },
  rerStop: { lat: 48.8295, lon: 2.2864 },
  park: { lat: 48.8809, lon: 2.3828 },
} as const;
