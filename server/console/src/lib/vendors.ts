// Google / Samsung classification of Android packages and DNS names.

export type Vendor = 'google' | 'samsung' | 'other';

export const VENDOR_LABELS: Record<Vendor, string> = {
  google: 'Google',
  samsung: 'Samsung',
  other: 'Others',
};

const GOOGLE_PACKAGES = ['com.google.', 'com.android.vending', 'com.android.chrome', 'com.android.googlesearch', 'android.autoinstalls.config.google'];
const SAMSUNG_PACKAGES = [
  'com.samsung.',
  'com.sec.',
  'com.osp.app.signin',
  'com.knox.',
  'com.samsung.android.',
  'com.sem.',
  'com.monotype.android.font.samsung',
  'flipboard.boxer.app',
];

// Domains (suffixes): Google, Firebase/analytics, CDN and Google platform services; Samsung services.
const GOOGLE_DOMAINS = [
  'google.com',
  'google.fr',
  'googleapis.com',
  'gstatic.com',
  'gvt1.com',
  'gvt2.com',
  'googleusercontent.com',
  'googlesyndication.com',
  'googleadservices.com',
  'googletagmanager.com',
  'google-analytics.com',
  'doubleclick.net',
  'app-measurement.com',
  'firebaseio.com',
  'firebaseinstallations.googleapis.com',
  'crashlytics.com',
  'firebase.com',
  'youtube.com',
  'ytimg.com',
  'ggpht.com',
  'android.com',
  'withgoogle.com',
  'gmail.com',
  'goo.gl',
  '1e100.net',
  'googlevideo.com',
  'app.goo.gl',
];
const SAMSUNG_DOMAINS = [
  'samsung.com',
  'samsungcloud.com',
  'samsungapps.com',
  'samsungdm.com',
  'samsungosp.com',
  'samsungknox.com',
  'samsungqbe.com',
  'samsungelectronics.com',
  'samsungcloudsolution.com',
  'samsungrs.com',
  'samsungotn.net',
  'samsungads.com',
  'samsungiotcloud.com',
  'smartthings.com',
  'galaxyappstore.com',
  'sec.samsung.com',
];

export function classifyPackage(pkg: string | undefined): Vendor {
  if (!pkg) return 'other';
  const p = pkg.toLowerCase();
  if (GOOGLE_PACKAGES.some((g) => (g.endsWith('.') ? p.startsWith(g) : p === g))) return 'google';
  if (SAMSUNG_PACKAGES.some((s) => p.startsWith(s) || p === s)) return 'samsung';
  return 'other';
}

function matchesDomain(host: string, domains: string[]): boolean {
  return domains.some((d) => host === d || host.endsWith(`.${d}`));
}

export function classifyHost(host: string | undefined): Vendor {
  if (!host) return 'other';
  const h = host.toLowerCase().replace(/\.$/, '');
  if (matchesDomain(h, SAMSUNG_DOMAINS)) return 'samsung';
  if (matchesDomain(h, GOOGLE_DOMAINS)) return 'google';
  return 'other';
}
