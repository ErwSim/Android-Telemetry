/**
 * What the signature of sensitive commands guarantees, and its limits (contract §8, "What the signature guarantees,
 * and its limits"). The text does not promise more than the cryptography holds.
 */
export function ServerLimits({ compact = false }: { compact?: boolean }) {
  if (compact) {
    return (
      <div className="callout callout-info">
        <p>
          <strong>The server does not know your passphrase.</strong> It relays the command without being able to forge it or verify the signature: a wrong
          passphrase is accepted by the server, then <strong>refused by the phone</strong> ("invalid signature"), which you will see in the history. If
          you suspect the server, do not enter the passphrase here any more.
        </p>
      </div>
    );
  }
  return (
    <div className="callout callout-info" data-testid="server-limits">
      <p>
        <strong>What the signature guarantees, and what it does not.</strong> No sensitive command runs without a valid signature for the
        passphrase set on the phone, but this guarantee has limits:
      </p>
      <ul>
        <li>
          <strong>The passphrase must be strong.</strong> The server keeps the command and its signature: it can search for the passphrase offline, at full speed.
          Only a high-entropy passphrase holds up: <strong>five randomly chosen words</strong>, reserved for this use (12 characters at minimum, and a passphrase
          that is too weak is refused).
        </li>
        <li>
          <strong>This page is served by the server.</strong> A compromised server could read the passphrase at the next entry, or ask for it under a false
          pretext. If you suspect it, <strong>do not enter the passphrase here any more</strong> and change it in the phone app.
        </li>
        <li>
          <strong>"Cancelled" and "expired" only commit the server.</strong> A signed command remains executable by the phone until its expiry
          date if a copy exists. <strong>Only changing the passphrase in the phone app makes an already signed command void.</strong>{' '}
          An erase is therefore only valid for 15 minutes by default (24 hours at most).
        </li>
        <li>
          The server cannot verify the passphrase: it accepts a wrong signature. <strong>Only the phone detects a wrong passphrase</strong> ("Invalid
          signature" in the history). After 5 invalid signatures within an hour, the phone refuses every sensitive command for an hour.
        </li>
        <li>The passphrase is never sent or remembered by this page: you are asked for it again with every command.</li>
      </ul>
    </div>
  );
}
