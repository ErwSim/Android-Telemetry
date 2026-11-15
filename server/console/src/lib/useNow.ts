import { useEffect, useState } from 'react';

/** Date courante rafraîchie périodiquement (clés de requêtes « dernières 24 h »). */
export function useNow(intervalMs = 60_000): Date {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const t = window.setInterval(() => setNow(new Date()), intervalMs);
    return () => window.clearInterval(t);
  }, [intervalMs]);
  return now;
}
