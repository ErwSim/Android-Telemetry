/** Ce que le serveur peut et ne peut pas faire pour une commande sensible (contrat §8). */
export function ServerLimits({ compact = false }: { compact?: boolean }) {
  if (compact) {
    return (
      <div className="callout callout-info">
        <p>
          <strong>Le serveur ne connaît pas votre code.</strong> Il relaie la commande sans pouvoir la fabriquer ni vérifier la signature : un code faux
          est accepté par le serveur, puis <strong>refusé par le téléphone</strong> (« signature invalide »), ce que vous verrez dans l'historique.
        </p>
      </div>
    );
  }
  return (
    <div className="callout callout-info">
      <p>
        <strong>Ce que le serveur ne peut pas faire sans votre code.</strong> Ces commandes sont signées dans ce navigateur avec un code que le serveur ne
        connaît pas : un serveur compromis pourrait au pire faire sonner le téléphone ou lui demander sa position, mais ni le verrouiller ni l'effacer.
      </p>
      <ul>
        <li>Le code (PBKDF2 puis HMAC-SHA256, par WebCrypto) n'est jamais envoyé ni mémorisé : il vous est redemandé à chaque commande.</li>
        <li>
          Le serveur ne peut pas vérifier le code : il accepte une signature fausse. <strong>Seul le téléphone détecte un code faux</strong> (« Signature
          invalide » dans l'historique).
        </li>
        <li>Après 5 signatures invalides en une heure, le téléphone refuse toute commande sensible pendant une heure.</li>
      </ul>
    </div>
  );
}
