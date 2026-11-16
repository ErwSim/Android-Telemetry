/**
 * Ce que la signature des commandes sensibles garantit, et ses limites (contrat §8, « Ce que la signature garantit,
 * et ses limites », revue de sécurité de la v1.1). Le texte ne promet pas plus que la cryptographie ne tient.
 */
export function ServerLimits({ compact = false }: { compact?: boolean }) {
  if (compact) {
    return (
      <div className="callout callout-info">
        <p>
          <strong>Le serveur ne connaît pas votre code.</strong> Il relaie la commande sans pouvoir la fabriquer ni vérifier la signature : un code faux
          est accepté par le serveur, puis <strong>refusé par le téléphone</strong> (« signature invalide »), ce que vous verrez dans l'historique. Si
          vous soupçonnez le serveur, ne saisissez plus le code ici.
        </p>
      </div>
    );
  }
  return (
    <div className="callout callout-info" data-testid="server-limits">
      <p>
        <strong>Ce que la signature garantit, et ce qu'elle ne garantit pas.</strong> Aucune commande sensible ne s'exécute sans une signature valide pour le
        code défini sur le téléphone, mais cette garantie a des limites :
      </p>
      <ul>
        <li>
          <strong>Le code doit être fort.</strong> Le serveur conserve la commande et sa signature : il peut chercher le code hors ligne, à toute vitesse.
          Seul un code à forte entropie résiste : <strong>cinq mots tirés au hasard</strong>, réservés à cet usage (12 caractères au minimum, et un code trop
          faible est refusé).
        </li>
        <li>
          <strong>Cette page est servie par le serveur.</strong> Un serveur compromis pourrait lire le code à la prochaine saisie, ou le demander sous un faux
          prétexte. Si vous le soupçonnez, <strong>ne saisissez plus le code ici</strong> et changez-le dans l'application du téléphone.
        </li>
        <li>
          <strong>« Annulée » et « expirée » n'engagent que le serveur.</strong> Une commande signée reste exécutable par le téléphone jusqu'à sa date
          d'expiration si une copie existe. <strong>Seul le changement du code dans l'application du téléphone rend caduque une commande déjà signée.</strong>{' '}
          Un effacement n'est donc valable que 15 minutes par défaut (24 heures au plus).
        </li>
        <li>
          Le serveur ne peut pas vérifier le code : il accepte une signature fausse. <strong>Seul le téléphone détecte un code faux</strong> (« Signature
          invalide » dans l'historique). Après 5 signatures invalides en une heure, le téléphone refuse toute commande sensible pendant une heure.
        </li>
        <li>Le code n'est jamais envoyé ni mémorisé par cette page : il vous est redemandé à chaque commande.</li>
      </ul>
    </div>
  );
}
