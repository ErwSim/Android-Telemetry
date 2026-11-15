import { Link } from 'react-router-dom';

export default function NotFound() {
  return (
    <div className="state state-empty">
      <h1>Page introuvable</h1>
      <p>
        <Link to="/">Retour à la vue d'ensemble</Link>
      </p>
    </div>
  );
}
