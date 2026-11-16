import { Link } from 'react-router-dom';

export default function NotFound() {
  return (
    <div className="state state-empty">
      <h1>Page not found</h1>
      <p>
        <Link to="/">Back to the Overview</Link>
      </p>
    </div>
  );
}
