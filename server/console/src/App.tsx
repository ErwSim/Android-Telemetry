import { lazy, Suspense } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import Layout from './components/Layout.tsx';
import { Loading } from './components/ui.tsx';
import { DeviceProvider } from './state/device.tsx';
import { useAuth } from './state/auth.tsx';
import Login from './pages/Login.tsx';
import NotFound from './pages/NotFound.tsx';

const Overview = lazy(() => import('./pages/Overview.tsx'));
const MapPage = lazy(() => import('./pages/MapPage.tsx'));
const Events = lazy(() => import('./pages/Events.tsx'));
const EventDetail = lazy(() => import('./pages/EventDetail.tsx'));
const Network = lazy(() => import('./pages/Network.tsx'));
const Apps = lazy(() => import('./pages/Apps.tsx'));
const Security = lazy(() => import('./pages/Security.tsx'));
const Alerts = lazy(() => import('./pages/Alerts.tsx'));
const Commands = lazy(() => import('./pages/Commands.tsx'));
const Tracking = lazy(() => import('./pages/Tracking.tsx'));

function Protected() {
  const { status } = useAuth();
  const loc = useLocation();
  if (status === 'loading')
    return (
      <div className="boot">
        <Loading label="Chargement…" />
      </div>
    );
  if (status === 'anon') {
    const from = loc.pathname + loc.search;
    return <Navigate to="/connexion" replace state={{ from }} />;
  }
  return (
    <DeviceProvider>
      <Layout />
    </DeviceProvider>
  );
}

export default function App() {
  return (
    <Suspense
      fallback={
        <div className="boot">
          <Loading />
        </div>
      }
    >
      <Routes>
        <Route path="/connexion" element={<Login />} />
        <Route element={<Protected />}>
          <Route index element={<Overview />} />
          <Route path="carte" element={<MapPage />} />
          <Route path="evenements" element={<Events />} />
          <Route path="evenements/:id" element={<EventDetail />} />
          <Route path="reseau" element={<Network />} />
          <Route path="pistage" element={<Tracking />} />
          <Route path="applications" element={<Apps />} />
          <Route path="securite" element={<Security />} />
          <Route path="alertes" element={<Alerts />} />
          <Route path="commandes" element={<Commands />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </Suspense>
  );
}
