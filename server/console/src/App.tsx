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
const AppSheet = lazy(() => import('./pages/AppSheet.tsx'));
const Detections = lazy(() => import('./pages/Detections.tsx'));
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
        <Loading label="Loading…" />
      </div>
    );
  if (status === 'anon') {
    const from = loc.pathname + loc.search;
    return <Navigate to="/login" replace state={{ from }} />;
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
        <Route path="/login" element={<Login />} />
        <Route element={<Protected />}>
          <Route index element={<Overview />} />
          <Route path="detections" element={<Detections />} />
          <Route path="map" element={<MapPage />} />
          <Route path="events" element={<Events />} />
          <Route path="events/:id" element={<EventDetail />} />
          <Route path="network" element={<Network />} />
          <Route path="tracking" element={<Tracking />} />
          <Route path="apps" element={<Apps />} />
          <Route path="apps/detail" element={<AppSheet />} />
          <Route path="security" element={<Security />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="commands" element={<Commands />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </Suspense>
  );
}
