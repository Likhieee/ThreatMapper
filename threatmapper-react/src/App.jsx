import React, { useState, useEffect, useCallback } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import { useNotifications, NotifContainer } from './components/Notifications';
import { useAPI } from './hooks/useAPI';
import Overview from './pages/Overview';
import ThreatActors from './pages/ThreatActors';
import KnowledgeGraph from './pages/KnowledgeGraph';
import HiddenLinks from './pages/HiddenLinks';
import Predictions from './pages/Predictions';
import Vulnerabilities from './pages/Vulnerabilities';
import IOCHunter from './pages/IOCHunter';
import ActivityLog from './pages/ActivityLog';
import DarkWeb from './pages/DarkWeb';

export default function App() {
  const { notifs, show } = useNotifications();
  const { data: dashData } = useAPI('/dashboard');
  const stats = dashData?.statistics || {};

  return (
    <BrowserRouter>
      <NotifContainer notifs={notifs} onDismiss={id => {}}/>
      <Layout stats={stats}>
        <Routes>
          <Route path="/" element={<Navigate to="/overview" replace/>}/>
          <Route path="/overview" element={<Overview stats={stats}/>}/>
          <Route path="/actors" element={<ThreatActors/>}/>
          <Route path="/graph" element={<KnowledgeGraph/>}/>
          <Route path="/hidden" element={<HiddenLinks/>}/>
          <Route path="/predictions" element={<Predictions/>}/>
          <Route path="/vulns" element={<Vulnerabilities/>}/>
          <Route path="/ioc" element={<IOCHunter/>}/>
          <Route path="/logs" element={<ActivityLog/>}/>
          <Route path="/darkweb" element={<DarkWeb/>}/>
          <Route path="*" element={<Navigate to="/overview" replace/>}/>
        </Routes>
      </Layout>
    </BrowserRouter>
  );
}
