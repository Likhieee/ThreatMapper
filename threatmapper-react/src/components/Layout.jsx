import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAPI, BACKEND } from '../hooks/useAPI';

const NAV = [
  { id:'overview', label:'Overview', icon:'⊞', badge:'3', badgeColor:'nb-red', section:'COMMAND' },
  { id:'actors', label:'Threat Actors', icon:'👤', badge:'', badgeColor:'nb-red', section:'COMMAND' },
  { id:'graph', label:'Knowledge Graph', icon:'◈', badge:'', section:'COMMAND' },
  { id:'hidden', label:'Hidden Links', icon:'👁', badge:'AI', badgeColor:'nb-cyan', section:'COMMAND' },
  { id:'predictions', label:'Predictions', icon:'📈', badge:'AI', badgeColor:'nb-cyan', section:'COMMAND' },
  { id:'vulns', label:'Vulnerabilities', icon:'🛡', badge:'HIGH', badgeColor:'nb-red', section:'INTEL' },
  { id:'ioc', label:'IOC Hunter', icon:'🔍', badge:'', badgeColor:'nb-yellow', section:'INTEL' },
  { id:'logs', label:'Activity Log', icon:'≡', badge:'LIVE', badgeColor:'nb-green', section:'INTEL' },
  { id:'darkweb', label:'Dark Web Intel', icon:'🌐', badge:'TOR', badgeColor:'nb-purple', section:'INTEL' },
];

const BADGE_COLORS = {
  'nb-red': { bg:'rgba(240,62,62,0.15)', color:'var(--red)', border:'rgba(240,62,62,0.3)' },
  'nb-cyan': { bg:'rgba(34,211,238,0.1)', color:'var(--cyan)', border:'rgba(34,211,238,0.2)' },
  'nb-green': { bg:'rgba(34,197,94,0.1)', color:'var(--green)', border:'rgba(34,197,94,0.2)' },
  'nb-yellow': { bg:'rgba(234,179,8,0.1)', color:'var(--yellow)', border:'rgba(234,179,8,0.2)' },
  'nb-purple': { bg:'rgba(168,85,247,0.1)', color:'var(--purple)', border:'rgba(168,85,247,0.2)' },
};

export default function Layout({ children, stats }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [clock, setClock] = useState('');
  const { data: awsData } = useAPI('/');

  useEffect(() => {
    const tick = () => setClock(new Date().toLocaleTimeString('en-GB', { hour12: false }) + ' UTC');
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  const currentPage = location.pathname.replace('/', '') || 'overview';
  const sections = [...new Set(NAV.map(n => n.section))];

  return (
    <div style={{ display:'grid', gridTemplateColumns:'220px 1fr', gridTemplateRows:'56px 1fr', height:'100vh', overflow:'hidden' }}>

      {/* TOPBAR */}
      <header style={{ gridColumn:'1/3', display:'flex', alignItems:'center', justifyContent:'space-between',
        padding:'0 20px', background:'var(--bg2)', borderBottom:'1px solid var(--border)', zIndex:100 }}>
        
        <div style={{ display:'flex', alignItems:'center', gap:10 }}>
          <div style={{ width:32, height:32, background:'linear-gradient(135deg,var(--red),var(--purple))',
            borderRadius:8, display:'flex', alignItems:'center', justifyContent:'center', fontSize:14 }}>🛡</div>
          <div>
            <div style={{ fontFamily:'var(--title)', fontSize:16, fontWeight:800, letterSpacing:1,
              background:'linear-gradient(90deg,var(--red2),var(--purple))', WebkitBackgroundClip:'text', WebkitTextFillColor:'transparent' }}>
              THREATMAPPER
            </div>
            <div style={{ fontSize:9, color:'var(--text3)', fontFamily:'var(--mono)', letterSpacing:2 }}>AI-OSINT INTELLIGENCE ENGINE</div>
          </div>
        </div>

        <div style={{ display:'flex', gap:24, alignItems:'center' }}>
          {[
            { val: stats?.ThreatActors, lbl: 'ACTORS', color: 'var(--cyan)' },
            { val: stats?.Malware, lbl: 'MALWARE', color: 'var(--red)' },
            { val: stats?.IOCs, lbl: 'IOCs', color: 'var(--purple)' },
            { val: stats?.CVEs, lbl: 'CVEs', color: 'var(--orange)' },
          ].map((s,i) => (
            <div key={i} style={{ textAlign:'center' }}>
              <div style={{ fontFamily:'var(--title)', fontSize:18, fontWeight:800, color:s.color }}>{s.val?.toLocaleString()??'—'}</div>
              <div style={{ fontSize:9, color:'var(--text3)', fontFamily:'var(--mono)', letterSpacing:1 }}>{s.lbl}</div>
            </div>
          ))}
        </div>

        <div style={{ display:'flex', alignItems:'center', gap:12 }}>
          <div style={{ background:'rgba(240,62,62,0.1)', border:'1px solid rgba(240,62,62,0.3)',
            padding:'4px 10px', borderRadius:4, fontSize:10, color:'var(--red)', fontFamily:'var(--mono)', letterSpacing:1 }}>
            ⚠ THREAT LEVEL: CRITICAL
          </div>
          <div style={{ display:'flex', alignItems:'center', gap:6, background:'rgba(34,197,94,0.1)',
            border:'1px solid rgba(34,197,94,0.3)', padding:'4px 10px', borderRadius:4,
            fontSize:10, color:'var(--green)', fontFamily:'var(--mono)' }}>
            <span style={{ width:6, height:6, borderRadius:'50%', background:'var(--green)',
              animation:'pulse 2s infinite', boxShadow:'0 0 6px var(--green)', display:'block' }}/>
            LIVE
          </div>
          <div style={{ fontFamily:'var(--mono)', fontSize:12, color:'var(--text3)' }}>{clock}</div>
        </div>
      </header>

      {/* SIDEBAR */}
      <nav style={{ background:'var(--bg2)', borderRight:'1px solid var(--border)',
        padding:'16px 0', display:'flex', flexDirection:'column', overflowY:'auto' }}>
        
        {sections.map(section => (
          <div key={section} style={{ padding:'0 12px', marginBottom:4 }}>
            <div style={{ fontSize:9, color:'var(--text3)', fontFamily:'var(--mono)',
              letterSpacing:2, padding:'8px 8px 4px', textTransform:'uppercase' }}>{section}</div>
            {NAV.filter(n => n.section === section).map(item => {
              const isActive = currentPage === item.id;
              const bc = item.badgeColor ? BADGE_COLORS[item.badgeColor] : null;
              return (
                <div key={item.id}
                  onClick={() => navigate('/'+item.id)}
                  style={{ display:'flex', alignItems:'center', gap:10, padding:'8px 10px',
                    borderRadius:6, cursor:'pointer', transition:'all 0.15s', margin:'1px 0',
                    fontSize:13, color: isActive ? 'var(--red2)' : 'var(--text2)',
                    background: isActive ? 'var(--redglow)' : 'transparent',
                    border: `1px solid ${isActive ? 'rgba(240,62,62,0.2)' : 'transparent'}` }}>
                  <span style={{ fontSize:14 }}>{item.icon}</span>
                  <span>{item.label}</span>
                  {item.badge && bc && (
                    <span style={{ marginLeft:'auto', fontSize:9, fontFamily:'var(--mono)',
                      padding:'2px 6px', borderRadius:3, letterSpacing:1,
                      background:bc.bg, color:bc.color, border:`1px solid ${bc.border}` }}>
                      {item.badge}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        ))}

        <div style={{ marginTop:'auto', padding:12, borderTop:'1px solid var(--border)' }}>
          {[
            { key:'NEO4J', ok:!!stats },
            { key:'ML MODEL', ok:true },
            { key:'AWS API', ok:!!awsData },
            { key:'SCRAPER', ok:true },
          ].map(s => (
            <div key={s.key} style={{ display:'flex', justifyContent:'space-between',
              alignItems:'center', padding:'4px 0', fontSize:10, fontFamily:'var(--mono)' }}>
              <span style={{ color:'var(--text3)' }}>{s.key}</span>
              <span style={{ color: s.ok ? 'var(--green)' : 'var(--red)' }}>
                {s.ok ? '● ONLINE' : '● OFFLINE'}
              </span>
            </div>
          ))}
        </div>
      </nav>

      {/* MAIN */}
      <main style={{ overflow:'hidden', display:'flex', flexDirection:'column', background:'var(--bg)' }}>
        {children}
      </main>

      <style>{`@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}`}</style>
    </div>
  );
}
