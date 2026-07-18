import React, { useState, useEffect, useCallback } from 'react';

const MSGS = [
  {m:'APT28 C2 infrastructure detected — 3 new IOCs',t:'alert'},
  {m:'Knowledge graph updated — 12 new relationships',t:'info'},
  {m:'Lazarus Group targeting banking sector',t:'alert'},
  {m:'CVE-2024-3821 added to CISA KEV database',t:'warn'},
  {m:'Hidden link: APT29 ↔ Sandworm share X-Agent',t:'alert'},
  {m:'OTX sync complete — 847 new IOCs ingested',t:'info'},
  {m:'Prediction model updated — 87.3% accuracy',t:'info'},
  {m:'FIN7 new TTP — supply chain vector observed',t:'warn'},
];

export function useNotifications() {
  const [notifs, setNotifs] = useState([]);
  const show = useCallback((msg, type='info') => {
    const id = Date.now();
    setNotifs(p => [{id, msg, type, time: new Date().toLocaleTimeString('en-GB',{hour12:false})}, ...p].slice(0,5));
    setTimeout(() => setNotifs(p => p.filter(n => n.id !== id)), 6000);
  }, []);
  useEffect(() => {
    show('ThreatMapper online — Neo4j Aura connected', 'ok');
    let i = 0;
    const schedule = () => setTimeout(() => { show(MSGS[i%MSGS.length].m, MSGS[i%MSGS.length].t); i++; schedule(); }, 18000+Math.random()*15000);
    schedule();
  }, [show]);
  return { notifs, show };
}

const COLORS = {
  alert:{bg:'rgba(240,62,62,0.12)',border:'var(--red)',color:'var(--red2)',icon:'🚨'},
  warn:{bg:'rgba(234,179,8,0.1)',border:'var(--yellow)',color:'var(--yellow)',icon:'⚠️'},
  info:{bg:'rgba(34,211,238,0.08)',border:'var(--cyan)',color:'var(--cyan2)',icon:'ℹ️'},
  ok:{bg:'rgba(34,197,94,0.08)',border:'var(--green)',color:'var(--green)',icon:'✅'},
};

export function NotifContainer({ notifs, onDismiss }) {
  return (
    <div style={{position:'fixed',top:64,right:16,zIndex:9999,display:'flex',flexDirection:'column',gap:8,maxWidth:360,pointerEvents:'none'}}>
      {notifs.map(n => {
        const c = COLORS[n.type] || COLORS.info;
        return (
          <div key={n.id} onClick={() => onDismiss(n.id)}
            style={{padding:'12px 14px',borderRadius:6,fontSize:11,fontFamily:'var(--mono)',
              borderLeft:`3px solid ${c.border}`,background:c.bg,color:c.color,
              pointerEvents:'auto',cursor:'pointer',backdropFilter:'blur(12px)',
              animation:'nIn 0.3s ease'}}>
            <div style={{fontSize:9,opacity:0.6,marginBottom:4}}>{c.icon} {n.time}</div>
            {n.msg}
          </div>
        );
      })}
      <style>{`@keyframes nIn{from{opacity:0;transform:translateX(16px)}to{opacity:1;transform:none}}`}</style>
    </div>
  );
}
