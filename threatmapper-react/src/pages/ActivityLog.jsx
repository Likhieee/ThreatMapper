import React, { useState, useEffect } from 'react';
import { Card, Btn, Tag } from '../components/UI';

const LOGS = [
  {t:'alert',m:'APT28 C2 beacon detected — IP 185.220.x.x flagged in graph'},
  {t:'info',m:'MITRE ATT&CK sync complete — 23 new techniques mapped'},
  {t:'warn',m:'Carbanak lateral movement pattern observed in OTX feed'},
  {t:'info',m:'Neo4j graph updated — 3 new actor relationship nodes added'},
  {t:'alert',m:'Lazarus Group — new cryptocurrency theft TTP observed'},
  {t:'info',m:'AlienVault OTX pulse ingested — FIN7 phishing campaign'},
  {t:'warn',m:'CVE-2024-5678 actively exploited in the wild'},
  {t:'alert',m:'Hidden link: APT41 and Sandworm share Mimikatz variant'},
  {t:'info',m:'Prediction model retrained — accuracy 87.3%'},
  {t:'warn',m:'Indian banking sector risk score elevated to 78%'},
  {t:'alert',m:'OilRig phishing campaign targeting Middle East government'},
  {t:'info',m:'ThreatFox feed ingested — 42 new C2 server IOCs'},
];

const COLORS = {alert:'var(--red)',warn:'var(--yellow)',info:'var(--cyan)'};

export default function ActivityLog() {
  const [logs, setLogs] = useState(() =>
    LOGS.map((l,i) => ({...l, id:i, time:new Date(Date.now()-i*30000).toLocaleTimeString('en-GB',{hour12:false})}))
  );
  const [filter, setFilter] = useState('all');

  useEffect(() => {
    let i = LOGS.length;
    const id = setInterval(() => {
      const l = LOGS[i%LOGS.length];
      setLogs(prev => [{...l, id:Date.now(), time:new Date().toLocaleTimeString('en-GB',{hour12:false})}, ...prev].slice(0,100));
      i++;
    }, 5000);
    return () => clearInterval(id);
  }, []);

  const filtered = filter === 'all' ? logs : logs.filter(l => l.t === filter);
  const icons = {alert:'🚨',warn:'⚠️',info:'ℹ️'};

  return (
    <div style={{padding:20,display:'flex',flexDirection:'column',gap:16,height:'100%',overflow:'hidden'}}>
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',flexShrink:0}}>
        <div>
          <h2 style={{fontFamily:'var(--title)',fontSize:22,fontWeight:800}}>Activity Log</h2>
          <p style={{fontSize:11,color:'var(--text3)',fontFamily:'var(--mono)',marginTop:2}}>Real-time threat intelligence feed</p>
        </div>
        <div style={{display:'flex',gap:4,alignItems:'center'}}>
          <Tag variant='green'>● STREAMING</Tag>
          {['all','alert','warn','info'].map(f => (
            <Btn key={f} active={filter===f} onClick={()=>setFilter(f)}>{f.toUpperCase()}</Btn>
          ))}
        </div>
      </div>
      <Card style={{flex:1,overflow:'hidden',padding:0}}>
        <div style={{overflowY:'auto',height:'100%',padding:12,display:'flex',flexDirection:'column',gap:4}}>
          {filtered.map(log => (
            <div key={log.id} style={{display:'flex',gap:12,padding:'8px 10px',borderRadius:4,
              background:'var(--bg3)',borderLeft:`2px solid ${COLORS[log.t]||'var(--border)'}`}}>
              <span style={{color:'var(--text3)',fontFamily:'var(--mono)',fontSize:10,flexShrink:0,marginTop:1}}>{log.time}</span>
              <span style={{fontSize:12,fontFamily:'var(--mono)',marginRight:6}}>{icons[log.t]}</span>
              <span style={{color:COLORS[log.t]||'var(--text2)',fontSize:11,fontFamily:'var(--mono)'}}>{log.m}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
