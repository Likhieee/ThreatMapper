import React, { useEffect, useState } from 'react';
import { useAPI } from '../hooks/useAPI';
import { Card, MetricCard, Loading, ProgressBar, Tag } from '../components/UI';

const SECTORS = [
  {name:'Financial Services',risk:92,color:'var(--red)'},
  {name:'Healthcare',risk:87,color:'var(--red)'},
  {name:'Energy / Utilities',risk:84,color:'var(--orange)'},
  {name:'Defense Contractors',risk:80,color:'var(--orange)'},
  {name:'Government',risk:74,color:'var(--yellow)'},
  {name:'Telecommunications',risk:67,color:'var(--yellow)'},
  {name:'Technology',risk:55,color:'var(--green)'},
];

const FEED = [
  {t:'alert',m:'APT28 C2 beacon — IP 185.220.x.x flagged'},
  {t:'info',m:'Neo4j graph updated — 3 new relationships'},
  {t:'warn',m:'Carbanak lateral movement pattern observed'},
  {t:'alert',m:'Lazarus Group — new crypto theft TTP'},
  {t:'info',m:'OTX pulse ingested — FIN7 campaign'},
  {t:'warn',m:'CVE-2024-5678 actively exploited'},
  {t:'alert',m:'Hidden link: APT41 ↔ Sandworm share tools'},
  {t:'info',m:'Prediction model retrained — 87.3% acc'},
];

export default function Overview({ stats }) {
  const { data: topActors, loading: la } = useAPI('/top-threat-actors');
  const { data: topMalware, loading: lm } = useAPI('/top-malware');
  const [feed, setFeed] = useState(FEED.slice(0,5));
  const [idx, setIdx] = useState(5);

  useEffect(() => {
    const id = setInterval(() => {
      setFeed(f => [{t:FEED[idx%FEED.length].t, m:FEED[idx%FEED.length].m, time:new Date().toLocaleTimeString('en-GB',{hour12:false})}, ...f].slice(0,8));
      setIdx(i => i+1);
    }, 4000);
    return () => clearInterval(id);
  }, [idx]);

  const feedColor = {alert:'var(--red)',warn:'var(--yellow)',info:'var(--cyan)'};

  return (
    <div style={{padding:20,display:'flex',flexDirection:'column',gap:16,overflowY:'auto',height:'100%'}}>
      {/* Metrics */}
      <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:16}}>
        <MetricCard label="Threat Actors" value={stats?.ThreatActors?.toLocaleString()} color="var(--red)" delta="tracked globally"/>
        <MetricCard label="Malware Families" value={stats?.Malware?.toLocaleString()} color="var(--cyan)" delta="catalogued"/>
        <MetricCard label="Active IOCs" value={stats?.IOCs?.toLocaleString()} color="var(--purple)" delta="indicators"/>
        <MetricCard label="CVEs Tracked" value={stats?.CVEs?.toLocaleString()} color="var(--green)" delta="vulnerabilities"/>
      </div>

      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
        {/* Top Actors */}
        <Card title="Top Threat Actors">
          {la ? <Loading/> : (topActors||[]).slice(0,7).map((a,i) => (
            <div key={i} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'8px 0',borderBottom:'1px solid var(--border)'}}>
              <div>
                <div style={{fontFamily:'var(--mono)',fontSize:12,color:'var(--text)'}}>{a.actor||a.name}</div>
                <div style={{fontSize:10,color:'var(--text3)',marginTop:2}}>Malware used: {a.malware_count||0}</div>
              </div>
              <div style={{textAlign:'right'}}>
                <div style={{fontFamily:'var(--title)',fontSize:20,fontWeight:800,color:'var(--red)'}}>{a.malware_count||0}</div>
                <div style={{fontSize:9,color:'var(--text3)'}}>tools</div>
              </div>
            </div>
          ))}
        </Card>

        {/* Sector Risk */}
        <Card title="Sector Risk Index" action={<Tag variant="red">CRITICAL</Tag>}>
          {SECTORS.map((s,i) => (
            <div key={i} style={{marginBottom:10}}>
              <div style={{display:'flex',justifyContent:'space-between',fontSize:11,marginBottom:4}}>
                <span style={{color:'var(--text)'}}>{s.name}</span>
                <span style={{color:s.color,fontFamily:'var(--mono)',fontWeight:700}}>{s.risk}%</span>
              </div>
              <ProgressBar value={s.risk} color={s.color}/>
            </div>
          ))}
        </Card>
      </div>

      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
        {/* Top Malware */}
        <Card title="Top Malware Families">
          {lm ? <Loading/> : (topMalware||[]).slice(0,7).map((m,i) => (
            <div key={i} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'8px 0',borderBottom:'1px solid var(--border)'}}>
              <div>
                <div style={{fontFamily:'var(--mono)',fontSize:12,color:'var(--cyan)'}}>{m.malware||m.name}</div>
                <div style={{fontSize:10,color:'var(--text3)',marginTop:2}}>Used by {m.actor_count||0} groups</div>
              </div>
              <Tag variant="red">{m.actor_count||0} actors</Tag>
            </div>
          ))}
        </Card>

        {/* Live Feed */}
        <Card title="Live Intelligence Feed" action={<Tag variant="green">STREAMING</Tag>}>
          <div style={{display:'flex',flexDirection:'column',gap:6}}>
            {feed.map((f,i) => (
              <div key={i} style={{display:'flex',gap:10,fontFamily:'var(--mono)',fontSize:10,padding:'6px 8px',borderRadius:3,background:'var(--bg3)'}}>
                <span style={{color:'var(--text3)',flexShrink:0}}>{f.time||'--:--:--'}</span>
                <span style={{color:feedColor[f.t]||'var(--text2)'}}>{f.m}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
