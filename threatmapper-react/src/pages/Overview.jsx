import React, { useEffect, useState } from 'react';
import { useAPI } from '../hooks/useAPI';
import { Card, MetricCard, Loading, ProgressBar, Tag } from '../components/UI';

const SECTORS = [
  {name:'Financial Services',  risk:92, color:'var(--red)'},
  {name:'Healthcare',          risk:87, color:'var(--red)'},
  {name:'Energy / Utilities',  risk:84, color:'var(--orange)'},
  {name:'Defense Contractors', risk:80, color:'var(--orange)'},
  {name:'Government',          risk:74, color:'var(--yellow)'},
  {name:'Telecommunications',  risk:67, color:'var(--yellow)'},
  {name:'Technology',          risk:55, color:'var(--green)'},
];

const FALLBACK_ACTORS = [
  {actor:'Lazarus Group',  malware_count:18, origin:'DPRK',    category:'Nation-State'},
  {actor:'APT28',          malware_count:14, origin:'Russia',  category:'Nation-State'},
  {actor:'APT41',          malware_count:22, origin:'China',   category:'Nation-State'},
  {actor:'Sandworm',       malware_count:11, origin:'Russia',  category:'Nation-State'},
  {actor:'FIN7',           malware_count:9,  origin:'Unknown', category:'Cybercrime'},
  {actor:'Cobalt Group',   malware_count:7,  origin:'Unknown', category:'Cybercrime'},
  {actor:'APT29',          malware_count:16, origin:'Russia',  category:'Nation-State'},
  {actor:'OilRig',         malware_count:12, origin:'Iran',    category:'Nation-State'},
  {actor:'MuddyWater',     malware_count:8,  origin:'Iran',    category:'Nation-State'},
  {actor:'Kimsuky',        malware_count:10, origin:'DPRK',    category:'Nation-State'},
];

const FALLBACK_MALWARE = [
  {malware:'Cobalt Strike', actor_count:31, type:'RAT/C2',       severity:'CRITICAL'},
  {malware:'Mimikatz',      actor_count:28, type:'Credential',   severity:'CRITICAL'},
  {malware:'TrickBot',      actor_count:19, type:'Banking',      severity:'HIGH'},
  {malware:'Emotet',        actor_count:24, type:'Loader',       severity:'CRITICAL'},
  {malware:'PlugX',         actor_count:17, type:'RAT',          severity:'HIGH'},
  {malware:'NukeSped',      actor_count:6,  type:'Backdoor',     severity:'HIGH'},
  {malware:'Zebrocy',       actor_count:4,  type:'Downloader',   severity:'MEDIUM'},
  {malware:'BlackEnergy',   actor_count:3,  type:'ICS Malware',  severity:'CRITICAL'},
  {malware:'Industroyer',   actor_count:2,  type:'ICS Malware',  severity:'CRITICAL'},
  {malware:'WannaCry',      actor_count:8,  type:'Ransomware',   severity:'CRITICAL'},
];

const FEED = [
  {t:'alert', m:'CVE-2024-5678 actively exploited in the wild'},
  {t:'alert', m:'APT28 C2 beacon — IP 105.220.x.x flagged'},
  {t:'info',  m:'Neo4j graph updated — 3 new relationships'},
  {t:'warn',  m:'Carbanak lateral movement pattern observed'},
  {t:'alert', m:'Lazarus Group — new crypto theft TTP detected'},
  {t:'info',  m:'OTX pulse ingested — FIN7 campaign update'},
  {t:'warn',  m:'Hidden link: APT41 ↔ Sandworm share 4 tools'},
  {t:'info',  m:'Prediction model retrained — 94.2% accuracy'},
  {t:'alert', m:'Ransomware IOC cluster: 12 new C2 IPs blocked'},
  {t:'warn',  m:'Volt Typhoon activity — US infrastructure target'},
  {t:'info',  m:'MITRE ATT&CK mapping updated for APT38'},
  {t:'alert', m:'BlackCat RaaS — new variant with ALPHV features'},
];

const feedColor = {alert:'var(--red)', warn:'var(--yellow)', info:'var(--cyan)'};

export default function Overview({ stats }) {
  const { data: topActorsRaw, loading: la } = useAPI('/top-threat-actors');
  const { data: topMalwareRaw, loading: lm } = useAPI('/top-malware');
  const [feed, setFeed] = useState(
    FEED.slice(0, 5).map(f => ({...f, time: new Date().toLocaleTimeString('en-GB',{hour12:false})}))
  );
  const [idx, setIdx] = useState(5);

  useEffect(() => {
    const id = setInterval(() => {
      const item = FEED[idx % FEED.length];
      setFeed(f => [{...item, time: new Date().toLocaleTimeString('en-GB',{hour12:false})}, ...f].slice(0, 8));
      setIdx(i => i + 1);
    }, 4000);
    return () => clearInterval(id);
  }, [idx]);

  // Normalise: prefer live API, fallback to static
  const actorList = Array.isArray(topActorsRaw) && topActorsRaw.length > 0
    ? topActorsRaw : FALLBACK_ACTORS;
  const malwareList = Array.isArray(topMalwareRaw) && topMalwareRaw.length > 0
    ? topMalwareRaw : FALLBACK_MALWARE;

  // Metric values — use stats from API, fall back to sensible defaults
  const metrics = {
    actors:  stats?.ThreatActors ?? actorList.length,
    malware: stats?.Malware      ?? malwareList.length,
    iocs:    stats?.IOCs         ?? 3522,
    cves:    stats?.CVEs         ?? 2000,
  };

  const sevColor = s => s==='CRITICAL'?'var(--red)':s==='HIGH'?'var(--orange)':'var(--yellow)';

  return (
    <div style={{padding:20, display:'flex', flexDirection:'column', gap:16, overflowY:'auto', height:'100%'}}>

      {/* Metric Cards */}
      <div style={{display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:16}}>
        <MetricCard label="Threat Actors"    value={metrics.actors.toLocaleString()}  color="var(--red)"    delta="tracked globally"/>
        <MetricCard label="Malware Families" value={metrics.malware.toLocaleString()} color="var(--cyan)"   delta="catalogued"/>
        <MetricCard label="Active IOCs"      value={metrics.iocs.toLocaleString()}    color="var(--purple)" delta="indicators"/>
        <MetricCard label="CVEs Tracked"     value={metrics.cves.toLocaleString()}    color="var(--orange)" delta="vulnerabilities"/>
      </div>

      <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:16}}>

        {/* Top Threat Actors */}
        <Card title="Top Threat Actors">
          {la ? <Loading/> : actorList.slice(0, 8).map((a, i) => (
            <div key={i} style={{display:'flex', justifyContent:'space-between', alignItems:'center',
              padding:'8px 0', borderBottom:'1px solid var(--border)'}}>
              <div>
                <div style={{fontFamily:'var(--mono)', fontSize:12, color:'var(--text)'}}>
                  {a.actor || a.name}
                </div>
                <div style={{fontSize:10, color:'var(--text3)', marginTop:2}}>
                  {a.origin && <span style={{color:'var(--text3)'}}>{a.origin} · </span>}
                  {a.category || 'Threat Actor'} · {a.malware_count || 0} tools
                </div>
              </div>
              <div style={{display:'flex', alignItems:'center', gap:8}}>
                <div style={{fontFamily:'var(--title)', fontSize:22, fontWeight:800, color:'var(--red)'}}>
                  {a.malware_count || 0}
                </div>
                <div style={{fontSize:9, color:'var(--text3)'}}>tools</div>
              </div>
            </div>
          ))}
        </Card>

        {/* Sector Risk */}
        <Card title="Sector Risk Index" action={<Tag variant="red">CRITICAL</Tag>}>
          {SECTORS.map((s, i) => (
            <div key={i} style={{marginBottom:10}}>
              <div style={{display:'flex', justifyContent:'space-between', fontSize:11, marginBottom:4}}>
                <span style={{color:'var(--text)'}}>{s.name}</span>
                <span style={{color:s.color, fontFamily:'var(--mono)', fontWeight:700}}>{s.risk}%</span>
              </div>
              <ProgressBar value={s.risk} color={s.color}/>
            </div>
          ))}
        </Card>
      </div>

      <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:16}}>

        {/* Top Malware */}
        <Card title="Top Malware Families">
          {lm ? <Loading/> : malwareList.slice(0, 8).map((m, i) => (
            <div key={i} style={{display:'flex', justifyContent:'space-between', alignItems:'center',
              padding:'8px 0', borderBottom:'1px solid var(--border)'}}>
              <div>
                <div style={{fontFamily:'var(--mono)', fontSize:12, color:'var(--cyan)'}}>
                  {m.malware || m.name}
                </div>
                <div style={{fontSize:10, color:'var(--text3)', marginTop:2}}>
                  {m.type || 'Malware'} · used by {m.actor_count || 0} groups
                </div>
              </div>
              <div style={{display:'flex', alignItems:'center', gap:6}}>
                {m.severity && (
                  <Tag variant={m.severity==='CRITICAL'?'red':m.severity==='HIGH'?'orange':'yellow'}>
                    {m.severity}
                  </Tag>
                )}
                <Tag variant="red">{m.actor_count || 0} actors</Tag>
              </div>
            </div>
          ))}
        </Card>

        {/* Live Feed */}
        <Card title="Live Intelligence Feed" action={<Tag variant="green">STREAMING</Tag>}>
          <div style={{display:'flex', flexDirection:'column', gap:6}}>
            {feed.map((f, i) => (
              <div key={i} style={{display:'flex', gap:10, fontFamily:'var(--mono)', fontSize:10,
                padding:'6px 8px', borderRadius:3, background:'var(--bg3)'}}>
                <span style={{color:'var(--text3)', flexShrink:0}}>{f.time || '--:--:--'}</span>
                <span style={{color:feedColor[f.t] || 'var(--text2)'}}>{f.m}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
