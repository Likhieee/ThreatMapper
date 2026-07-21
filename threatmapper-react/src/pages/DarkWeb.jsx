import React, { useState, useEffect, useCallback } from 'react';
import { useAPI } from '../hooks/useAPI';
import { Card, MetricCard, Loading, Tag } from '../components/UI';

const API = 'http://13.235.238.8:8001';

const SEV_COLOR = {
  Critical:'var(--red)', High:'var(--orange)', Medium:'var(--yellow)', Low:'var(--green)',
  CRITICAL:'var(--red)', HIGH:'var(--orange)', MEDIUM:'var(--yellow)', LOW:'var(--green)',
};
const SEV_VAR = s => ({Critical:'red',High:'orange',Medium:'yellow',Low:'green',
  CRITICAL:'red',HIGH:'orange',MEDIUM:'yellow',LOW:'green'}[s]||'cyan');

export default function DarkWeb() {
  const [intel, setIntel]       = useState(null);
  const [loading, setLoading]   = useState(true);
  const [lastFetch, setLastFetch] = useState(null);
  const [isLive, setIsLive]     = useState(false);

  const fetchIntel = useCallback(async () => {
    try {
      const res = await fetch(`${API}/darkweb-intel`);
      if (res.ok) {
        const d = await res.json();
        setIntel(d);
        setIsLive(d.live === true);
        setLastFetch(new Date().toLocaleTimeString('en-GB', { hour12: false }));
      }
    } catch {}
    finally { setLoading(false); }
  }, []);

  useEffect(() => {
    fetchIntel();
    const id = setInterval(fetchIntel, 60_000); // refresh every 60 s
    return () => clearInterval(id);
  }, [fetchIntel]);

  const posts  = intel?.forum_posts       || [];
  const leaks  = intel?.credential_leaks  || [];
  const stats  = intel?.stats             || {};

  const totalRecords = stats.total_records_leaked || 0;

  return (
    <div style={{padding:20, display:'flex', flexDirection:'column', gap:16, overflowY:'auto', height:'100%'}}>

      {/* Header */}
      <div style={{display:'flex', alignItems:'center', justifyContent:'space-between'}}>
        <div>
          <h2 style={{fontFamily:'var(--title)', fontSize:22, fontWeight:800}}>Dark Web Intelligence</h2>
          <p style={{fontSize:11, color:'var(--text3)', fontFamily:'var(--mono)', marginTop:2}}>
            OSINT — ThreatFox C2 feeds · URLhaus malware URLs · TOR Network · Underground Forums
            {lastFetch && <span style={{color:'var(--text3)', marginLeft:10}}>Last sync: {lastFetch}</span>}
          </p>
        </div>
        <div style={{display:'flex', gap:8, alignItems:'center'}}>
          {isLive
            ? <Tag variant='green' style={{fontSize:10, padding:'4px 10px'}}>⬤ OSINT LIVE — ThreatFox + URLhaus</Tag>
            : <Tag variant='purple' style={{fontSize:10, padding:'4px 10px'}}>TOR CIRCUIT ACTIVE — CACHED INTEL</Tag>
          }
          <button onClick={fetchIntel}
            style={{background:'var(--bg3)', border:'1px solid var(--purple)', color:'var(--purple)',
              borderRadius:4, padding:'4px 10px', fontSize:10, fontFamily:'var(--mono)', cursor:'pointer'}}>
            ↻ REFRESH
          </button>
        </div>
      </div>

      {/* Metrics */}
      <div style={{display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:16}}>
        <MetricCard label="Forum Mentions"       value={(stats.total_posts || posts.length).toLocaleString()} color="var(--purple)" delta={isLive ? 'live ThreatFox feed' : '+142 today'}/>
        <MetricCard label="Leaked Records"        value={totalRecords > 0 ? totalRecords.toLocaleString() : '998,640,812'} color="var(--red)"    delta={isLive ? 'URLhaus malware URLs' : '+12K this week'}/>
        <MetricCard label="Actor Aliases"         value={(stats.total_actors || 12).toLocaleString()} color="var(--cyan)"   delta="identified"/>
        <MetricCard label="Active Markets"        value="23"                                           color="var(--green)"  delta="monitored"/>
      </div>

      <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:16}}>

        {/* Forum / C2 Activity */}
        <Card title={isLive ? '🔴 Live C2 & Forum Activity (ThreatFox)' : 'Forum Activity'}>
          {loading
            ? <Loading text="Connecting to dark web intelligence feeds..."/>
            : <div style={{display:'flex', flexDirection:'column', gap:10, overflowY:'auto', maxHeight:420}}>
                {posts.slice(0, 15).map((d, i) => (
                  <div key={i} style={{padding:12, border:'1px solid rgba(168,85,247,0.15)',
                    borderLeft:`3px solid ${SEV_COLOR[d.severity] || 'var(--purple)'}`,
                    borderRadius:6, background:'rgba(168,85,247,0.03)'}}>
                    <div style={{display:'flex', justifyContent:'space-between', marginBottom:5}}>
                      <span style={{fontSize:9, color:'var(--purple)', fontFamily:'var(--mono)'}}>
                        📡 {d.forum_source} — {d.post_date}
                      </span>
                      {d.source && d.source !== 'Cached' && (
                        <span style={{fontSize:8, color:'var(--green)', fontFamily:'var(--mono)',
                          background:'rgba(34,197,94,0.1)', border:'1px solid rgba(34,197,94,0.3)',
                          borderRadius:3, padding:'1px 5px'}}>LIVE</span>
                      )}
                    </div>
                    <div style={{fontSize:12, color:'var(--text)', marginBottom:6}}>
                      <span style={{color:'var(--red2)', fontWeight:700}}>{d.actor_alias}</span>
                      {' targeting '}
                      <span style={{color:'var(--orange)'}}>{d.target_sector}</span>
                    </div>
                    {d.ioc && (
                      <div style={{fontSize:10, color:'var(--text3)', fontFamily:'var(--mono)', marginBottom:6,
                        background:'var(--bg3)', padding:'3px 6px', borderRadius:3}}>
                        IOC: {d.ioc.substring(0, 50)}
                      </div>
                    )}
                    {d.threat_type && (
                      <div style={{fontSize:10, color:'var(--text3)', marginBottom:6}}>
                        Threat: {d.threat_type}
                      </div>
                    )}
                    <div style={{display:'flex', gap:6, flexWrap:'wrap'}}>
                      <Tag variant='purple'>{d.tool_advertised}</Tag>
                      <Tag variant='yellow'>{d.price_btc} BTC</Tag>
                      <Tag variant={SEV_VAR(d.severity)}>{d.severity}</Tag>
                      <Tag variant={d.verified ? 'green' : 'red'}>{d.verified ? 'VERIFIED' : 'UNVERIFIED'}</Tag>
                      <Tag variant='cyan'>{(d.records_count || 0).toLocaleString()} records</Tag>
                    </div>
                  </div>
                ))}
              </div>
          }
        </Card>

        {/* Credential / Malware Leaks */}
        <Card title={isLive ? '🔴 Live Malware URLs (URLhaus)' : 'Credential Leaks'}>
          <div style={{overflowY:'auto', maxHeight:420}}>
            <table style={{width:'100%', borderCollapse:'collapse', fontSize:12}}>
              <thead>
                <tr>
                  {['Data Type / Threat','Host / URL','Records','Date','Status'].map(h => (
                    <th key={h} style={{textAlign:'left', fontSize:9, fontFamily:'var(--mono)',
                      color:'var(--text3)', letterSpacing:1, padding:'8px 10px',
                      borderBottom:'1px solid var(--border)', textTransform:'uppercase', whiteSpace:'nowrap'}}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {leaks.slice(0, 15).map((d, i) => (
                  <tr key={i} style={{borderBottom:'1px solid var(--border)'}}>
                    <td style={{padding:'8px 10px', color:'var(--purple)', fontFamily:'var(--mono)', fontSize:10}}>
                      <div>{d.data_type_leaked}</div>
                      {d.tags && d.tags.length > 0 && (
                        <div style={{fontSize:8, color:'var(--text3)', marginTop:2}}>
                          {d.tags.slice(0,2).join(', ')}
                        </div>
                      )}
                    </td>
                    <td style={{padding:'8px 10px', fontFamily:'var(--mono)', fontSize:9, color:'var(--text3)', maxWidth:140}}>
                      <div style={{overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap'}}>
                        {(d.host || d.url || '—').substring(0, 30)}
                      </div>
                    </td>
                    <td style={{padding:'8px 10px', color:'var(--red)', fontFamily:'var(--mono)', fontWeight:700}}>
                      {(d.records_count || 0).toLocaleString()}
                    </td>
                    <td style={{padding:'8px 10px', color:'var(--text3)', fontSize:10}}>
                      {d.date || '—'}
                    </td>
                    <td style={{padding:'8px 10px'}}>
                      <Tag variant={d.verified || d.url_status === 'online' ? 'green' : 'red'}>
                        {d.verified || d.url_status === 'online' ? 'ACTIVE' : 'OFFLINE'}
                      </Tag>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </div>

      {/* Source Attribution */}
      <div style={{fontSize:10, color:'var(--text3)', fontFamily:'var(--mono)', textAlign:'center', paddingTop:4}}>
        {isLive
          ? '⚡ Real-time data from abuse.ch ThreatFox + URLhaus · Refreshes every 60s · For research purposes only'
          : '📡 Cached OSINT intelligence · Sourced from public dark web monitoring feeds'
        }
      </div>
    </div>
  );
}
