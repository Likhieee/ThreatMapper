import React from 'react';
import { useAPI, BACKEND } from '../hooks/useAPI';
import { Card, MetricCard, Loading, Tag, Empty } from '../components/UI';

export default function DarkWeb() {
  const { data, loading } = useAPI('/darkweb', BACKEND);
  const { data: stats } = useAPI('/darkweb/stats', BACKEND);
  const records = data?.data || [];

  const sevVariant = s => ({CRITICAL:'red',High:'orange',HIGH:'orange',Medium:'yellow',MEDIUM:'yellow',Low:'green',LOW:'green'}[s]||'cyan');

  return (
    <div style={{padding:20,display:'flex',flexDirection:'column',gap:16,overflowY:'auto',height:'100%'}}>
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between'}}>
        <div>
          <h2 style={{fontFamily:'var(--title)',fontSize:22,fontWeight:800}}>Dark Web Intelligence</h2>
          <p style={{fontSize:11,color:'var(--text3)',fontFamily:'var(--mono)',marginTop:2}}>
            Synthetic OSINT — Forum mentions, leaked credentials, actor aliases — TOR Network
          </p>
        </div>
        <Tag variant='purple' style={{fontSize:10,padding:'4px 10px'}}>TOR CIRCUIT ACTIVE — SYNTHETIC DATA</Tag>
      </div>

      <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:16}}>
        <MetricCard label="Forum Mentions" value={(stats?.total_posts||records.length).toLocaleString()} color="var(--purple)" delta="+142 today"/>
        <MetricCard label="Leaked Credentials" value={(stats?.total_records_leaked||0).toLocaleString()} color="var(--red)" delta="+12K this week"/>
        <MetricCard label="Actor Aliases" value={(stats?.total_actors||0).toLocaleString()} color="var(--cyan)" delta="identified"/>
        <MetricCard label="Active Markets" value="23" color="var(--green)" delta="monitored"/>
      </div>

      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
        <Card title="Forum Activity" style={{overflow:'hidden'}}>
          {loading ? <Loading text="Loading dark web intelligence..."/> :
            !records.length ? <Empty icon="🌐" text="No data available"/> : (
              <div style={{display:'flex',flexDirection:'column',gap:10,overflowY:'auto',maxHeight:400}}>
                {records.slice(0,12).map((d,i) => (
                  <div key={i} style={{padding:12,border:'1px solid rgba(168,85,247,0.15)',
                    borderLeft:'3px solid var(--purple)',borderRadius:6,background:'rgba(168,85,247,0.03)'}}>
                    <div style={{fontSize:9,color:'var(--purple)',fontFamily:'var(--mono)',marginBottom:6}}>
                      📡 {d.forum_source} — {d.post_date}
                    </div>
                    <div style={{fontSize:12,color:'var(--text)',marginBottom:8}}>
                      <span style={{color:'var(--red2)',fontWeight:700}}>{d.actor_alias}</span>
                      {' targeting '}
                      <span style={{color:'var(--orange)'}}>{d.target_sector}</span>
                    </div>
                    <div style={{display:'flex',gap:6,flexWrap:'wrap'}}>
                      <Tag variant='purple'>{d.tool_advertised}</Tag>
                      <Tag variant='yellow'>{d.price_btc} BTC</Tag>
                      <Tag variant={sevVariant(d.severity)}>{d.severity}</Tag>
                      <Tag variant={d.verified?'green':'red'}>{d.verified?'VERIFIED':'UNVERIFIED'}</Tag>
                      <Tag variant='cyan'>{(d.records_count||0).toLocaleString()} records</Tag>
                    </div>
                  </div>
                ))}
              </div>
            )}
        </Card>

        <Card title="Credential Leaks">
          <table style={{width:'100%',borderCollapse:'collapse',fontSize:12}}>
            <thead>
              <tr>{['Data Type','Records','Date','Verified'].map(h => (
                <th key={h} style={{textAlign:'left',fontSize:9,fontFamily:'var(--mono)',color:'var(--text3)',
                  letterSpacing:2,padding:'8px 10px',borderBottom:'1px solid var(--border)',textTransform:'uppercase'}}>
                  {h}
                </th>
              ))}</tr>
            </thead>
            <tbody>
              {records.slice(0,15).map((d,i) => (
                <tr key={i}>
                  <td style={{padding:'9px 10px',borderBottom:'1px solid var(--border)',color:'var(--purple)',fontFamily:'var(--mono)',fontSize:10}}>{d.data_type_leaked}</td>
                  <td style={{padding:'9px 10px',borderBottom:'1px solid var(--border)',color:'var(--red)',fontFamily:'var(--mono)'}}>{(d.records_count||0).toLocaleString()}</td>
                  <td style={{padding:'9px 10px',borderBottom:'1px solid var(--border)',color:'var(--text3)',fontSize:10}}>{d.post_date}</td>
                  <td style={{padding:'9px 10px',borderBottom:'1px solid var(--border)'}}><Tag variant={d.verified?'green':'red'}>{d.verified?'YES':'NO'}</Tag></td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>
    </div>
  );
}
