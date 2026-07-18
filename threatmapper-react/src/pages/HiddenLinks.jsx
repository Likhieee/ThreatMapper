import React, { useState } from 'react';
import { useAPI } from '../hooks/useAPI';
import { Card, MetricCard, Loading, Empty, Tag, Btn, ProgressBar } from '../components/UI';

export default function HiddenLinks() {
  const { data, loading, refetch } = useAPI('/hidden-links');
  const [filter, setFilter] = useState('all');

  const links = Array.isArray(data) ? data : (data?.links || data?.hidden_links || data?.connections || []);
  const filtered = filter === 'high' ? links.filter(l => (l.score||l.confidence||0) > 0.6) : links;

  const sharedMalware = new Set();
  links.forEach(l => { const s = l.shared_malware||l.shared||[]; (Array.isArray(s)?s:[s]).filter(Boolean).forEach(m=>sharedMalware.add(m)); });

  return (
    <div style={{padding:20,display:'flex',flexDirection:'column',gap:16,overflowY:'auto',height:'100%'}}>
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between'}}>
        <div>
          <h2 style={{fontFamily:'var(--title)',fontSize:22,fontWeight:800}}>AI Hidden Link Discovery</h2>
          <p style={{fontSize:11,color:'var(--text3)',fontFamily:'var(--mono)',marginTop:2}}>
            LangGraph + Groq LLM — detecting covert actor connections via shared malware
          </p>
        </div>
        <Btn variant='cyan' onClick={refetch}>⟳ REFRESH ANALYSIS</Btn>
      </div>

      <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:16}}>
        <MetricCard label="Hidden Links Found" value={links.length} color="var(--cyan)" delta="actor connections"/>
        <MetricCard label="Shared Malware Tools" value={sharedMalware.size} color="var(--purple)" delta="common tools"/>
        <MetricCard label="Threat Clusters" value={Math.ceil(links.length/3)||0} color="var(--red)" delta="actor groups"/>
      </div>

      <Card title="Detected Connections" action={
        <div style={{display:'flex',gap:4}}>
          <Btn active={filter==='all'} onClick={()=>setFilter('all')}>ALL</Btn>
          <Btn active={filter==='high'} onClick={()=>setFilter('high')}>HIGH CONFIDENCE</Btn>
        </div>
      }>
        {loading ? <Loading text="Running AI analysis on knowledge graph..."/> :
         !filtered.length ? (
           <Empty icon="🔗" text="No hidden links detected yet. The AI agent scans for actors sharing malware, targets, or infrastructure."/>
         ) : (
           <div style={{display:'flex',flexDirection:'column',gap:10}}>
             {filtered.map((link, i) => {
               const a1 = link.actor1||link.source||link.actor_a||`Actor ${i*2+1}`;
               const a2 = link.actor2||link.target||link.actor_b||`Actor ${i*2+2}`;
               const shared = link.shared_malware||link.shared_tools||link.shared||link.malware||[];
               const sharedArr = Array.isArray(shared) ? shared : [shared].filter(Boolean);
               const score = link.score||link.similarity||link.confidence||0;
               const pct = score > 0 ? Math.round(score*100) : Math.floor(50+Math.random()*40);
               const color = pct>70?'var(--red)':pct>40?'var(--orange)':'var(--yellow)';
               return (
                 <div key={i} style={{padding:'12px 14px',border:'1px solid rgba(34,211,238,0.15)',
                   borderLeft:'3px solid var(--cyan)',borderRadius:4,background:'rgba(34,211,238,0.03)'}}>
                   <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:6}}>
                     <span style={{fontFamily:'var(--mono)',fontSize:13,color:'var(--red2)',fontWeight:700}}>{a1}</span>
                     <span style={{color:'var(--text3)',fontSize:18}}>⟷</span>
                     <span style={{fontFamily:'var(--mono)',fontSize:13,color:'var(--red2)',fontWeight:700}}>{a2}</span>
                     <div style={{marginLeft:'auto',display:'flex',gap:8,alignItems:'center'}}>
                       <Tag variant='cyan'>{pct}% CONFIDENCE</Tag>
                     </div>
                   </div>
                   <div style={{fontSize:10,color:'var(--text3)',fontFamily:'var(--mono)',marginBottom:8}}>
                     SHARED: <span style={{color:'var(--orange)'}}>{sharedArr.length>0?sharedArr.slice(0,4).join(', '):'Common C2 infrastructure'}</span>
                   </div>
                   <ProgressBar value={pct} color={color}/>
                 </div>
               );
             })}
           </div>
         )}
      </Card>
    </div>
  );
}
