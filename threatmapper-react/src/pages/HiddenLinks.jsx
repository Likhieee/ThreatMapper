import React, { useState } from 'react';
import { useAPI } from '../hooks/useAPI';
import { Card, MetricCard, Loading, Empty, Tag, Btn, ProgressBar } from '../components/UI';

export default function HiddenLinks() {
  // /scores returns: [{ actor1, actor2, similarity (0-100), shared_malware: string[] }]
  const { data, loading, refetch } = useAPI('/scores');
  const [filter, setFilter] = useState('all');

  const links = Array.isArray(data) ? data : [];

  // Sort by similarity descending
  const sorted = [...links].sort((a, b) => (b.similarity || 0) - (a.similarity || 0));
  const filtered = filter === 'high' ? sorted.filter(l => (l.similarity || 0) >= 50) : sorted;

  // Collect all unique shared malware across all links
  const sharedMalwareSet = new Set();
  links.forEach(l => {
    const sm = l.shared_malware || [];
    (Array.isArray(sm) ? sm : [sm]).filter(Boolean).forEach(m => sharedMalwareSet.add(m));
  });

  // Count unique actors
  const actorSet = new Set();
  links.forEach(l => {
    if (l.actor1) actorSet.add(l.actor1);
    if (l.actor2) actorSet.add(l.actor2);
  });

  const getConfidenceLabel = (sim) => {
    if (sim >= 75) return { label: 'CRITICAL', variant: 'red' };
    if (sim >= 50) return { label: 'HIGH', variant: 'orange' };
    if (sim >= 25) return { label: 'MEDIUM', variant: 'yellow' };
    return { label: 'LOW', variant: 'cyan' };
  };

  const getBarColor = (sim) => {
    if (sim >= 75) return 'var(--red)';
    if (sim >= 50) return 'var(--orange)';
    if (sim >= 25) return 'var(--yellow)';
    return 'var(--cyan)';
  };

  return (
    <div style={{padding:20,display:'flex',flexDirection:'column',gap:16,overflowY:'auto',height:'100%'}}>
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between'}}>
        <div>
          <h2 style={{fontFamily:'var(--title)',fontSize:22,fontWeight:800}}>AI Hidden Link Discovery</h2>
          <p style={{fontSize:11,color:'var(--text3)',fontFamily:'var(--mono)',marginTop:2}}>
            Neo4j graph analysis — detecting covert actor connections via shared malware tooling
          </p>
        </div>
        <Btn variant='cyan' onClick={refetch}>⟳ REFRESH ANALYSIS</Btn>
      </div>

      <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:16}}>
        <MetricCard label="Actor Pair Connections" value={links.length} color="var(--cyan)" delta="hidden relationships"/>
        <MetricCard label="Unique Threat Actors" value={actorSet.size} color="var(--purple)" delta="actors in graph"/>
        <MetricCard label="Shared Malware Tools" value={sharedMalwareSet.size} color="var(--red)" delta="common tools"/>
      </div>

      <Card title="Detected Actor Connections" action={
        <div style={{display:'flex',gap:4}}>
          <Btn active={filter==='all'} onClick={()=>setFilter('all')}>ALL</Btn>
          <Btn active={filter==='high'} onClick={()=>setFilter('high')}>HIGH SIMILARITY ≥50%</Btn>
        </div>
      }>
        {loading ? <Loading text="Querying Neo4j relationship graph..."/> :
         !filtered.length ? (
           <Empty icon="🔗" text={
             links.length === 0
               ? "No hidden links detected yet. The graph needs actor pairs sharing malware to surface connections."
               : "No high-similarity connections found. Lower the filter to see all links."
           }/>
         ) : (
           <div style={{display:'flex',flexDirection:'column',gap:10}}>
             {filtered.map((link, i) => {
               const sim = Math.round(link.similarity || 0);
               const sharedArr = Array.isArray(link.shared_malware) ? link.shared_malware : [];
               const { label, variant } = getConfidenceLabel(sim);
               const barColor = getBarColor(sim);

               return (
                 <div key={i} style={{padding:'12px 14px',border:'1px solid rgba(34,211,238,0.15)',
                   borderLeft:`3px solid ${barColor}`,borderRadius:4,
                   background:'rgba(34,211,238,0.03)'}}>
                   <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:6}}>
                     <span style={{fontFamily:'var(--mono)',fontSize:13,color:'var(--red2)',fontWeight:700}}>
                       {link.actor1}
                     </span>
                     <span style={{color:'var(--text3)',fontSize:18}}>⟷</span>
                     <span style={{fontFamily:'var(--mono)',fontSize:13,color:'var(--red2)',fontWeight:700}}>
                       {link.actor2}
                     </span>
                     <div style={{marginLeft:'auto',display:'flex',gap:6,alignItems:'center'}}>
                       <Tag variant={variant}>{label}</Tag>
                       <Tag variant='cyan'>{sim}% SIMILARITY</Tag>
                     </div>
                   </div>

                   <div style={{fontSize:10,color:'var(--text3)',fontFamily:'var(--mono)',marginBottom:4}}>
                     SHARED MALWARE ({sharedArr.length}):&nbsp;
                     <span style={{color:'var(--orange)'}}>
                       {sharedArr.length > 0
                         ? sharedArr.slice(0, 5).join(' · ') + (sharedArr.length > 5 ? ` +${sharedArr.length - 5} more` : '')
                         : 'No shared tools recorded'}
                     </span>
                   </div>

                   <ProgressBar value={sim} color={barColor}/>
                 </div>
               );
             })}
           </div>
         )}
      </Card>
    </div>
  );
}
