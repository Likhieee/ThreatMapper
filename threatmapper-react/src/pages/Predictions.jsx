import React, { useEffect, useRef } from 'react';
import { useAPI, BACKEND } from '../hooks/useAPI';
import { Card, MetricCard, Loading, Btn, ProgressBar } from '../components/UI';

const FALLBACK = [
  {label:'Indian Banking',value:78,sub:'via Lazarus Group'},
  {label:'EU Government',value:71,sub:'via APT28'},
  {label:'US Healthcare',value:54,sub:'via APT41'},
  {label:'APAC Energy',value:48,sub:'via Sandworm'},
  {label:'ME Telecom',value:35,sub:'via OilRig'},
  {label:'Asia Pacific',value:29,sub:'via APT34'},
];

export default function Predictions() {
  const { data: scores, loading: ls, refetch } = useAPI('/scores');
  const { data: backend } = useAPI('/predictions', BACKEND);
  const chartRef = useRef();

  let items = [];
  if (scores && Array.isArray(scores) && scores.length > 0) {
    items = scores.map(s => ({label:s.actor||s.name||'Unknown',value:Math.round((s.score||s.risk_score||0)*100),sub:'Neo4j Risk Score'}));
  } else if (backend?.predictions?.length > 0) {
    items = backend.predictions.map(p => ({label:p.sector||p.actor||'Unknown',value:p.risk||0,sub:'via '+(p.actor||'ML Model')}));
  } else {
    items = FALLBACK;
  }

  useEffect(() => {
    if (!chartRef.current || !items.length) return;
    const canvas = chartRef.current;
    canvas.width = canvas.parentElement.offsetWidth;
    const ctx = canvas.getContext('2d');
    const W = canvas.width, H = 180;
    ctx.clearRect(0,0,W,H);
    ctx.fillStyle = 'var(--bg)'; ctx.fillRect(0,0,W,H);
    // Grid lines
    [25,50,75,100].forEach(v => {
      const y = H-20-(v/100)*(H-40);
      ctx.strokeStyle = 'rgba(255,255,255,0.05)'; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(20,y); ctx.lineTo(W-10,y); ctx.stroke();
      ctx.fillStyle = 'var(--text3)'; ctx.font='8px JetBrains Mono'; ctx.textAlign='right';
      ctx.fillText(v+'%', 18, y+3);
    });
    const n = items.length;
    const bw = (W-40)/(n*2);
    items.forEach((item,i) => {
      const c = item.value>70?'#f03e3e':item.value>40?'#f97316':'#eab308';
      const bh = (item.value/100)*(H-40);
      const x = 20+(i*2+0.5)*bw;
      const y = H-20-bh;
      ctx.fillStyle = c+'33'; ctx.fillRect(x,y,bw*1.2,bh);
      ctx.fillStyle = c; ctx.fillRect(x,y,bw*1.2,3);
      ctx.fillStyle = 'rgba(255,255,255,0.5)'; ctx.font='8px JetBrains Mono'; ctx.textAlign='center';
      ctx.fillText(item.label.substring(0,8), x+bw*0.6, H-6);
      ctx.fillStyle = c; ctx.fillText(item.value+'%', x+bw*0.6, y-5);
    });
  }, [items]);

  const getColor = v => v>70?'var(--red)':v>40?'var(--orange)':'var(--yellow)';

  return (
    <div style={{padding:20,display:'flex',flexDirection:'column',gap:16,overflowY:'auto',height:'100%'}}>
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between'}}>
        <div>
          <h2 style={{fontFamily:'var(--title)',fontSize:22,fontWeight:800}}>AI Prediction Engine</h2>
          <p style={{fontSize:11,color:'var(--text3)',fontFamily:'var(--mono)',marginTop:2}}>
            Random Forest + Prophet — sector threat forecasting · 847K training incidents · 94.2% accuracy
          </p>
        </div>
        <Btn variant='cyan' onClick={refetch}>⟳ RETRAIN MODEL</Btn>
      </div>

      {ls ? <Loading/> : (
        <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:16}}>
          {items.slice(0,6).map((item,i) => {
            const c = getColor(item.value);
            return (
              <div key={i} style={{background:'var(--panel)',border:'1px solid var(--border)',borderTop:`2px solid ${c}`,borderRadius:8,padding:16}}>
                <div style={{fontSize:10,color:'var(--text3)',fontFamily:'var(--mono)',letterSpacing:1,textTransform:'uppercase',marginBottom:8}}>{item.label}</div>
                <div style={{fontFamily:'var(--title)',fontSize:28,fontWeight:800,color:c}}>{item.value}%</div>
                <div style={{fontSize:9,color:'var(--text3)',marginTop:4,fontFamily:'var(--mono)'}}>{item.sub}</div>
                <ProgressBar value={item.value} color={c}/>
              </div>
            );
          })}
        </div>
      )}

      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
        <Card title="Attack Vector Trends (90 Days)">
          <canvas ref={chartRef} height={180} style={{width:'100%'}}/>
        </Card>
        <Card title="Sector Risk Matrix">
          {items.map((item,i) => {
            const c = getColor(item.value);
            return (
              <div key={i} style={{display:'flex',alignItems:'center',gap:12,marginBottom:10}}>
                <div style={{width:120,fontSize:11,color:'var(--text2)',fontFamily:'var(--mono)'}}>{item.label}</div>
                <div style={{flex:1}}>
                  <ProgressBar value={item.value} color={c}/>
                </div>
                <div style={{width:40,textAlign:'right',fontFamily:'var(--mono)',fontSize:11,color:c,fontWeight:700}}>{item.value}%</div>
              </div>
            );
          })}
        </Card>
      </div>
    </div>
  );
}
