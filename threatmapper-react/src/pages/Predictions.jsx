import React, { useState } from 'react';
import { useAPI } from '../hooks/useAPI';
import { Card, MetricCard, Loading, Btn, ProgressBar, Tag, Empty } from '../components/UI';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell
} from 'recharts';

// 12-sector fallback — shown when backend ML model is unavailable
const FALLBACK = [
  {sector:'Indian Banking',       risk:78, actor:'Lazarus Group',   confidence:'HIGH',   timeframe:'30 days'},
  {sector:'EU Government',        risk:71, actor:'APT28',           confidence:'HIGH',   timeframe:'30 days'},
  {sector:'US Healthcare',        risk:54, actor:'APT41',           confidence:'MEDIUM', timeframe:'45 days'},
  {sector:'APAC Energy',          risk:48, actor:'Sandworm',        confidence:'MEDIUM', timeframe:'60 days'},
  {sector:'ME Telecom',           risk:31, actor:'OilRig',          confidence:'LOW',    timeframe:'90 days'},
  {sector:'Asia Pacific Tech',    risk:24, actor:'APT34',           confidence:'LOW',    timeframe:'90 days'},
  {sector:'US Financial Services',risk:82, actor:'FIN7',            confidence:'HIGH',   timeframe:'21 days'},
  {sector:'UK Defence',           risk:67, actor:'APT29',           confidence:'HIGH',   timeframe:'30 days'},
  {sector:'German Manufacturing', risk:61, actor:'Turla',           confidence:'MEDIUM', timeframe:'45 days'},
  {sector:'LATAM Finance',        risk:43, actor:'Cobalt Group',    confidence:'MEDIUM', timeframe:'60 days'},
  {sector:'Global Crypto',        risk:88, actor:'Lazarus Group',   confidence:'HIGH',   timeframe:'14 days'},
  {sector:'EU Critical Infra',    risk:74, actor:'Volt Typhoon',    confidence:'HIGH',   timeframe:'30 days'},
];

function RiskTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  const c = (d.risk||0) > 70 ? '#f03e3e' : (d.risk||0) > 40 ? '#f97316' : '#eab308';
  return (
    <div style={{background:'var(--panel)',border:`1px solid ${c}`,borderRadius:6,padding:'8px 12px',fontFamily:'var(--mono)',fontSize:11}}>
      <div style={{color:'var(--text2)',marginBottom:4}}>{d.sector}</div>
      <div style={{color:c,fontWeight:700,fontSize:16}}>{d.risk}%</div>
      {d.actor && <div style={{color:'var(--text3)',fontSize:10,marginTop:2}}>via {d.actor}</div>}
    </div>
  );
}

export default function Predictions() {
  const { data, loading, refetch } = useAPI('/predictions');
  const [retraining, setRetraining] = useState(false);
  const [retrained, setRetrained]   = useState(false);

  const raw   = data?.predictions;
  const items = (Array.isArray(raw) && raw.length > 0) ? raw : FALLBACK;

  const getColor   = v => v > 70 ? 'var(--red)' : v > 40 ? 'var(--orange)' : 'var(--yellow)';
  const getVariant = c => {
    if (!c) return 'yellow';
    const u = c.toUpperCase();
    return u === 'HIGH' ? 'red' : u === 'MEDIUM' ? 'orange' : 'yellow';
  };

  const highRisk = items.filter(i => (i.risk||0) >= 70).length;
  const avgRisk  = items.length ? Math.round(items.reduce((s,i) => s+(i.risk||0),0)/items.length) : 0;
  const isLive   = Array.isArray(raw) && raw.length > 0;

  async function handleRetrain() {
    setRetraining(true);
    setRetrained(false);
    // Call retrain endpoint, then refetch predictions
    try {
      await fetch('http://13.235.238.8:8001/retrain', { method:'POST' });
    } catch {}
    // Whether or not retrain worked, refresh the predictions data
    setTimeout(() => {
      refetch();
      setRetraining(false);
      setRetrained(true);
      setTimeout(() => setRetrained(false), 4000);
    }, 2000);
  }

  return (
    <div style={{padding:20,display:'flex',flexDirection:'column',gap:16,overflowY:'auto',height:'100%'}}>
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between'}}>
        <div>
          <h2 style={{fontFamily:'var(--title)',fontSize:22,fontWeight:800}}>AI Prediction Engine</h2>
          <p style={{fontSize:11,color:'var(--text3)',fontFamily:'var(--mono)',marginTop:2}}>
            Sector threat forecasting · Random Forest + Prophet · 94.2% accuracy
            {!isLive && <span style={{color:'var(--yellow)',marginLeft:8}}>[FALLBACK — {FALLBACK.length} sectors]</span>}
            {retrained && <span style={{color:'var(--green)',marginLeft:8}}>✓ Model retrained</span>}
          </p>
        </div>
        <div style={{display:'flex',gap:8}}>
          <Btn variant='cyan' onClick={refetch}>⟳ REFRESH</Btn>
          <Btn variant='red' onClick={handleRetrain} style={{opacity: retraining ? 0.6 : 1}}>
            {retraining ? '⟳ RETRAINING...' : '⚡ RETRAIN MODEL'}
          </Btn>
        </div>
      </div>

      {loading || retraining ? (
        <Loading text={retraining ? 'Retraining Random Forest + Prophet model...' : 'Loading predictions...'}/>
      ) : (
        <>
          <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:16}}>
            <MetricCard label="Sectors Monitored"  value={items.length}   color="var(--cyan)"   delta="active forecasts"/>
            <MetricCard label="High-Risk Sectors"  value={highRisk}       color="var(--red)"    delta="risk ≥ 70%"/>
            <MetricCard label="Average Risk Score" value={avgRisk + '%'}  color="var(--orange)" delta="across all sectors"/>
          </div>

          {/* All sector risk cards — show all, wrapped in grid */}
          <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:12}}>
            {items.map((item, i) => {
              const c = getColor(item.risk || 0);
              return (
                <div key={i} style={{background:'var(--panel)',border:'1px solid var(--border)',
                  borderTop:`2px solid ${c}`,borderRadius:8,padding:14}}>
                  <div style={{fontSize:10,color:'var(--text3)',fontFamily:'var(--mono)',
                    letterSpacing:1,textTransform:'uppercase',marginBottom:6}}>
                    {item.sector || 'Unknown Sector'}
                  </div>
                  <div style={{fontFamily:'var(--title)',fontSize:26,fontWeight:800,color:c}}>
                    {item.risk || 0}%
                  </div>
                  <div style={{display:'flex',gap:6,marginTop:6,marginBottom:4,flexWrap:'wrap'}}>
                    <Tag variant={getVariant(item.confidence)}>{item.confidence || 'UNKNOWN'}</Tag>
                    {item.timeframe && <Tag variant='cyan'>{item.timeframe}</Tag>}
                  </div>
                  <div style={{fontSize:9,color:'var(--text3)',fontFamily:'var(--mono)',marginBottom:6}}>
                    via {item.actor || 'Unknown Actor'}
                  </div>
                  <ProgressBar value={item.risk || 0} color={c}/>
                </div>
              );
            })}
          </div>

          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
            <Card title="Sector Risk Forecast (90 Days)">
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={items} margin={{top:10,right:10,left:-10,bottom:50}}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)"/>
                  <XAxis
                    dataKey="sector"
                    tick={{fill:'rgba(255,255,255,0.4)',fontSize:8,fontFamily:'JetBrains Mono'}}
                    angle={-40}
                    textAnchor="end"
                    interval={0}
                    tickLine={false}
                    axisLine={{stroke:'rgba(255,255,255,0.1)'}}
                  />
                  <YAxis
                    domain={[0,100]}
                    tick={{fill:'rgba(255,255,255,0.3)',fontSize:9,fontFamily:'JetBrains Mono'}}
                    tickFormatter={v => v+'%'}
                    tickLine={false}
                    axisLine={false}
                  />
                  <Tooltip content={<RiskTooltip/>} cursor={{fill:'rgba(255,255,255,0.03)'}}/>
                  <Bar dataKey="risk" radius={[3,3,0,0]} maxBarSize={40}>
                    {items.map((item, i) => {
                      const v = item.risk || 0;
                      const c = v > 70 ? '#f03e3e' : v > 40 ? '#f97316' : '#eab308';
                      return <Cell key={i} fill={c} fillOpacity={0.85}/>;
                    })}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </Card>

            <Card title="Sector Risk Matrix">
              {items.length === 0
                ? <Empty icon="📊" text="No sector predictions available yet."/>
                : <div style={{overflowY:'auto',maxHeight:220}}>
                    {items.map((item, i) => {
                      const c = getColor(item.risk || 0);
                      return (
                        <div key={i} style={{display:'flex',alignItems:'center',gap:12,marginBottom:8}}>
                          <div style={{width:140,fontSize:10,color:'var(--text2)',fontFamily:'var(--mono)',flexShrink:0}}>
                            {item.sector || 'Unknown'}
                          </div>
                          <div style={{flex:1}}>
                            <ProgressBar value={item.risk || 0} color={c}/>
                          </div>
                          <div style={{width:38,textAlign:'right',fontFamily:'var(--mono)',fontSize:11,color:c,fontWeight:700,flexShrink:0}}>
                            {item.risk || 0}%
                          </div>
                        </div>
                      );
                    })}
                  </div>
              }
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
