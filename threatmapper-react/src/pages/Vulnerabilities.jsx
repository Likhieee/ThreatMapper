import React, { useState } from 'react';
import { useAPI } from '../hooks/useAPI';
import { Card, Loading, Tag, Btn, DataTable } from '../components/UI';

export default function Vulnerabilities() {
  const { data, loading } = useAPI('/iocs');
  const [filter, setFilter] = useState('all');

  const iocs = Array.isArray(data) ? data : (data?.iocs || data?.data || []);
  const rows = iocs.slice(0,100).map(ioc => ({
    cells: [
      <Tag variant='red'>{ioc.type||ioc.ioc_type||'IOC'}</Tag>,
      <span style={{fontFamily:'var(--mono)',fontSize:11,color:'var(--cyan)'}}>{(ioc.value||ioc.ioc||'N/A').substring(0,50)}</span>,
      <span style={{color:'var(--text3)',fontSize:10}}>{ioc.first_seen||'—'}</span>,
      <span style={{color:'var(--text3)',fontSize:10}}>{ioc.first_seen||'—'}</span>,
      <Tag variant='red'>ACTIVE</Tag>
    ]
  }));

  return (
    <div style={{padding:20,display:'flex',flexDirection:'column',gap:16,height:'100%',overflow:'hidden'}}>
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',flexShrink:0}}>
        <div>
          <h2 style={{fontFamily:'var(--title)',fontSize:22,fontWeight:800}}>Vulnerabilities</h2>
          <p style={{fontSize:11,color:'var(--text3)',fontFamily:'var(--mono)',marginTop:2}}>CISA KEV + NVD CVE Database</p>
        </div>
        <div style={{display:'flex',gap:4}}>
          {['all','critical','high','medium'].map(f => (
            <Btn key={f} active={filter===f} onClick={()=>setFilter(f)}>{f.toUpperCase()}</Btn>
          ))}
        </div>
      </div>
      <Card style={{flex:1,overflow:'hidden',padding:0}}>
        <div style={{overflowY:'auto',height:'100%'}}>
          {loading ? <Loading text="Loading vulnerabilities..."/> :
            <DataTable headers={['Type','Indicator','First Seen','Last Seen','Status']} rows={rows} emptyText="No vulnerabilities found"/>
          }
        </div>
      </Card>
    </div>
  );
}
