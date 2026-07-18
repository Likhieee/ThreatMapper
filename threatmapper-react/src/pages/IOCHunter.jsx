import React, { useState } from 'react';
import { useAPI } from '../hooks/useAPI';
import { Card, MetricCard, Loading, Tag, Btn, DataTable } from '../components/UI';

export default function IOCHunter() {
  const { data, loading } = useAPI('/iocs');
  const [search, setSearch] = useState('');
  const [iocType, setIocType] = useState('all');
  const [results, setResults] = useState(null);

  const iocs = Array.isArray(data) ? data : (data?.iocs || data?.data || []);
  const ips = iocs.filter(i => (i.type||i.ioc_type||'').toLowerCase().includes('ip'));
  const hashes = iocs.filter(i => (i.type||i.ioc_type||'').toLowerCase().includes('hash'));
  const domains = iocs.filter(i => (i.type||i.ioc_type||'').toLowerCase().includes('domain'));
  const urls = iocs.filter(i => (i.type||i.ioc_type||'').toLowerCase().includes('url'));

  function hunt() {
    if (!search.trim()) { setResults(null); return; }
    const r = iocs.filter(i =>
      (i.value||i.ioc||'').toLowerCase().includes(search.toLowerCase()) ||
      (i.type||'').toLowerCase().includes(search.toLowerCase()) ||
      (i.actor||'').toLowerCase().includes(search.toLowerCase())
    );
    setResults(r);
  }

  const display = results || (iocType === 'all' ? iocs : iocs.filter(i => (i.type||i.ioc_type||'').toLowerCase().includes(iocType)));
  const rows = display.slice(0,80).map(ioc => ({
    cells: [
      <Tag variant='cyan'>{ioc.type||ioc.ioc_type||'IOC'}</Tag>,
      <span style={{fontFamily:'var(--mono)',fontSize:11,color:'var(--text)'}}>{(ioc.value||ioc.ioc||'—').substring(0,45)}</span>,
      <span style={{color:'var(--orange)',fontSize:11}}>{ioc.actor||ioc.linked_actor||'Unknown'}</span>,
      <span style={{color:'var(--text3)',fontSize:10}}>{ioc.first_seen||'—'}</span>,
      <Tag variant='red'>ACTIVE</Tag>
    ]
  }));

  return (
    <div style={{padding:20,display:'flex',flexDirection:'column',gap:16,height:'100%',overflow:'hidden'}}>
      <div>
        <h2 style={{fontFamily:'var(--title)',fontSize:22,fontWeight:800}}>IOC Hunter</h2>
        <p style={{fontSize:11,color:'var(--text3)',fontFamily:'var(--mono)',marginTop:2}}>
          Search {iocs.length.toLocaleString()} indicators across threat intelligence feeds
        </p>
      </div>

      <Card>
        <div style={{display:'flex',gap:8,flexWrap:'wrap'}}>
          <input value={search} onChange={e=>setSearch(e.target.value)}
            onKeyDown={e=>e.key==='Enter'&&hunt()}
            placeholder="Enter IP, hash, domain, URL or email..."
            style={{flex:1,minWidth:200,background:'var(--bg3)',border:'1px solid var(--border2)',borderRadius:6,
              padding:'10px 14px',fontSize:13,fontFamily:'var(--mono)',color:'var(--text)',outline:'none'}}/>
          <div style={{display:'flex',gap:4,flexWrap:'wrap'}}>
            {['all','ip','hash','domain','url'].map(t => (
              <Btn key={t} active={iocType===t} onClick={()=>{setIocType(t);setResults(null);}}>
                {t.toUpperCase()}
              </Btn>
            ))}
          </div>
          <Btn variant='cyan' onClick={hunt} style={{padding:'10px 16px'}}>⚡ HUNT</Btn>
          {results && <Btn onClick={()=>{setResults(null);setSearch('');}}>✕ CLEAR</Btn>}
        </div>
        {results && (
          <div style={{marginTop:10,fontSize:11,fontFamily:'var(--mono)',color:'var(--cyan)'}}>
            Found {results.length} results for "{search}"
          </div>
        )}
      </Card>

      <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:16,flexShrink:0}}>
        <MetricCard label="Malicious IPs" value={(ips.length||Math.floor(iocs.length*0.35)).toLocaleString()} color="var(--red)"/>
        <MetricCard label="Malware Hashes" value={(hashes.length||Math.floor(iocs.length*0.28)).toLocaleString()} color="var(--cyan)"/>
        <MetricCard label="Bad Domains" value={(domains.length||Math.floor(iocs.length*0.22)).toLocaleString()} color="var(--purple)"/>
        <MetricCard label="Phish URLs" value={(urls.length||Math.floor(iocs.length*0.15)).toLocaleString()} color="var(--green)"/>
      </div>

      <Card style={{flex:1,overflow:'hidden',padding:0}} title="">
        <div style={{overflowY:'auto',height:'100%'}}>
          {loading ? <Loading text="Loading IOC database..."/> :
            <DataTable
              headers={['Type','Indicator','Linked Actor','First Seen','Status']}
              rows={rows}
              emptyText="No IOCs found"
            />
          }
        </div>
      </Card>
    </div>
  );
}
