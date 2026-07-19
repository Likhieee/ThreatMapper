import React, { useState } from 'react';
import { useAPI } from '../hooks/useAPI';
import { Card, Loading, Tag, Btn, SearchInput, DataTable } from '../components/UI';

export default function ThreatActors() {
  const { data, loading } = useAPI('/actors');

  // Handle both formats: array of strings OR array of objects
  const rawActors = Array.isArray(data) ? data : (data?.actors || []);
  const actors = rawActors.map(a => {
    if (typeof a === 'string') {
      return { name: a, origin: 'Unknown', aliases: '', malware: [] };
    }
    return a;
  });

  const [search, setSearch] = useState('');
  const filtered = actors.filter(a => {
    const name = (a.name||a.actor||'').toLowerCase();
    return !search || name.includes(search.toLowerCase());
  });

  const rows = filtered.slice(0,80).map(a => ({
    cells: [
      <span style={{fontFamily:'var(--mono)',color:'var(--red2)',fontWeight:700}}>{a.name||a.actor||'Unknown'}</span>,
      <Tag variant='cyan'>{a.origin||a.country||'MITRE ATT&CK'}</Tag>,
      <span style={{fontSize:10,color:'var(--text3)'}}>{Array.isArray(a.aliases)?a.aliases.slice(0,2).join(', '):(a.aliases||'—')}</span>,
      <span style={{fontFamily:'var(--mono)',fontSize:10,color:'var(--orange)'}}>{Array.isArray(a.malware)?a.malware.slice(0,2).join(', '):(a.tools||[]).slice(0,2).join(', ')||'View profile'}</span>,
      <Tag variant='red'>HIGH</Tag>,
      <Btn onClick={()=>alert(`Actor: ${a.name||a.actor}\nSource: MITRE ATT&CK / AlienVault OTX Knowledge Graph`)}>PROFILE →</Btn>
    ]
  }));

  return (
    <div style={{padding:20,display:'flex',flexDirection:'column',gap:16,height:'100%',overflow:'hidden'}}>
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',flexShrink:0}}>
        <div>
          <h2 style={{fontFamily:'var(--title)',fontSize:22,fontWeight:800}}>Threat Actors</h2>
          <p style={{fontSize:11,color:'var(--text3)',fontFamily:'var(--mono)',marginTop:2}}>
            MITRE ATT&CK + AlienVault OTX — {actors.length} groups tracked
          </p>
        </div>
      </div>
      <div style={{flexShrink:0}}>
        <SearchInput value={search} onChange={setSearch} onSearch={()=>{}} placeholder="Search threat actors..."/>
      </div>
      <Card style={{flex:1,overflow:'hidden',padding:0}}>
        <div style={{overflowY:'auto',height:'100%'}}>
          {loading ? <Loading text="Loading threat actors..."/> :
            <DataTable
              headers={['Actor','Source','Aliases','Malware Used','Severity','Action']}
              rows={rows}
              emptyText="No actors found"
            />
          }
        </div>
      </Card>
    </div>
  );
}