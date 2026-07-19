import React, { useState } from 'react';
import axios from 'axios';
import { useAPI, API } from '../hooks/useAPI';
import { Card, Loading, Tag, Btn, SearchInput, DataTable } from '../components/UI';

export default function ThreatActors() {
  const { data, loading } = useAPI('/actors');
  const [selected, setSelected] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const rawActors = Array.isArray(data) ? data : (data?.actors || []);
  const actors = rawActors.map(a => typeof a === 'string' ? { name: a } : a);

  const [search, setSearch] = useState('');
  const filtered = actors.filter(a => {
    const name = (a.name||'').toLowerCase();
    return !search || name.includes(search.toLowerCase());
  });

  async function openProfile(name) {
    setDetailLoading(true);
    setSelected({ name, loading: true });
    try {
      const res = await axios.get(`${API}/actor/${encodeURIComponent(name)}`, { timeout: 8000 });
      setSelected({ name, ...res.data, loading: false });
    } catch(e) {
      setSelected({ name, description: 'No detailed intelligence available for this actor yet.', loading: false });
    }
    setDetailLoading(false);
  }

  const rows = filtered.slice(0,80).map(a => ({
    onClick: () => openProfile(a.name),
    cells: [
      <span style={{fontFamily:'var(--mono)',color:'var(--red2)',fontWeight:700}}>{a.name}</span>,
      <Tag variant='cyan'>MITRE ATT&CK</Tag>,
      <span style={{fontSize:10,color:'var(--text3)'}}>Click to view aliases</span>,
      <span style={{fontFamily:'var(--mono)',fontSize:10,color:'var(--orange)'}}>View profile →</span>,
      <Tag variant='red'>HIGH</Tag>,
      <Btn onClick={(e)=>{e.stopPropagation(); openProfile(a.name);}}>PROFILE →</Btn>
    ]
  }));

  return (
    <div style={{padding:20,display:'flex',flexDirection:'column',gap:16,height:'100%',overflow:'hidden',position:'relative'}}>
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
              headers={['Actor','Source','Aliases','Details','Severity','Action']}
              rows={rows}
              emptyText="No actors found"
            />
          }
        </div>
      </Card>

      {/* PROFILE MODAL */}
      {selected && (
        <div onClick={()=>setSelected(null)} style={{position:'fixed',inset:0,background:'rgba(0,0,0,0.7)',
          zIndex:1000,display:'flex',alignItems:'center',justifyContent:'center',backdropFilter:'blur(4px)'}}>
          <div onClick={e=>e.stopPropagation()} style={{background:'var(--panel)',border:'1px solid var(--border2)',
            borderRadius:10,padding:24,maxWidth:600,width:'90%',maxHeight:'80vh',overflowY:'auto',
            boxShadow:'0 20px 60px rgba(0,0,0,0.5)'}}>
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:16}}>
              <div>
                <div style={{fontFamily:'var(--title)',fontSize:24,fontWeight:800,color:'var(--red2)'}}>{selected.name}</div>
                <div style={{fontSize:10,color:'var(--text3)',fontFamily:'var(--mono)',marginTop:4}}>MITRE ATT&CK Threat Group Profile</div>
              </div>
              <Btn onClick={()=>setSelected(null)}>✕ CLOSE</Btn>
            </div>

            {selected.loading ? <Loading text="Fetching threat intelligence..."/> : (
              <>
                {selected.aliases && (
                  <div style={{marginBottom:16}}>
                    <div style={{fontSize:9,color:'var(--text3)',fontFamily:'var(--mono)',letterSpacing:1,marginBottom:8,textTransform:'uppercase'}}>Known Aliases</div>
                    <div style={{display:'flex',flexWrap:'wrap',gap:6}}>
                      {selected.aliases.split(',').map((alias,i) => (
                        <Tag key={i} variant='orange'>{alias.trim()}</Tag>
                      ))}
                    </div>
                  </div>
                )}
                <div>
                  <div style={{fontSize:9,color:'var(--text3)',fontFamily:'var(--mono)',letterSpacing:1,marginBottom:8,textTransform:'uppercase'}}>Intelligence Summary</div>
                  <div style={{fontSize:13,color:'var(--text2)',lineHeight:1.7}}>
                    {selected.description?.replace(/\[|\]|\(https?:\/\/[^\)]+\)/g, '') || 'No detailed description available.'}
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}