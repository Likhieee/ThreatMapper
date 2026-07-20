import React, { useState } from 'react';
import { useAPI, BACKEND } from '../hooks/useAPI';
import { Card, Loading, Tag, Btn, DataTable, MetricCard, Empty } from '../components/UI';

const FALLBACK_IOCS = [
  {type:'IP',    value:'185.220.101.47',  severity:'CRITICAL', actor:'APT28',        first_seen:'2024-11-01', last_seen:'2024-12-10'},
  {type:'HASH',  value:'a3f4b2c1d9e8f7a0', severity:'CRITICAL', actor:'Lazarus Group', first_seen:'2024-11-20', last_seen:'2024-12-08'},
  {type:'URL',   value:'malware.c2-evil.net/stage2', severity:'HIGH', actor:'FIN7',   first_seen:'2024-10-15', last_seen:'2024-12-05'},
  {type:'CVE',   value:'CVE-2024-3821',   severity:'HIGH',     actor:'APT41',        first_seen:'2024-09-01', last_seen:'2024-11-30'},
  {type:'IP',    value:'91.108.4.182',    severity:'HIGH',     actor:'Carbanak',     first_seen:'2024-10-20', last_seen:'2024-11-25'},
  {type:'CVE',   value:'CVE-2024-21413', severity:'CRITICAL',  actor:'APT29',        first_seen:'2024-08-14', last_seen:'2024-12-01'},
  {type:'DOMAIN',value:'update-flash.pw', severity:'HIGH',     actor:'Sandworm',     first_seen:'2024-11-05', last_seen:'2024-12-09'},
  {type:'HASH',  value:'b2e3c4d5e6f7a8b9', severity:'MEDIUM',  actor:'OilRig',       first_seen:'2024-09-22', last_seen:'2024-11-18'},
  {type:'IP',    value:'77.91.68.33',     severity:'MEDIUM',   actor:'MuddyWater',   first_seen:'2024-10-01', last_seen:'2024-11-10'},
  {type:'CVE',   value:'CVE-2024-38112', severity:'HIGH',      actor:'APT38',        first_seen:'2024-07-09', last_seen:'2024-10-31'},
];

const SEVERITY_COLORS = {
  CRITICAL: 'red', HIGH: 'orange', MEDIUM: 'yellow', LOW: 'cyan'
};

export default function Vulnerabilities() {
  const { data: apiData, loading }    = useAPI('/iocs');
  const { data: backendData }         = useAPI('/iocs', BACKEND);
  const [filter, setFilter]           = useState('all');

  // /iocs from real API returns string[], from backend returns {iocs:[...objects]}
  let iocs = [];
  if (Array.isArray(apiData) && apiData.length > 0) {
    if (typeof apiData[0] === 'string') {
      // Real API: plain IOC value strings — wrap into display objects
      iocs = apiData.map(val => ({
        type: val.startsWith('CVE') ? 'CVE'
             : /^\d{1,3}(\.\d{1,3}){3}$/.test(val) ? 'IP'
             : val.includes('.') && !val.includes(' ') ? 'DOMAIN'
             : 'IOC',
        value: val,
        severity: 'HIGH',
        actor: '—',
        first_seen: '—',
        last_seen: '—',
      }));
    } else {
      iocs = apiData; // already objects
    }
  } else if (backendData?.iocs?.length > 0) {
    iocs = backendData.iocs;
  } else {
    iocs = FALLBACK_IOCS;
  }

  const filtered = filter === 'all'
    ? iocs
    : iocs.filter(i => (i.severity || '').toUpperCase() === filter.toUpperCase());

  const critCount = iocs.filter(i => (i.severity||'').toUpperCase() === 'CRITICAL').length;
  const highCount = iocs.filter(i => (i.severity||'').toUpperCase() === 'HIGH').length;

  const getSev = (ioc) => (ioc.severity || 'HIGH').toUpperCase();

  const rows = filtered.slice(0, 100).map(ioc => ({
    cells: [
      <Tag variant={SEVERITY_COLORS[getSev(ioc)] || 'cyan'}>{ioc.type || 'IOC'}</Tag>,
      <span style={{fontFamily:'var(--mono)',fontSize:11,color:'var(--cyan)'}}>
        {(ioc.value || ioc.indicator || ioc.ioc || 'N/A').substring(0, 48)}
      </span>,
      <Tag variant={SEVERITY_COLORS[getSev(ioc)] || 'yellow'}>{getSev(ioc)}</Tag>,
      <span style={{color:'var(--text3)',fontSize:10,fontFamily:'var(--mono)'}}>
        {ioc.actor || ioc.threat_actor || '—'}
      </span>,
      <span style={{color:'var(--text3)',fontSize:10}}>{ioc.first_seen || '—'}</span>,
      <span style={{color:'var(--text3)',fontSize:10}}>{ioc.last_seen  || ioc.last_updated || '—'}</span>,
      <Tag variant='red'>ACTIVE</Tag>,
    ]
  }));

  return (
    <div style={{padding:20,display:'flex',flexDirection:'column',gap:16,height:'100%',overflow:'hidden'}}>
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',flexShrink:0}}>
        <div>
          <h2 style={{fontFamily:'var(--title)',fontSize:22,fontWeight:800}}>Vulnerabilities & IOCs</h2>
          <p style={{fontSize:11,color:'var(--text3)',fontFamily:'var(--mono)',marginTop:2}}>
            CISA KEV + NVD CVE Database · {iocs.length} indicators tracked
          </p>
        </div>
        <div style={{display:'flex',gap:4}}>
          {['all','critical','high','medium'].map(f => (
            <Btn key={f} active={filter===f} onClick={()=>setFilter(f)}>{f.toUpperCase()}</Btn>
          ))}
        </div>
      </div>

      <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:12,flexShrink:0}}>
        <MetricCard label="Total IOCs"      value={iocs.length}  color="var(--cyan)"   delta="tracked indicators"/>
        <MetricCard label="Critical"        value={critCount}    color="var(--red)"    delta="immediate action"/>
        <MetricCard label="High Severity"   value={highCount}    color="var(--orange)" delta="urgent review"/>
        <MetricCard label="Showing"         value={filtered.length} color="var(--purple)" delta={`${filter} filter`}/>
      </div>

      <Card style={{flex:1,overflow:'hidden',padding:0}}>
        <div style={{overflowY:'auto',height:'100%'}}>
          {loading
            ? <Loading text="Loading IOCs from Neo4j..."/>
            : rows.length === 0
              ? <Empty icon="🛡" text={`No ${filter} severity IOCs found.`}/>
              : <DataTable
                  headers={['Type','Indicator','Severity','Actor','First Seen','Last Seen','Status']}
                  rows={rows}
                  emptyText="No vulnerabilities found"
                />
          }
        </div>
      </Card>
    </div>
  );
}
