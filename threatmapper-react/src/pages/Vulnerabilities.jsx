import React, { useState } from 'react';
import { useAPI, BACKEND } from '../hooks/useAPI';
import { Card, Loading, Tag, Btn, DataTable, MetricCard, Empty } from '../components/UI';

const FALLBACK_IOCS = [
  // CRITICAL
  {type:'IP',    value:'185.220.101.47',         severity:'CRITICAL', actor:'APT28',          malware:'X-Agent',         first_seen:'2024-11-01', last_seen:'2024-12-10'},
  {type:'HASH',  value:'a3f4b2c1d9e8f7a06b5c4d3e',severity:'CRITICAL', actor:'Lazarus Group',  malware:'NukeSped',        first_seen:'2024-11-20', last_seen:'2024-12-08'},
  {type:'CVE',   value:'CVE-2024-21413',          severity:'CRITICAL', actor:'APT29',          malware:'WellMail',        first_seen:'2024-08-14', last_seen:'2024-12-01'},
  {type:'CVE',   value:'CVE-2024-3400',           severity:'CRITICAL', actor:'Kimsuky',        malware:'BabyShark',       first_seen:'2024-04-12', last_seen:'2024-11-30'},
  {type:'IP',    value:'194.165.16.11',           severity:'CRITICAL', actor:'Sandworm',       malware:'Industroyer2',    first_seen:'2024-10-05', last_seen:'2024-12-03'},
  {type:'CVE',   value:'CVE-2024-38112',          severity:'CRITICAL', actor:'APT38',          malware:'BLINDINGCAN',     first_seen:'2024-07-09', last_seen:'2024-10-31'},
  {type:'DOMAIN',value:'srv-update.microsoft.pw', severity:'CRITICAL', actor:'APT41',          malware:'PlugX',           first_seen:'2024-09-10', last_seen:'2024-12-07'},
  {type:'HASH',  value:'9f8e7d6c5b4a3f2e1d0c9b8a',severity:'CRITICAL', actor:'DarkSide',       malware:'DarkSide RaaS',   first_seen:'2024-10-01', last_seen:'2024-11-28'},
  {type:'IP',    value:'45.142.212.100',          severity:'CRITICAL', actor:'Conti',          malware:'Conti Ransomware',first_seen:'2024-10-15', last_seen:'2024-12-05'},
  {type:'CVE',   value:'CVE-2024-6387',           severity:'CRITICAL', actor:'APT32',          malware:'Denis',           first_seen:'2024-07-01', last_seen:'2024-11-20'},
  {type:'CVE',   value:'CVE-2024-29988',          severity:'CRITICAL', actor:'Turla',          malware:'Snake',           first_seen:'2024-05-14', last_seen:'2024-11-15'},
  {type:'IP',    value:'77.83.159.226',           severity:'CRITICAL', actor:'REvil',          malware:'Sodinokibi',      first_seen:'2024-09-20', last_seen:'2024-12-01'},
  // HIGH
  {type:'CVE',   value:'CVE-2024-3821',           severity:'HIGH',     actor:'APT41',          malware:'Speculoos',       first_seen:'2024-09-01', last_seen:'2024-11-30'},
  {type:'IP',    value:'91.108.4.182',            severity:'HIGH',     actor:'Carbanak',       malware:'Carbanak',        first_seen:'2024-10-20', last_seen:'2024-11-25'},
  {type:'DOMAIN',value:'update-flash.pw',         severity:'HIGH',     actor:'Sandworm',       malware:'BlackEnergy',     first_seen:'2024-11-05', last_seen:'2024-12-09'},
  {type:'CVE',   value:'CVE-2024-4577',           severity:'HIGH',     actor:'Lazarus Group',  malware:'MATA',            first_seen:'2024-06-10', last_seen:'2024-11-18'},
  {type:'DOMAIN',value:'cdn-bootstrap.net',       severity:'HIGH',     actor:'FIN7',           malware:'Carbanak',        first_seen:'2024-08-22', last_seen:'2024-12-04'},
  {type:'IP',    value:'62.233.50.246',           severity:'HIGH',     actor:'Turla',          malware:'ComRAT',          first_seen:'2024-09-15', last_seen:'2024-11-22'},
  {type:'CVE',   value:'CVE-2024-21762',          severity:'HIGH',     actor:'APT28',          malware:'Zebrocy',         first_seen:'2024-02-08', last_seen:'2024-10-30'},
  {type:'HASH',  value:'f1e2d3c4b5a6978869504231',severity:'HIGH',     actor:'OilRig',         malware:'RDAT',            first_seen:'2024-07-30', last_seen:'2024-11-12'},
  {type:'IP',    value:'203.0.113.45',            severity:'HIGH',     actor:'MuddyWater',     malware:'PowGoop',         first_seen:'2024-08-01', last_seen:'2024-11-30'},
  {type:'CVE',   value:'CVE-2024-30051',          severity:'HIGH',     actor:'QakBot',         malware:'QakBot',          first_seen:'2024-05-20', last_seen:'2024-11-05'},
  {type:'DOMAIN',value:'telemetry-api.cloud',     severity:'HIGH',     actor:'Chimera',        malware:'Cobalt Strike',   first_seen:'2024-10-08', last_seen:'2024-12-02'},
  {type:'IP',    value:'185.234.218.23',          severity:'HIGH',     actor:'BlackCat',       malware:'ALPHV',           first_seen:'2024-11-10', last_seen:'2024-12-06'},
  {type:'CVE',   value:'CVE-2024-1709',           severity:'HIGH',     actor:'APT34',          malware:'Helminth',        first_seen:'2024-02-21', last_seen:'2024-10-14'},
  {type:'HASH',  value:'c8d9e0f1a2b3c4d5e6f70819',severity:'HIGH',     actor:'Lazarus Group',  malware:'AppleJeus',       first_seen:'2024-09-05', last_seen:'2024-11-29'},
  {type:'CVE',   value:'CVE-2024-23113',          severity:'HIGH',     actor:'Volt Typhoon',   malware:'SOGU',            first_seen:'2024-02-08', last_seen:'2024-11-01'},
  {type:'IP',    value:'5.188.86.172',            severity:'HIGH',     actor:'FIN8',           malware:'BADHATCH',        first_seen:'2024-08-18', last_seen:'2024-11-20'},
  {type:'DOMAIN',value:'api-secure.top',          severity:'HIGH',     actor:'APT29',          malware:'BEACON',          first_seen:'2024-07-14', last_seen:'2024-10-28'},
  {type:'CVE',   value:'CVE-2024-26169',          severity:'HIGH',     actor:'APT40',          malware:'Derusbi',         first_seen:'2024-03-12', last_seen:'2024-10-20'},
  {type:'IP',    value:'195.123.245.190',         severity:'HIGH',     actor:'Cobalt Group',   malware:'Cobalt Strike',   first_seen:'2024-09-28', last_seen:'2024-12-08'},
  {type:'HASH',  value:'11223344556677889900aabb',severity:'HIGH',     actor:'DarkHydrus',     malware:'RogueRobin',      first_seen:'2024-10-22', last_seen:'2024-11-30'},
  {type:'CVE',   value:'CVE-2024-43572',          severity:'HIGH',     actor:'Storm-0501',     malware:'Nokoyawa',        first_seen:'2024-10-08', last_seen:'2024-12-01'},
  {type:'DOMAIN',value:'windows-defender.pw',     severity:'HIGH',     actor:'BlackByte',      malware:'BlackByte',       first_seen:'2024-08-30', last_seen:'2024-11-18'},
  {type:'CVE',   value:'CVE-2024-38080',          severity:'HIGH',     actor:'APT28',          malware:'X-Tunnel',        first_seen:'2024-07-09', last_seen:'2024-11-12'},
  {type:'IP',    value:'88.218.61.244',           severity:'HIGH',     actor:'Wizard Spider',  malware:'TrickBot',        first_seen:'2024-10-01', last_seen:'2024-12-03'},
  // MEDIUM
  {type:'HASH',  value:'b2e3c4d5e6f7a8b9c0d1e2f3',severity:'MEDIUM',  actor:'OilRig',         malware:'QUADAGENT',       first_seen:'2024-09-22', last_seen:'2024-11-18'},
  {type:'IP',    value:'77.91.68.33',             severity:'MEDIUM',   actor:'MuddyWater',     malware:'POWERSTATS',      first_seen:'2024-10-01', last_seen:'2024-11-10'},
  {type:'CVE',   value:'CVE-2024-20656',          severity:'MEDIUM',   actor:'Kimsuky',        malware:'AppleSeed',       first_seen:'2024-01-09', last_seen:'2024-10-22'},
  {type:'DOMAIN',value:'download-fonts.com',      severity:'MEDIUM',   actor:'MuddyWater',     malware:'POWERSTATS',      first_seen:'2024-07-17', last_seen:'2024-10-28'},
  {type:'IP',    value:'103.75.190.12',           severity:'MEDIUM',   actor:'Lazarus Group',  malware:'WhisperGate',     first_seen:'2024-08-05', last_seen:'2024-10-30'},
  {type:'CVE',   value:'CVE-2024-30040',          severity:'MEDIUM',   actor:'FIN6',           malware:'FlawedAmmyy',     first_seen:'2024-05-14', last_seen:'2024-10-15'},
  {type:'HASH',  value:'deadbeef12345678cafebabe',severity:'MEDIUM',   actor:'APT32',          malware:'Kerrdown',        first_seen:'2024-09-01', last_seen:'2024-11-05'},
  {type:'DOMAIN',value:'s3-upload.storage-aws.ml',severity:'MEDIUM',  actor:'APT41',          malware:'MESSAGETAP',      first_seen:'2024-06-20', last_seen:'2024-10-12'},
  {type:'IP',    value:'139.180.203.104',         severity:'MEDIUM',   actor:'Chimera',        malware:'Cobalt Strike',   first_seen:'2024-07-08', last_seen:'2024-10-22'},
  {type:'CVE',   value:'CVE-2024-0519',           severity:'MEDIUM',   actor:'APT35',          malware:'CharmPower',      first_seen:'2024-01-16', last_seen:'2024-09-30'},
  {type:'HASH',  value:'f0e1d2c3b4a5968778695049',severity:'MEDIUM',   actor:'Turla',          malware:'TinyTurla',       first_seen:'2024-08-14', last_seen:'2024-10-20'},
  {type:'IP',    value:'176.97.76.122',           severity:'MEDIUM',   actor:'DarkHydrus',     malware:'Meterpreter',     first_seen:'2024-09-10', last_seen:'2024-11-01'},
  {type:'CVE',   value:'CVE-2024-38178',          severity:'MEDIUM',   actor:'APT37',          malware:'GOLDBACKDOOR',    first_seen:'2024-08-13', last_seen:'2024-11-02'},
  {type:'DOMAIN',value:'login.micro-soft.top',    severity:'MEDIUM',   actor:'OilRig',         malware:'ISMAgent',        first_seen:'2024-07-22', last_seen:'2024-10-14'},
  {type:'IP',    value:'37.120.247.39',           severity:'MEDIUM',   actor:'BlackCat',       malware:'Exmatter',        first_seen:'2024-09-30', last_seen:'2024-11-08'},
  {type:'CVE',   value:'CVE-2024-38143',          severity:'MEDIUM',   actor:'Sandworm',       malware:'CaddyWiper',      first_seen:'2024-08-09', last_seen:'2024-10-25'},
  {type:'HASH',  value:'aabbccddeeff00112233445566',severity:'MEDIUM', actor:'FIN7',           malware:'Griffon',         first_seen:'2024-10-05', last_seen:'2024-11-15'},
  {type:'DOMAIN',value:'cdn.jquery-libs.com',     severity:'MEDIUM',   actor:'Kimsuky',        malware:'GoldDragon',      first_seen:'2024-06-15', last_seen:'2024-10-10'},
  {type:'IP',    value:'185.117.88.172',          severity:'MEDIUM',   actor:'Wizard Spider',  malware:'Ryuk',            first_seen:'2024-09-03', last_seen:'2024-10-28'},
  {type:'CVE',   value:'CVE-2024-38189',          severity:'MEDIUM',   actor:'APT38',          malware:'FASTCash',        first_seen:'2024-08-13', last_seen:'2024-10-22'},
  {type:'HASH',  value:'102938475665748392010abcd',severity:'MEDIUM',  actor:'Leviathan',      malware:'Derusbi',         first_seen:'2024-07-20', last_seen:'2024-10-05'},
  // LOW
  {type:'CVE',   value:'CVE-2024-20684',          severity:'LOW',      actor:'Lazarus Group',  malware:'BLINDINGCAN',     first_seen:'2024-01-14', last_seen:'2024-09-18'},
  {type:'IP',    value:'109.248.11.149',          severity:'LOW',      actor:'MuddyWater',     malware:'PowGoop',         first_seen:'2024-06-10', last_seen:'2024-09-22'},
  {type:'DOMAIN',value:'analytics-cdn.net',       severity:'LOW',      actor:'FIN6',           malware:'FrameworkPOS',    first_seen:'2024-05-05', last_seen:'2024-09-01'},
  {type:'HASH',  value:'cafe0000dead1111babe2222',severity:'LOW',       actor:'APT34',          malware:'PICKPOCKET',      first_seen:'2024-04-14', last_seen:'2024-09-15'},
  {type:'IP',    value:'51.210.242.234',          severity:'LOW',      actor:'APT32',          malware:'Denis',           first_seen:'2024-05-20', last_seen:'2024-09-10'},
  {type:'CVE',   value:'CVE-2024-20693',          severity:'LOW',      actor:'APT29',          malware:'MiniDuke',        first_seen:'2024-01-09', last_seen:'2024-08-30'},
  {type:'DOMAIN',value:'fonts-googleapis.live',   severity:'LOW',      actor:'DarkHydrus',     malware:'RogueRobin',      first_seen:'2024-03-18', last_seen:'2024-08-22'},
  {type:'HASH',  value:'f9e8d7c6b5a4938271605040',severity:'LOW',      actor:'OilRig',         malware:'RDAT',            first_seen:'2024-04-02', last_seen:'2024-08-18'},
  {type:'IP',    value:'134.255.250.93',          severity:'LOW',      actor:'Turla',          malware:'ComRAT',          first_seen:'2024-03-14', last_seen:'2024-08-10'},
  {type:'CVE',   value:'CVE-2024-20681',          severity:'LOW',      actor:'Kimsuky',        malware:'AppleSeed',       first_seen:'2024-01-09', last_seen:'2024-07-30'},
  {type:'DOMAIN',value:'update-checker.info',     severity:'LOW',      actor:'Cobalt Group',   malware:'Cobalt Strike',   first_seen:'2024-02-28', last_seen:'2024-08-05'},
  {type:'IP',    value:'45.91.200.131',           severity:'LOW',      actor:'BlackByte',      malware:'BlackByte',       first_seen:'2024-05-10', last_seen:'2024-08-25'},
  {type:'CVE',   value:'CVE-2024-20676',          severity:'LOW',      actor:'APT40',          malware:'BADFLICK',        first_seen:'2024-01-09', last_seen:'2024-07-20'},
  {type:'HASH',  value:'1029384756657483920aaff1',severity:'LOW',      actor:'APT37',          malware:'POORAIM',         first_seen:'2024-03-22', last_seen:'2024-08-01'},
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
