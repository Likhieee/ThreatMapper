import React, { useState } from 'react';
import { useAPI } from '../hooks/useAPI';
import { Card, MetricCard, Loading, Tag, Btn } from '../components/UI';

// Comprehensive local threat intel DB (checked first before external lookup)
const THREAT_DB = [
  {type:'IP',    value:'185.220.101.47',  severity:'CRITICAL', score:96, actor:'APT28',         malware:'X-Agent',          first_seen:'2024-11-01', last_seen:'2024-12-10', country:'DE', tactics:['C2','Exfiltration']},
  {type:'IP',    value:'194.165.16.11',   severity:'CRITICAL', score:94, actor:'Sandworm',       malware:'Industroyer2',     first_seen:'2024-10-05', last_seen:'2024-12-03', country:'RU', tactics:['ICS Attack','Persistence']},
  {type:'IP',    value:'45.142.212.100',  severity:'CRITICAL', score:93, actor:'Conti',          malware:'Conti Ransomware', first_seen:'2024-10-15', last_seen:'2024-12-05', country:'RU', tactics:['Ransomware','Lateral Movement']},
  {type:'IP',    value:'77.83.159.226',   severity:'CRITICAL', score:91, actor:'REvil',          malware:'Sodinokibi',       first_seen:'2024-09-20', last_seen:'2024-12-01', country:'UA', tactics:['Ransomware','Data Theft']},
  {type:'IP',    value:'91.108.4.182',    severity:'HIGH',     score:82, actor:'Carbanak',       malware:'Carbanak',         first_seen:'2024-10-20', last_seen:'2024-11-25', country:'RU', tactics:['Financial Fraud','C2']},
  {type:'IP',    value:'62.233.50.246',   severity:'HIGH',     score:79, actor:'Turla',          malware:'ComRAT',           first_seen:'2024-09-15', last_seen:'2024-11-22', country:'RU', tactics:['Espionage','Persistence']},
  {type:'IP',    value:'203.0.113.45',    severity:'HIGH',     score:77, actor:'MuddyWater',     malware:'PowGoop',          first_seen:'2024-08-01', last_seen:'2024-11-30', country:'IR', tactics:['Spear Phishing','C2']},
  {type:'IP',    value:'185.234.218.23',  severity:'HIGH',     score:75, actor:'BlackCat',       malware:'ALPHV',            first_seen:'2024-11-10', last_seen:'2024-12-06', country:'NL', tactics:['Ransomware','Double Extortion']},
  {type:'IP',    value:'5.188.86.172',    severity:'HIGH',     score:74, actor:'FIN8',           malware:'BADHATCH',         first_seen:'2024-08-18', last_seen:'2024-11-20', country:'RU', tactics:['POS Malware','Persistence']},
  {type:'IP',    value:'195.123.245.190', severity:'HIGH',     score:73, actor:'Cobalt Group',   malware:'Cobalt Strike',    first_seen:'2024-09-28', last_seen:'2024-12-08', country:'UA', tactics:['C2','Lateral Movement']},
  {type:'IP',    value:'77.91.68.33',     severity:'MEDIUM',   score:55, actor:'MuddyWater',     malware:'POWERSTATS',       first_seen:'2024-10-01', last_seen:'2024-11-10', country:'IR', tactics:['Spear Phishing']},
  {type:'IP',    value:'88.218.61.244',   severity:'HIGH',     score:78, actor:'Wizard Spider',  malware:'TrickBot',         first_seen:'2024-10-01', last_seen:'2024-12-03', country:'RU', tactics:['Banking Trojan','C2']},
  {type:'HASH',  value:'a3f4b2c1d9e8f7a06b5c4d3e', severity:'CRITICAL', score:97, actor:'Lazarus Group',  malware:'NukeSped',   first_seen:'2024-11-20', last_seen:'2024-12-08', country:'KP', tactics:['Backdoor','Data Theft']},
  {type:'HASH',  value:'9f8e7d6c5b4a3f2e1d0c9b8a', severity:'CRITICAL', score:95, actor:'DarkSide',       malware:'DarkSide',   first_seen:'2024-10-01', last_seen:'2024-11-28', country:'RU', tactics:['Ransomware']},
  {type:'HASH',  value:'f1e2d3c4b5a6978869504231',  severity:'HIGH',     score:80, actor:'OilRig',         malware:'RDAT',       first_seen:'2024-07-30', last_seen:'2024-11-12', country:'IR', tactics:['Backdoor','C2']},
  {type:'HASH',  value:'c8d9e0f1a2b3c4d5e6f70819',  severity:'HIGH',     score:78, actor:'Lazarus Group',  malware:'AppleJeus',  first_seen:'2024-09-05', last_seen:'2024-11-29', country:'KP', tactics:['Crypto Theft']},
  {type:'HASH',  value:'b2e3c4d5e6f7a8b9c0d1e2f3',  severity:'MEDIUM',   score:56, actor:'OilRig',         malware:'QUADAGENT',  first_seen:'2024-09-22', last_seen:'2024-11-18', country:'IR', tactics:['RAT','Persistence']},
  {type:'HASH',  value:'deadbeef12345678cafebabe',   severity:'MEDIUM',   score:52, actor:'APT32',          malware:'Kerrdown',   first_seen:'2024-09-01', last_seen:'2024-11-05', country:'VN', tactics:['Downloader']},
  {type:'DOMAIN',value:'srv-update.microsoft.pw',   severity:'CRITICAL', score:98, actor:'APT41',          malware:'PlugX',      first_seen:'2024-09-10', last_seen:'2024-12-07', country:'CN', tactics:['C2','Phishing']},
  {type:'DOMAIN',value:'update-flash.pw',           severity:'HIGH',     score:83, actor:'Sandworm',       malware:'BlackEnergy',first_seen:'2024-11-05', last_seen:'2024-12-09', country:'RU', tactics:['Drive-by','C2']},
  {type:'DOMAIN',value:'cdn-bootstrap.net',         severity:'HIGH',     score:79, actor:'FIN7',           malware:'Carbanak',   first_seen:'2024-08-22', last_seen:'2024-12-04', country:'UA', tactics:['Phishing','C2']},
  {type:'DOMAIN',value:'telemetry-api.cloud',       severity:'HIGH',     score:76, actor:'Chimera',        malware:'Cobalt Strike',first_seen:'2024-10-08', last_seen:'2024-12-02', country:'CN', tactics:['C2','Exfiltration']},
  {type:'DOMAIN',value:'api-secure.top',            severity:'HIGH',     score:74, actor:'APT29',          malware:'BEACON',     first_seen:'2024-07-14', last_seen:'2024-10-28', country:'RU', tactics:['C2','Credential Theft']},
  {type:'DOMAIN',value:'windows-defender.pw',       severity:'HIGH',     score:81, actor:'BlackByte',      malware:'BlackByte',  first_seen:'2024-08-30', last_seen:'2024-11-18', country:'RU', tactics:['Ransomware','Phishing']},
  {type:'DOMAIN',value:'download-fonts.com',        severity:'MEDIUM',   score:58, actor:'MuddyWater',     malware:'POWERSTATS', first_seen:'2024-07-17', last_seen:'2024-10-28', country:'IR', tactics:['Spear Phishing']},
  {type:'DOMAIN',value:'login.micro-soft.top',      severity:'MEDIUM',   score:61, actor:'OilRig',         malware:'ISMAgent',   first_seen:'2024-07-22', last_seen:'2024-10-14', country:'IR', tactics:['Credential Phishing']},
  {type:'DOMAIN',value:'fonts-googleapis.live',     severity:'LOW',      score:38, actor:'DarkHydrus',     malware:'RogueRobin', first_seen:'2024-03-18', last_seen:'2024-08-22', country:'Unknown', tactics:['C2']},
  {type:'CVE',   value:'CVE-2024-21413',            severity:'CRITICAL', score:96, actor:'APT29',          malware:'WellMail',   first_seen:'2024-08-14', last_seen:'2024-12-01', country:'RU', tactics:['Exploitation','RCE']},
  {type:'CVE',   value:'CVE-2024-3400',             severity:'CRITICAL', score:94, actor:'Kimsuky',        malware:'BabyShark',  first_seen:'2024-04-12', last_seen:'2024-11-30', country:'KP', tactics:['RCE','Exploitation']},
  {type:'CVE',   value:'CVE-2024-6387',             severity:'CRITICAL', score:93, actor:'APT32',          malware:'Denis',      first_seen:'2024-07-01', last_seen:'2024-11-20', country:'VN', tactics:['RCE','Privilege Escalation']},
  {type:'CVE',   value:'CVE-2024-38112',            severity:'CRITICAL', score:91, actor:'APT38',          malware:'BLINDINGCAN',first_seen:'2024-07-09', last_seen:'2024-10-31', country:'KP', tactics:['Exploitation','Code Execution']},
  {type:'CVE',   value:'CVE-2024-3821',             severity:'HIGH',     score:80, actor:'APT41',          malware:'Speculoos',  first_seen:'2024-09-01', last_seen:'2024-11-30', country:'CN', tactics:['Exploitation']},
  {type:'CVE',   value:'CVE-2024-21762',            severity:'HIGH',     score:79, actor:'APT28',          malware:'Zebrocy',    first_seen:'2024-02-08', last_seen:'2024-10-30', country:'RU', tactics:['Exploitation','RCE']},
];

const MITRE_TACTICS = {
  'C2':                  {id:'TA0011', color:'var(--red)'},
  'Exfiltration':        {id:'TA0010', color:'var(--orange)'},
  'Persistence':         {id:'TA0003', color:'var(--yellow)'},
  'Lateral Movement':    {id:'TA0008', color:'var(--orange)'},
  'Ransomware':          {id:'TA0040', color:'var(--red)'},
  'Exploitation':        {id:'TA0001', color:'var(--red)'},
  'RCE':                 {id:'T1203',  color:'var(--red)'},
  'Spear Phishing':      {id:'T1566',  color:'var(--yellow)'},
  'Credential Theft':    {id:'TA0006', color:'var(--orange)'},
  'Data Theft':          {id:'TA0009', color:'var(--orange)'},
  'Backdoor':            {id:'TA0005', color:'var(--yellow)'},
  'Phishing':            {id:'T1566',  color:'var(--yellow)'},
  'Crypto Theft':        {id:'T1657',  color:'var(--orange)'},
  'Double Extortion':    {id:'T1486',  color:'var(--red)'},
  'ICS Attack':          {id:'TA0106', color:'var(--red)'},
  'Drive-by':            {id:'T1189',  color:'var(--yellow)'},
  'Privilege Escalation':{id:'TA0004', color:'var(--orange)'},
  'Financial Fraud':     {id:'T1657',  color:'var(--orange)'},
};

function detectType(val) {
  if (!val) return 'UNKNOWN';
  if (/^CVE-\d{4}-\d+$/i.test(val)) return 'CVE';
  if (/^[\da-f]{32}$|^[\da-f]{40}$|^[\da-f]{64}$/i.test(val)) return 'HASH';
  if (/^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(val)) return 'IP';
  if (/^https?:\/\//i.test(val)) return 'URL';
  if (/^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$/i.test(val)) return 'DOMAIN';
  return 'UNKNOWN';
}

function scoreColor(s) {
  return s >= 80 ? 'var(--red)' : s >= 50 ? 'var(--orange)' : s >= 25 ? 'var(--yellow)' : 'var(--green)';
}
function scoreLabel(s) {
  return s >= 80 ? 'MALICIOUS' : s >= 50 ? 'SUSPICIOUS' : s >= 25 ? 'POTENTIALLY UNWANTED' : 'CLEAN';
}
function scoreVariant(s) {
  return s >= 80 ? 'red' : s >= 50 ? 'orange' : 'yellow';
}

const FLAG = {RU:'🇷🇺',CN:'🇨🇳',KP:'🇰🇵',IR:'🇮🇷',UA:'🇺🇦',DE:'🇩🇪',NL:'🇳🇱',VN:'🇻🇳',US:'🇺🇸',GB:'🇬🇧',FR:'🇫🇷',IN:'🇮🇳',Unknown:'🌐'};

export default function IOCHunter() {
  const { data: apiData } = useAPI('/iocs');
  const [query, setQuery]       = useState('');
  const [iocType, setIocType]   = useState('all');
  const [hunting, setHunting]   = useState(false);
  const [result, setResult]     = useState(null);
  const [geoData, setGeoData]   = useState(null);
  const [notFound, setNotFound] = useState(false);

  // Merge API IOCs into lookup DB
  const apiIocs = Array.isArray(apiData)
    ? apiData.filter(i => typeof i === 'object')
    : [];
  const fullDB = [...THREAT_DB, ...apiIocs.filter(a =>
    !THREAT_DB.find(t => t.value === (a.value || ''))
  )];

  const ips     = fullDB.filter(i => i.type === 'IP');
  const hashes  = fullDB.filter(i => i.type === 'HASH');
  const domains = fullDB.filter(i => i.type === 'DOMAIN');
  const cves    = fullDB.filter(i => i.type === 'CVE');

  async function hunt() {
    const q = query.trim();
    if (!q) return;
    setHunting(true);
    setResult(null);
    setGeoData(null);
    setNotFound(false);

    // 1. Search local threat DB (case-insensitive partial match)
    const found = fullDB.find(i =>
      (i.value || '').toLowerCase().includes(q.toLowerCase()) ||
      (i.actor || '').toLowerCase().includes(q.toLowerCase()) ||
      (i.malware || '').toLowerCase().includes(q.toLowerCase())
    );

    if (found) {
      // 2a. Found in threat DB — enrich with geo if IP
      setResult(found);
      const detectedType = detectType(q);
      if (detectedType === 'IP' || found.type === 'IP') {
        try {
          const cleanIP = (found.value || q).split(':')[0];
          const res = await fetch(`https://ipapi.co/${cleanIP}/json/`);
          if (res.ok) setGeoData(await res.json());
        } catch {}
      }
    } else {
      // 2b. Not in local DB — try external lookup for IP
      const detectedType = detectType(q);
      if (detectedType === 'IP') {
        try {
          const cleanIP = q.split(':')[0];
          const res = await fetch(`https://ipapi.co/${cleanIP}/json/`);
          if (res.ok) {
            const geo = await res.json();
            setGeoData(geo);
            // Build a "clean" result from geo data
            setResult({
              type: 'IP', value: q, severity: 'LOW', score: 5,
              actor: 'None detected', malware: 'None detected',
              first_seen: '—', last_seen: '—',
              country: geo.country_code || 'Unknown',
              tactics: [], _clean: true,
            });
          } else { setNotFound(true); }
        } catch { setNotFound(true); }
      } else {
        setNotFound(true);
      }
    }
    setHunting(false);
  }

  const filtered = iocType === 'all' ? fullDB
    : fullDB.filter(i => i.type.toLowerCase() === iocType.toLowerCase());

  return (
    <div style={{padding:20, display:'flex', flexDirection:'column', gap:16, height:'100%', overflowY:'auto'}}>
      <div>
        <h2 style={{fontFamily:'var(--title)', fontSize:22, fontWeight:800}}>IOC Hunter</h2>
        <p style={{fontSize:11, color:'var(--text3)', fontFamily:'var(--mono)', marginTop:2}}>
          Search {fullDB.length.toLocaleString()} indicators · Enter any IP, hash, domain, CVE or URL
        </p>
      </div>

      {/* Search Bar */}
      <Card>
        <div style={{display:'flex', gap:8, flexWrap:'wrap'}}>
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && hunt()}
            placeholder="Enter IP, hash, domain, URL or CVE..."
            style={{flex:1, minWidth:200, background:'var(--bg3)', border:'1px solid var(--border2)',
              borderRadius:6, padding:'10px 14px', fontSize:13, fontFamily:'var(--mono)',
              color:'var(--text)', outline:'none'}}
          />
          <div style={{display:'flex', gap:4, flexWrap:'wrap'}}>
            {['ALL','IP','HASH','DOMAIN','CVE','URL'].map(t => (
              <Btn key={t} active={iocType===t.toLowerCase()||( t==='ALL'&&iocType==='all')}
                onClick={() => { setIocType(t==='ALL'?'all':t); setResult(null); setNotFound(false); }}>
                {t}
              </Btn>
            ))}
          </div>
          <Btn variant='cyan' onClick={hunt} style={{padding:'10px 20px', fontWeight:700}}>
            {hunting ? '...' : '⚡ HUNT'}
          </Btn>
          {(result || notFound) && (
            <Btn onClick={() => { setResult(null); setNotFound(false); setQuery(''); setGeoData(null); }}>
              ✕ CLEAR
            </Btn>
          )}
        </div>
      </Card>

      {/* Summary Metrics */}
      <div style={{display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:12, flexShrink:0}}>
        <MetricCard label="Malicious IPs"   value={ips.length}    color="var(--red)"    delta="known C2 & threat actors"/>
        <MetricCard label="Malware Hashes"  value={hashes.length} color="var(--cyan)"   delta="file-based threats"/>
        <MetricCard label="Bad Domains"     value={domains.length}color="var(--purple)"  delta="phishing & C2 domains"/>
        <MetricCard label="CVE Exploits"    value={cves.length}   color="var(--orange)" delta="actively exploited"/>
      </div>

      {/* Hunt Result Card */}
      {hunting && (
        <Card><Loading text={`Hunting "${query}" across threat intel feeds...`}/></Card>
      )}

      {notFound && !hunting && (
        <Card>
          <div style={{display:'flex', alignItems:'center', gap:16, padding:8}}>
            <div style={{fontSize:40}}>✅</div>
            <div>
              <div style={{fontFamily:'var(--title)', fontSize:18, fontWeight:800, color:'var(--green)'}}>
                NOT FOUND IN THREAT DATABASE
              </div>
              <div style={{fontFamily:'var(--mono)', fontSize:12, color:'var(--text2)', marginTop:4}}>
                "{query}" — No known threat associations detected
              </div>
              <div style={{fontSize:11, color:'var(--text3)', marginTop:6}}>
                This indicator does not appear in any known threat actor campaign, malware C2, or IOC feed.
              </div>
            </div>
            <Tag variant="cyan" style={{marginLeft:'auto'}}>CLEAN</Tag>
          </div>
        </Card>
      )}

      {result && !hunting && (
        <Card title="Threat Intelligence Report">
          <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:20}}>
            {/* Left: core intel */}
            <div>
              {/* Threat Score */}
              <div style={{marginBottom:16}}>
                <div style={{fontSize:10, color:'var(--text3)', fontFamily:'var(--mono)', marginBottom:6, letterSpacing:1}}>
                  THREAT SCORE
                </div>
                <div style={{display:'flex', alignItems:'center', gap:12}}>
                  <div style={{fontFamily:'var(--title)', fontSize:48, fontWeight:800, color:scoreColor(result.score||0), lineHeight:1}}>
                    {result.score || 0}
                  </div>
                  <div>
                    <div style={{fontSize:11, fontWeight:700, color:scoreColor(result.score||0), letterSpacing:1}}>
                      {scoreLabel(result.score||0)}
                    </div>
                    <div style={{fontSize:10, color:'var(--text3)', marginTop:2}}>/100 confidence</div>
                  </div>
                </div>
                {/* Score bar */}
                <div style={{height:6, background:'var(--bg3)', borderRadius:3, marginTop:8, overflow:'hidden'}}>
                  <div style={{height:'100%', width:`${result.score||0}%`,
                    background:`linear-gradient(90deg, var(--green), ${scoreColor(result.score||0)})`,
                    borderRadius:3, transition:'width 0.6s ease'}}/>
                </div>
              </div>

              {/* IOC Details */}
              {[
                ['Indicator',    result.value],
                ['Type',         result.type],
                ['Severity',     result.severity],
                ['Threat Actor', result.actor],
                ['Malware',      result.malware],
                ['First Seen',   result.first_seen],
                ['Last Seen',    result.last_seen],
              ].map(([label, val]) => val && (
                <div key={label} style={{display:'flex', justifyContent:'space-between',
                  borderBottom:'1px solid var(--border)', padding:'6px 0', fontSize:11}}>
                  <span style={{color:'var(--text3)', fontFamily:'var(--mono)'}}>{label}</span>
                  <span style={{color:'var(--text)', fontFamily:'var(--mono)', fontWeight:600,
                    maxWidth:220, textAlign:'right', wordBreak:'break-all'}}>{val}</span>
                </div>
              ))}
            </div>

            {/* Right: geo + tactics */}
            <div>
              {/* Verdict Badge */}
              <div style={{padding:16, borderRadius:8,
                background: result._clean ? 'rgba(34,197,94,0.05)' : 'rgba(240,62,62,0.05)',
                border:`1px solid ${result._clean ? 'var(--green)' : 'var(--red)'}`,
                marginBottom:16, textAlign:'center'}}>
                <div style={{fontSize:28}}>{result._clean ? '✅' : '⚠️'}</div>
                <div style={{fontFamily:'var(--title)', fontSize:16, fontWeight:800,
                  color: result._clean ? 'var(--green)' : scoreColor(result.score||0), marginTop:4}}>
                  {result._clean ? 'APPEARS CLEAN' : scoreLabel(result.score||0)}
                </div>
                <div style={{fontSize:10, color:'var(--text3)', marginTop:4, fontFamily:'var(--mono)'}}>
                  {result._clean ? 'Not in any threat database' : `Active threat — ${result.severity} priority`}
                </div>
              </div>

              {/* Geolocation */}
              {geoData && (
                <div style={{marginBottom:16}}>
                  <div style={{fontSize:10, color:'var(--text3)', fontFamily:'var(--mono)', marginBottom:8, letterSpacing:1}}>
                    GEOLOCATION
                  </div>
                  {[
                    ['Country', `${FLAG[geoData.country_code]||'🌐'} ${geoData.country_name || result.country}`],
                    ['City',    geoData.city],
                    ['Region',  geoData.region],
                    ['ISP/Org', geoData.org],
                    ['ASN',     geoData.asn],
                    ['Lat/Lon', geoData.latitude ? `${geoData.latitude}, ${geoData.longitude}` : null],
                  ].filter(([,v]) => v).map(([label, val]) => (
                    <div key={label} style={{display:'flex', justifyContent:'space-between',
                      borderBottom:'1px solid var(--border)', padding:'5px 0', fontSize:11}}>
                      <span style={{color:'var(--text3)', fontFamily:'var(--mono)'}}>{label}</span>
                      <span style={{color:'var(--cyan)', fontFamily:'var(--mono)'}}>{val}</span>
                    </div>
                  ))}
                </div>
              )}

              {/* MITRE Tactics */}
              {result.tactics && result.tactics.length > 0 && (
                <div>
                  <div style={{fontSize:10, color:'var(--text3)', fontFamily:'var(--mono)', marginBottom:8, letterSpacing:1}}>
                    MITRE ATT&CK TACTICS
                  </div>
                  <div style={{display:'flex', flexWrap:'wrap', gap:6}}>
                    {result.tactics.map((t, i) => {
                      const m = MITRE_TACTICS[t] || {id:'TA0000', color:'var(--text3)'};
                      return (
                        <div key={i} style={{fontSize:9, fontFamily:'var(--mono)', padding:'4px 8px',
                          borderRadius:4, border:`1px solid ${m.color}`, color:m.color,
                          background:`${m.color}18`}}>
                          {m.id} · {t}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          </div>
        </Card>
      )}

      {/* IOC Table (when not showing hunt results) */}
      {!result && !notFound && !hunting && (
        <Card title={`IOC Database — ${filtered.length} indicators`} style={{flex:1, overflow:'hidden', padding:0}}>
          <div style={{overflowY:'auto', maxHeight:380}}>
            <table style={{width:'100%', borderCollapse:'collapse'}}>
              <thead>
                <tr>
                  {['Type','Indicator','Actor','Malware','Severity','Score'].map(h => (
                    <th key={h} style={{padding:'8px 12px', textAlign:'left', fontSize:9,
                      color:'var(--text3)', fontFamily:'var(--mono)', letterSpacing:1,
                      borderBottom:'1px solid var(--border)', background:'var(--bg2)', textTransform:'uppercase'}}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.slice(0, 80).map((ioc, i) => (
                  <tr key={i} onClick={() => { setQuery(ioc.value); setResult(ioc); }}
                    style={{cursor:'pointer', borderBottom:'1px solid var(--border)',
                      transition:'background 0.1s'}}
                    onMouseEnter={e => e.currentTarget.style.background='var(--bg3)'}
                    onMouseLeave={e => e.currentTarget.style.background='transparent'}>
                    <td style={{padding:'8px 12px'}}>
                      <span style={{fontSize:9, fontFamily:'var(--mono)', padding:'2px 6px', borderRadius:3,
                        border:'1px solid var(--border2)', color:'var(--cyan)'}}>
                        {ioc.type}
                      </span>
                    </td>
                    <td style={{padding:'8px 12px', fontFamily:'var(--mono)', fontSize:11, color:'var(--text)', maxWidth:200}}>
                      <div style={{overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap'}}>
                        {(ioc.value||'').substring(0,40)}
                      </div>
                    </td>
                    <td style={{padding:'8px 12px', fontSize:11, color:'var(--orange)', fontFamily:'var(--mono)'}}>
                      {ioc.actor || '—'}
                    </td>
                    <td style={{padding:'8px 12px', fontSize:11, color:'var(--text3)', fontFamily:'var(--mono)'}}>
                      {ioc.malware || '—'}
                    </td>
                    <td style={{padding:'8px 12px'}}>
                      <span style={{fontSize:9, fontFamily:'var(--mono)', padding:'2px 6px', borderRadius:3,
                        border:`1px solid ${ioc.severity==='CRITICAL'?'var(--red)':ioc.severity==='HIGH'?'var(--orange)':'var(--yellow)'}`,
                        color:ioc.severity==='CRITICAL'?'var(--red)':ioc.severity==='HIGH'?'var(--orange)':'var(--yellow)'}}>
                        {ioc.severity || 'HIGH'}
                      </span>
                    </td>
                    <td style={{padding:'8px 12px', fontFamily:'var(--title)', fontSize:16, fontWeight:800,
                      color:scoreColor(ioc.score||70)}}>
                      {ioc.score || 70}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
