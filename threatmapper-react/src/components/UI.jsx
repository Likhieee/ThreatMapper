import React from 'react';

export const styles = {
  card: { background:'var(--panel)', border:'1px solid var(--border)', borderRadius:8, padding:16 },
  cardTitle: { fontSize:10, fontFamily:'var(--mono)', color:'var(--text2)', letterSpacing:2, textTransform:'uppercase', display:'flex', alignItems:'center', gap:8, marginBottom:14 },
  btn: { display:'inline-flex', alignItems:'center', gap:6, padding:'6px 12px', borderRadius:5, fontSize:11, fontFamily:'var(--mono)', cursor:'pointer', border:'1px solid var(--border2)', background:'var(--bg3)', color:'var(--text2)', transition:'all 0.15s', letterSpacing:'0.5px' },
  table: { width:'100%', borderCollapse:'collapse', fontSize:12 },
};

export function Card({ title, children, action, style={} }) {
  return (
    <div style={{...styles.card, ...style}}>
      {title && (
        <div style={styles.cardTitle}>
          <span style={{width:3,height:12,background:'var(--red)',borderRadius:1,display:'block'}}/>
          {title}
          {action && <div style={{marginLeft:'auto'}}>{action}</div>}
        </div>
      )}
      {children}
    </div>
  );
}

export function MetricCard({ label, value, color='var(--cyan)', delta, accent }) {
  return (
    <div style={{...styles.card, position:'relative', overflow:'hidden', borderTop:`2px solid ${color}`}}>
      <div style={{fontSize:10, color:'var(--text3)', fontFamily:'var(--mono)', letterSpacing:1, textTransform:'uppercase', marginBottom:8}}>{label}</div>
      <div style={{fontFamily:'var(--title)', fontSize:32, fontWeight:800, color, lineHeight:1}}>{value??'—'}</div>
      {delta && <div style={{fontSize:10, color:'var(--text3)', marginTop:6, fontFamily:'var(--mono)'}}>{delta}</div>}
    </div>
  );
}

export function Btn({ children, onClick, variant='default', active=false, style={} }) {
  const colors = {
    default: { border:'var(--border2)', bg:'var(--bg3)', color:'var(--text2)' },
    cyan: { border:'var(--cyan)', bg:'var(--cyanglow)', color:'var(--cyan)' },
    red: { border:'var(--red)', bg:'var(--redglow)', color:'var(--red)' },
    purple: { border:'var(--purple)', bg:'var(--purpleglow)', color:'var(--purple)' },
  };
  const c = active ? colors.red : colors[variant] || colors.default;
  return (
    <button onClick={onClick} style={{...styles.btn, borderColor:c.border, background:c.bg, color:c.color, ...style}}>
      {children}
    </button>
  );
}

export function Tag({ children, variant='cyan' }) {
  const colors = {
    red: { bg:'rgba(240,62,62,0.12)', color:'var(--red)', border:'rgba(240,62,62,0.25)' },
    orange: { bg:'rgba(249,115,22,0.12)', color:'var(--orange)', border:'rgba(249,115,22,0.25)' },
    yellow: { bg:'rgba(234,179,8,0.12)', color:'var(--yellow)', border:'rgba(234,179,8,0.25)' },
    green: { bg:'rgba(34,197,94,0.12)', color:'var(--green)', border:'rgba(34,197,94,0.25)' },
    cyan: { bg:'rgba(34,211,238,0.12)', color:'var(--cyan)', border:'rgba(34,211,238,0.25)' },
    purple: { bg:'rgba(168,85,247,0.12)', color:'var(--purple)', border:'rgba(168,85,247,0.25)' },
  };
  const c = colors[variant] || colors.cyan;
  return (
    <span style={{display:'inline-block', padding:'2px 8px', borderRadius:3, fontSize:9, fontFamily:'var(--mono)', letterSpacing:1, background:c.bg, color:c.color, border:`1px solid ${c.border}`}}>
      {children}
    </span>
  );
}

export function Loading({ text='Loading...' }) {
  return (
    <div style={{display:'flex', alignItems:'center', justifyContent:'center', padding:40, color:'var(--text3)', fontFamily:'var(--mono)', fontSize:12, gap:10}}>
      <div style={{width:16, height:16, border:'2px solid var(--border2)', borderTopColor:'var(--cyan)', borderRadius:'50%', animation:'spin 0.8s linear infinite'}}/>
      {text}
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </div>
  );
}

export function Empty({ icon='🛡', text='No data available' }) {
  return (
    <div style={{display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', padding:40, gap:10, color:'var(--text3)', fontFamily:'var(--mono)', fontSize:11, textAlign:'center'}}>
      <span style={{fontSize:32, opacity:0.3}}>{icon}</span>
      {text}
    </div>
  );
}

export function ProgressBar({ value, color='var(--red)' }) {
  return (
    <div style={{height:4, background:'var(--border)', borderRadius:2, overflow:'hidden', marginTop:6}}>
      <div style={{height:'100%', width:`${value}%`, background:color, borderRadius:2, transition:'width 1s ease'}}/>
    </div>
  );
}

export function SearchInput({ value, onChange, onSearch, placeholder }) {
  return (
    <div style={{display:'flex', gap:8}}>
      <input
        value={value} onChange={e=>onChange(e.target.value)}
        onKeyDown={e=>e.key==='Enter'&&onSearch()}
        placeholder={placeholder||'Search...'}
        style={{flex:1, background:'var(--bg3)', border:'1px solid var(--border2)', borderRadius:6,
          padding:'8px 12px', fontSize:12, fontFamily:'var(--mono)', color:'var(--text)', outline:'none'}}
      />
      <Btn onClick={onSearch} variant='cyan'>⚡ SEARCH</Btn>
    </div>
  );
}

export function DataTable({ headers, rows, emptyText='No data' }) {
  if(!rows?.length) return <Empty text={emptyText}/>;
  return (
    <table style={styles.table}>
      <thead>
        <tr>{headers.map((h,i)=>(
          <th key={i} style={{textAlign:'left', fontSize:9, fontFamily:'var(--mono)', color:'var(--text3)',
            letterSpacing:2, padding:'8px 10px', borderBottom:'1px solid var(--border)', textTransform:'uppercase', fontWeight:500}}>
            {h}
          </th>
        ))}</tr>
      </thead>
      <tbody>
        {rows.map((row,i)=>(
          <tr key={i} style={{cursor:row.onClick?'pointer':undefined}} onClick={row.onClick}>
            {row.cells.map((cell,j)=>(
              <td key={j} style={{padding:'9px 10px', borderBottom:'1px solid var(--border)', color:'var(--text2)', verticalAlign:'middle'}}>
                {cell}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
