import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { useAPI } from '../hooks/useAPI';
import { Loading, Btn } from '../components/UI';

const COLORS = {
  ThreatActor:'#f03e3e', Malware:'#22d3ee',
  Technique:'#f97316', CVE:'#a855f7', IOC:'#22c55e'
};

export default function KnowledgeGraph() {
  const svgRef = useRef();
  const tooltipRef = useRef();
  const { data, loading } = useAPI('/graph-data');
  const [filter, setFilter] = useState('all');
  const [selected, setSelected] = useState(null);
  const simRef = useRef();

  useEffect(() => {
    if (!data?.nodes?.length) return;
    buildGraph(data.nodes, data.edges, filter);
  }, [data, filter]);

  function buildGraph(allNodes, allEdges, f) {
    const container = svgRef.current?.parentElement;
    if (!container) return;
    const W = container.offsetWidth;
    const H = container.offsetHeight;

    // Filter nodes
    const typeMap = { actor:'ThreatActor', malware:'Malware', technique:'Technique', cve:'CVE', ioc:'IOC' };
    const nodes = f === 'all' ? [...allNodes] : allNodes.filter(n => n.label === (typeMap[f] || f));
    const nodeIds = new Set(nodes.map(n => n.id));
    const edges = allEdges.filter(e => nodeIds.has(e.source) && nodeIds.has(e.target));

    d3.select(svgRef.current).selectAll('*').remove();
    const svg = d3.select(svgRef.current).attr('width', W).attr('height', H);

    // Zoom
    const g = svg.append('g');
    svg.call(d3.zoom().scaleExtent([0.1, 4]).on('zoom', e => g.attr('transform', e.transform)));

    // Simulation
    const sim = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(edges).id(d => d.id).distance(90).strength(0.5))
      .force('charge', d3.forceManyBody().strength(-250))
      .force('center', d3.forceCenter(W / 2, H / 2))
      .force('collision', d3.forceCollide().radius(26));
    simRef.current = sim;

    // Gradient defs
    const defs = svg.append('defs');
    Object.entries(COLORS).forEach(([k, c]) => {
      const grad = defs.append('radialGradient').attr('id', 'grad-'+k).attr('r', '60%');
      grad.append('stop').attr('offset', '0%').attr('stop-color', c).attr('stop-opacity', 0.3);
      grad.append('stop').attr('offset', '100%').attr('stop-color', c).attr('stop-opacity', 0.05);
    });

    // Links
    const link = g.append('g').selectAll('line').data(edges).join('line')
      .attr('stroke', 'rgba(255,255,255,0.06)').attr('stroke-width', 1);

    // Nodes
    const node = g.append('g').selectAll('g').data(nodes).join('g')
      .attr('cursor', 'pointer')
      .call(d3.drag()
        .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on('end', (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }))
      .on('click', (e, d) => { setSelected(d); e.stopPropagation(); })
      .on('mouseover', (e, d) => {
        const tip = tooltipRef.current;
        if (tip) {
          tip.style.display = 'block';
          tip.innerHTML = `<div style="color:${COLORS[d.label]||'#22d3ee'};font-weight:700;margin-bottom:4px">${d.id}</div>
            <div style="color:var(--text3);font-size:10px">${d.label}</div>
            ${d.description ? `<div style="margin-top:6px;font-size:10px;color:var(--text2)">${d.description?.substring(0,80)||''}...</div>` : ''}`;
        }
      })
      .on('mousemove', e => {
        const tip = tooltipRef.current;
        if (tip) { tip.style.left = (e.pageX+14)+'px'; tip.style.top = (e.pageY-10)+'px'; }
      })
      .on('mouseout', () => { if (tooltipRef.current) tooltipRef.current.style.display = 'none'; });

    // Glow circle
    node.append('circle')
      .attr('r', d => d.label === 'ThreatActor' ? 18 : d.label === 'Malware' ? 14 : d.label === 'IOC' ? 9 : 12)
      .attr('fill', d => `url(#grad-${d.label})`)
      .attr('stroke', 'none');

    // Main circle
    node.append('circle')
      .attr('r', d => d.label === 'ThreatActor' ? 12 : d.label === 'Malware' ? 9 : d.label === 'IOC' ? 6 : 7)
      .attr('fill', d => (COLORS[d.label] || '#22d3ee') + '22')
      .attr('stroke', d => COLORS[d.label] || '#22d3ee')
      .attr('stroke-width', 1.5);

    // Labels
    node.append('text')
      .text(d => d.id.length > 11 ? d.id.substring(0, 11) + '…' : d.id)
      .attr('text-anchor', 'middle').attr('dy', '0.35em')
      .style('fill', d => COLORS[d.label] || '#22d3ee')
      .style('font-size', '7px').style('font-family', 'var(--mono)')
      .style('pointer-events', 'none');

    sim.on('tick', () => {
      link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
          .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    svg.on('click', () => setSelected(null));
  }

  const filters = ['all', 'actor', 'malware', 'technique', 'cve', 'ioc'];

  return (
    <div style={{display:'flex',flexDirection:'column',height:'100%',overflow:'hidden',padding:20,gap:12}}>
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',flexShrink:0}}>
        <div>
          <h2 style={{fontFamily:'var(--title)',fontSize:22,fontWeight:800}}>Knowledge Graph</h2>
          <p style={{fontSize:11,color:'var(--text3)',fontFamily:'var(--mono)',marginTop:2}}>
            {data ? `${data.nodes?.length} nodes · ${data.edges?.length} edges — D3.js force simulation` : 'Loading...'}
          </p>
        </div>
        <div style={{display:'flex',gap:4}}>
          {filters.map(f => (
            <Btn key={f} active={filter===f} onClick={()=>setFilter(f)}>
              {f.toUpperCase()}
            </Btn>
          ))}
          <Btn variant='cyan' onClick={()=>{ if(simRef.current) simRef.current.alpha(0.3).restart(); }}>↺ RESET</Btn>
        </div>
      </div>

      {/* Legend */}
      <div style={{display:'flex',gap:8,flexShrink:0}}>
        {Object.entries(COLORS).map(([k,c]) => (
          <div key={k} onClick={()=>setFilter(k.toLowerCase())} style={{display:'flex',alignItems:'center',gap:4,
            background:'var(--panel)',border:'1px solid var(--border)',padding:'3px 10px',
            borderRadius:4,cursor:'pointer',fontSize:10,fontFamily:'var(--mono)'}}>
            <span style={{width:8,height:8,borderRadius:'50%',background:c,flexShrink:0}}/>
            <span style={{color:'var(--text2)'}}>{k}</span>
          </div>
        ))}
      </div>

      <div style={{flex:1,background:'var(--panel)',border:'1px solid var(--border)',borderRadius:8,overflow:'hidden',position:'relative'}}>
        {loading && <div style={{position:'absolute',inset:0,display:'flex',alignItems:'center',justifyContent:'center',background:'var(--panel)',zIndex:10}}><Loading text="Loading knowledge graph..."/></div>}
        <svg ref={svgRef} style={{width:'100%',height:'100%',cursor:'grab'}}/>
      </div>

      {/* Node detail panel */}
      {selected && (
        <div style={{flexShrink:0,background:'var(--panel)',border:'1px solid var(--border)',borderRadius:8,padding:14,display:'flex',gap:16,alignItems:'center'}}>
          <div style={{width:10,height:10,borderRadius:'50%',background:COLORS[selected.label]||'var(--cyan)',boxShadow:`0 0 8px ${COLORS[selected.label]||'var(--cyan)'}`}}/>
          <div>
            <div style={{fontFamily:'var(--mono)',fontSize:13,color:'var(--text)',fontWeight:700}}>{selected.id}</div>
            <div style={{fontSize:10,color:'var(--text3)',marginTop:2}}>{selected.label} · {selected.description?.substring(0,80)||'No description'}...</div>
          </div>
          <Btn style={{marginLeft:'auto'}} onClick={()=>setSelected(null)}>✕ CLOSE</Btn>
        </div>
      )}

      {/* Tooltip */}
      <div ref={tooltipRef} style={{position:'fixed',display:'none',background:'var(--panel)',
        border:'1px solid var(--border2)',borderRadius:6,padding:'10px 12px',
        fontFamily:'var(--mono)',fontSize:11,color:'var(--text)',pointerEvents:'none',
        zIndex:1000,maxWidth:220,boxShadow:'0 8px 24px rgba(0,0,0,0.4)'}}/>
    </div>
  );
}
