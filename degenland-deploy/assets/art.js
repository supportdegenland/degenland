/* DegenLand · sprite dei miner (pixel art SVG) */

/* DegenLand · sprite dei miner v2 (pixel art 48×48 con ombreggiatura)
   Stile comune per ogni nuovo modello: contorno scuro, 3 toni di metallo, accento neon, LED. */
const MINERS = [
  {id:0,name:'Pixel',sol:0.025,pb:240,color:'#8C9BFF'},
  {id:1,name:'Bit Buddy',sol:0.1,pb:240,color:'#00F0FF'},
  {id:2,name:'Nebula',sol:0.3,pb:220,color:'#39FF88'},
  {id:3,name:'Quasar',sol:0.5,pb:200,color:'#F9F002'},
  {id:4,name:'Pulsar',sol:1,pb:160,color:'#FF8A00'},
  {id:5,name:'Singolarità',sol:3,pb:120,color:'#FF2E88'}
];
const SPECIAL = { 6: { id: 6, name: 'Pioniere', color: '#F2C14E' } };   // miner non acquistabili (Pioniere)
function minerSVG(type){
  const N=48, g=Array.from({length:N},()=>Array(N).fill(null));
  const hx=h=>[parseInt(h.slice(1,3),16),parseInt(h.slice(3,5),16),parseInt(h.slice(5,7),16)];
  const mix=(a,b,t)=>{const A=hx(a),B=hx(b);return '#'+A.map((v,i)=>Math.round(v+(B[i]-v)*t).toString(16).padStart(2,'0')).join('');};
  const AC=(MINERS[type]||SPECIAL[type]||MINERS[0]).color;
  const P={K:'#06030e',d0:'#0d1122',d1:'#182036',d2:'#27304e',d3:'#3a4568',d4:'#56638f',d5:'#8390b8',d6:'#c2cbe6',w:'#ffffff',
    a0:mix(AC,'#000000',.62),a1:AC,a2:mix(AC,'#ffffff',.55),ag:mix(AC,'#0b0719',.62),
    cu:'#b8692b',cu2:'#ef9c47',pcb:'#0a3a33',pcb2:'#16826a',gold:'#f2c14e',red:'#ff3b3b',grn:'#39ff88',amb:'#ffb000',bg:'#0b0719'};
  const px=(x,y,c)=>{x=Math.round(x);y=Math.round(y);if(x>=0&&x<N&&y>=0&&y<N)g[y][x]=P[c]||c;};
  const rect=(x,y,w,h,c)=>{for(let j=0;j<h;j++)for(let i=0;i<w;i++)px(x+i,y+j,c);};
  const line=(x0,y0,x1,y1,c)=>{const n=Math.max(Math.abs(x1-x0),Math.abs(y1-y0))*2||1;for(let k=0;k<=n;k++)px(x0+(x1-x0)*k/n,y0+(y1-y0)*k/n,c);};
  const disc=(cx,cy,r,c)=>{for(let y=0;y<N;y++)for(let x=0;x<N;x++)if(Math.hypot(x-cx,y-cy)<=r)px(x,y,c);};
  const ring=(cx,cy,r,c,t=1)=>{for(let y=0;y<N;y++)for(let x=0;x<N;x++){const d=Math.hypot(x-cx,y-cy);if(d<=r&&d>r-t)px(x,y,c);}};
  // pannello con luce in alto/sinistra, ombra in basso/destra e contorno
  const panel=(x,y,w,h,base='d2',hi='d4',lo='d1')=>{rect(x-1,y-1,w+2,h+2,'K');rect(x,y,w,h,base);rect(x,y,w,1,hi);rect(x,y,1,h,hi);rect(x,y+h-1,w,1,lo);rect(x+w-1,y,1,h,lo);};
  const screw=(x,y)=>{px(x,y,'d6');px(x+1,y,'d3');px(x,y+1,'d3');px(x+1,y+1,'d1');};
  const led=(x,y,c)=>{px(x-1,y,'d1');px(x+2,y,'d1');px(x,y,c);px(x+1,y,c);px(x,y-1,mix(P[c],'#0b0719',.55));px(x+1,y-1,mix(P[c],'#0b0719',.55));};
  const vents=(x,y,w,h,step=2,c='d0')=>{for(let j=0;j<h;j+=step){rect(x,y+j,w,1,c);}};
  const fins=(x,y,w,h)=>{for(let i=0;i<w;i+=2){rect(x+i,y,1,h,'d3');rect(x+i+1,y,1,h,'d0');}rect(x,y,w,1,'d5');};
  const smallFan=(cx,cy,r)=>{ disc(cx,cy,r,'K'); disc(cx,cy,r-1,'d0'); if(r>=3){px(cx-1,cy-1,'d4');px(cx+1,cy-1,'d3');px(cx-1,cy+1,'d3');px(cx+1,cy+1,'d4');px(cx,cy-2,'d5');px(cx,cy+2,'d5');px(cx-2,cy,'d3');px(cx+2,cy,'d5');} px(cx,cy,'a1'); if(r>=3)px(cx-1,cy,'a0'); };
  const fan=(cx,cy,r,glow=false)=>{
    if(r<=3) return smallFan(cx,cy,r);
    disc(cx,cy,r,'K'); disc(cx,cy,r-1,'d1'); if(glow) ring(cx,cy,r-1,'a1',1); disc(cx,cy,r-2,'d0');
    const B=r>=9?7:6;
    for(let i=0;i<B;i++){const a0=i*2*Math.PI/B;for(let t=1.6;t<r-2;t+=.45){const a=a0+t*0.30;const x=cx+Math.cos(a)*t,y=cy+Math.sin(a)*t;px(x,y,'d4');px(x+Math.cos(a+1.57)*.9,y+Math.sin(a+1.57)*.9,'d3');px(x-Math.cos(a+1.57)*.9,y-Math.sin(a+1.57)*.9,'d5');}}
    disc(cx,cy,r>=9?3:2,'d1'); disc(cx,cy,r>=9?2:1,'a1'); px(cx,cy,'a2'); if(r>=9)px(cx-1,cy-1,'a2');
  };
  const contacts=(x,y,w)=>{rect(x,y,w,2,'K');for(let i=0;i<w;i+=2){rect(x+i,y,1,2,'gold');}};
  const heatpipes=(x,y,n)=>{for(let k=0;k<n;k++){rect(x,y+k*4,7,3,'K');rect(x,y+k*4+1,6,1,'cu');rect(x,y+k*4,6,1,'cu2');rect(x+1,y+k*4+2,5,1,'cu');}};

  if(type===0||type===6){ // Pixel · scheda video a ventola singola (6 = versione dorata del Pioniere)
    rect(1,11,4,26,'K'); rect(2,12,2,24,'d5'); rect(2,12,1,24,'d6'); for(let k=0;k<5;k++)rect(2,15+k*4,2,2,'d1'); screw(2,13);
    panel(5,13,38,21,'d2','d4','d1'); rect(6,14,36,1,'a2'); rect(6,15,36,1,'a0'); rect(6,32,36,1,'a0');
    fan(18,24,8);
    panel(28,17,12,13,'d1','d3','d0'); for(let k=0;k<5;k++)line(29,18+k*2,39,18+k*2-0,'d0'); for(let k=0;k<3;k++){line(30+k*3,29,32+k*3,18,'d2');}
    rect(31,20,6,3,'a0'); rect(31,20,6,1,'a1'); rect(32,22,4,1,'a2');
    rect(35,9,7,4,'K'); rect(36,10,5,2,'d1'); for(let i=0;i<5;i+=1)px(36+i,11,i%2?'amb':'d3');
    contacts(10,35,24); led(38,32,'grn');
    if(type===6){ panel(28,17,12,13,'d0','a1','K'); const star=['....X....','....X....','...XXX...','XXXXXXXXX','.XXXXXXX.','..XXXXX..','..XXXXX..','.XXX.XXX.','.XX...XX.']; star.forEach((row,j)=>[...row].forEach((c,i)=>{ if(c==='X') px(30+i,19+j,j<3?'a2':'a1'); })); rect(6,32,36,1,'a1'); rect(2,12,2,24,'a1'); rect(2,12,1,24,'a2'); }
  }
  else if(type===1){ // Bit Buddy · GPU a doppia ventola
    rect(1,10,4,29,'K'); rect(2,11,2,27,'d5'); rect(2,11,1,27,'d6'); for(let k=0;k<6;k++)rect(2,14+k*4,2,2,'d1'); screw(2,12);
    panel(5,12,38,24,'d2','d4','d1');
    for(let i=0;i<38;i++){const t=i/38;px(6+i,13,t<.5?mix(P.a2,P.a1,t*2):mix(P.a1,P.a0,(t-.5)*2));} rect(6,14,36,1,'a0');
    fan(15,25,8); fan(31,25,8);
    for(let i=0;i<2;i++){line(23,17,23,34,'d0');} rect(22,16,3,2,'a1');
    heatpipes(42,17,4);
    rect(6,33,36,1,'a0'); rect(6,34,36,1,'d1'); screw(7,16); screw(38,30);
    contacts(9,37,26); led(40,15,'grn');
  }
  else if(type===2){ // Nebula · ASIC compatto
    rect(9,39,7,3,'K'); rect(10,39,5,2,'d1'); rect(32,39,7,3,'K'); rect(33,39,5,2,'d1');
    panel(5,9,38,30,'d2','d5','d1');
    rect(6,10,36,2,'d3'); rect(6,10,36,1,'d6'); rect(18,6,12,4,'K'); rect(19,7,10,2,'d5'); rect(19,7,10,1,'d6');
    fins(7,14,6,20); fins(35,14,6,20);
    panel(14,13,20,22,'d1','d3','d0'); for(let k=0;k<4;k++){line(15+k*5,14,15+k*5,34,'d0');} for(let k=0;k<4;k++){line(15,15+k*5,33,15+k*5,'d0');} fan(24,24,9); ring(24,24,10,'d3',1);
    rect(6,36,36,2,'a0'); rect(6,36,36,1,'a1'); screw(7,12); screw(39,12); screw(7,32); screw(39,32);
    led(8,36,'grn'); led(12,36,'amb'); rect(30,36,10,1,'a2');
  }
  else if(type===3){ // Quasar · rig aperto a 2 GPU
    const rail=(x,y,w,h)=>{rect(x,y,w,h,'K');rect(x+1,y+1,w-2,h-2,'d5');rect(x+1,y+1,w-2,1,'d6');};
    rail(2,5,44,4); rect(4,6,40,1,'a1'); rail(2,5,4,36); rail(42,5,4,36); rail(2,38,44,4);
    for(const gx of [8,25]){ panel(gx,12,15,11,'d2','d4','d1'); rect(gx+1,13,13,1,'a1'); fan(gx+4,18,3); fan(gx+11,18,3); rect(gx+5,22,5,1,'a0'); }
    for(const rx of [12,17,29,34]){ rect(rx,23,1,6,'pcb2'); rect(rx+1,23,1,6,'pcb'); }
    panel(9,29,26,8,'pcb','pcb2','d0'); for(let k=0;k<5;k++){line(11+k*5,31,14+k*5,31,'pcb2');line(11+k*5,34,16+k*5,34,'pcb2');}
    panel(13,30,7,6,'d3','d5','d1'); fins(14,31,5,4); rect(24,30,2,6,'K'); rect(24,31,2,4,'d6'); rect(28,30,2,6,'K'); rect(28,31,2,4,'d6');
    panel(33,29,8,8,'d1','d3','d0'); rect(34,31,6,3,'a1'); rect(34,31,6,1,'a2'); led(35,35,'grn'); screw(3,7); screw(43,7); screw(3,39); screw(43,39);
  }
  else if(type===4){ // Pulsar · rig a 6 GPU
    const rail=(x,y,w,h)=>{rect(x,y,w,h,'K');rect(x+1,y+1,w-2,h-2,'d5');rect(x+1,y+1,w-2,1,'d6');};
    rail(1,3,46,3); rect(3,4,42,1,'a1'); rail(1,3,3,39); rail(44,3,3,39); rail(1,40,46,3); rect(3,41,42,1,'a1');
    for(const gy of [7,17]) for(const gx of [6,19,32]){ panel(gx,gy,11,7,'d2','d4','d1'); rect(gx+1,gy+1,9,1,'a1'); fan(gx+3,gy+4,2); fan(gx+8,gy+4,2); }
    for(const rx of [9,14,22,27,35,40]) { rect(rx,24,1,4,'pcb2'); }
    panel(6,28,25,9,'pcb','pcb2','d0'); for(let k=0;k<4;k++){line(8+k*6,30,12+k*6,30,'pcb2');line(8+k*6,34,14+k*6,34,'pcb2');} panel(9,29,8,7,'d3','d5','d1'); fins(10,30,6,5);
    panel(33,28,11,10,'d1','d3','d0'); rect(35,30,7,4,'a1'); rect(35,30,7,1,'a2'); fan(38,36,2); led(35,35,'grn');
    screw(2,5);screw(44,5);screw(2,40);screw(44,40);
  }
  else { // Singolarità · server ASIC con nucleo luminoso
    rect(1,12,4,26,'K'); rect(2,13,2,24,'d5'); rect(2,13,1,24,'d6'); screw(2,15); screw(2,34);
    rect(43,12,4,26,'K'); rect(44,13,2,24,'d5'); rect(44,13,1,24,'d6'); screw(44,15); screw(44,34);
    panel(5,10,38,30,'d1','d3','d0'); rect(6,11,36,1,'a1'); rect(6,38,36,1,'a1'); rect(6,11,1,28,'a1'); rect(41,11,1,28,'a1');
    rect(8,13,32,5,'K'); rect(9,14,30,3,'d0'); for(let i=0;i<9;i++){const h=1+((i*5)%3);rect(10+i*3,17-h,2,h,i%3?'a1':'a2');} led(32,14,'grn'); led(35,14,'amb'); rect(37,14,2,2,'a2');
    rect(7,19,34,14,'d0'); for(const cx of [14,24,34]){ fan(cx,26,7,true); }
    for(let k=0;k<3;k++){ px(19+k*10,21,'a2'); px(19+k*10,31,'a2'); }
    rect(8,34,32,4,'K'); for(let i=0;i<16;i++){rect(9+i*2,35,1,2,'d2');} rect(8,38,32,1,'a2');
    rect(6,41,36,1,'ag'); rect(9,42,30,1,'ag'); screw(7,12);screw(39,12);
  }
  // serializzazione: righe → rettangoli
  let out='';
  for(let y=0;y<N;y++){let x=0;while(x<N){const c=g[y][x];if(!c){x++;continue;}let w=1;while(x+w<N&&g[y][x+w]===c)w++;out+=`<rect x="${x}" y="${y}" width="${w}" height="1" fill="${c}"/>`;x+=w;}}
  return `<svg viewBox="-1 -1 50 50" aria-hidden="true" shape-rendering="crispEdges"><g class="bob">${out}</g></svg>`;
}
