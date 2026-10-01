/* DegenLand · schermata preview e link social (le impostazioni sono in config.js) */
(function(){
  var C = window.DEGENLAND || {}, S = C.social || {}, d = document, root = d.documentElement;
  var ICONS = {"x": "<svg viewBox=\"0 0 16 16\" aria-hidden=\"true\" focusable=\"false\" shape-rendering=\"crispEdges\"><rect width=\"16\" height=\"16\" fill=\"#000000\"/><g fill=\"#fff\"><rect x=\"2\" y=\"3\" width=\"2\" height=\"1\"/><rect x=\"11\" y=\"3\" width=\"2\" height=\"1\"/><rect x=\"3\" y=\"4\" width=\"2\" height=\"1\"/><rect x=\"10\" y=\"4\" width=\"2\" height=\"1\"/><rect x=\"4\" y=\"5\" width=\"2\" height=\"1\"/><rect x=\"9\" y=\"5\" width=\"2\" height=\"1\"/><rect x=\"5\" y=\"6\" width=\"2\" height=\"1\"/><rect x=\"8\" y=\"6\" width=\"2\" height=\"1\"/><rect x=\"6\" y=\"7\" width=\"3\" height=\"1\"/><rect x=\"6\" y=\"8\" width=\"3\" height=\"1\"/><rect x=\"5\" y=\"9\" width=\"2\" height=\"1\"/><rect x=\"8\" y=\"9\" width=\"2\" height=\"1\"/><rect x=\"4\" y=\"10\" width=\"2\" height=\"1\"/><rect x=\"9\" y=\"10\" width=\"2\" height=\"1\"/><rect x=\"3\" y=\"11\" width=\"2\" height=\"1\"/><rect x=\"10\" y=\"11\" width=\"2\" height=\"1\"/><rect x=\"2\" y=\"12\" width=\"2\" height=\"1\"/><rect x=\"11\" y=\"12\" width=\"2\" height=\"1\"/></g></svg>", "telegram": "<svg viewBox=\"0 0 16 16\" aria-hidden=\"true\" focusable=\"false\" shape-rendering=\"crispEdges\"><rect width=\"16\" height=\"16\" fill=\"#2AABEE\"/><g fill=\"#fff\"><rect x=\"12\" y=\"3\" width=\"2\" height=\"1\"/><rect x=\"9\" y=\"4\" width=\"5\" height=\"1\"/><rect x=\"6\" y=\"5\" width=\"8\" height=\"1\"/><rect x=\"3\" y=\"6\" width=\"10\" height=\"1\"/><rect x=\"2\" y=\"7\" width=\"6\" height=\"1\"/><rect x=\"9\" y=\"7\" width=\"4\" height=\"1\"/><rect x=\"4\" y=\"8\" width=\"3\" height=\"1\"/><rect x=\"8\" y=\"8\" width=\"5\" height=\"1\"/><rect x=\"6\" y=\"9\" width=\"1\" height=\"1\"/><rect x=\"8\" y=\"9\" width=\"4\" height=\"1\"/><rect x=\"6\" y=\"10\" width=\"6\" height=\"1\"/><rect x=\"7\" y=\"11\" width=\"1\" height=\"1\"/><rect x=\"9\" y=\"11\" width=\"3\" height=\"1\"/><rect x=\"9\" y=\"12\" width=\"2\" height=\"1\"/></g></svg>", "discord": "<svg viewBox=\"0 0 16 16\" aria-hidden=\"true\" focusable=\"false\" shape-rendering=\"crispEdges\"><rect width=\"16\" height=\"16\" fill=\"#5865F2\"/><g fill=\"#fff\"><rect x=\"3\" y=\"3\" width=\"2\" height=\"1\"/><rect x=\"11\" y=\"3\" width=\"2\" height=\"1\"/><rect x=\"2\" y=\"4\" width=\"12\" height=\"1\"/><rect x=\"2\" y=\"5\" width=\"12\" height=\"1\"/><rect x=\"1\" y=\"6\" width=\"14\" height=\"1\"/><rect x=\"1\" y=\"7\" width=\"3\" height=\"1\"/><rect x=\"6\" y=\"7\" width=\"4\" height=\"1\"/><rect x=\"12\" y=\"7\" width=\"3\" height=\"1\"/><rect x=\"1\" y=\"8\" width=\"3\" height=\"1\"/><rect x=\"6\" y=\"8\" width=\"4\" height=\"1\"/><rect x=\"12\" y=\"8\" width=\"3\" height=\"1\"/><rect x=\"1\" y=\"9\" width=\"14\" height=\"1\"/><rect x=\"1\" y=\"10\" width=\"14\" height=\"1\"/><rect x=\"2\" y=\"11\" width=\"4\" height=\"1\"/><rect x=\"10\" y=\"11\" width=\"4\" height=\"1\"/><rect x=\"3\" y=\"12\" width=\"2\" height=\"1\"/><rect x=\"11\" y=\"12\" width=\"2\" height=\"1\"/></g></svg>"}, NAMES = {x:'X', telegram:'Telegram', discord:'Discord'};
  var LS = function(k, v){ try{ if(v===undefined) return localStorage.getItem(k); if(v===null) localStorage.removeItem(k); else localStorage.setItem(k, v); }catch(e){ return null; } };

  // link speciale ?preview=CHIAVE (entra) o ?preview=off (esci)
  try{
    var q = new URLSearchParams(location.search).get('preview');
    if(q === 'off') LS('dl_preview', null);
    else if(q) LS('dl_preview', q);
  }catch(e){}
  var gated = C.preview === true && LS('dl_preview') !== C.previewKey;

  function wireSocial(){
    var a = d.querySelectorAll('[data-social]');
    for(var i=0;i<a.length;i++){ var k = a[i].getAttribute('data-social'), u = S[k];
      if(u){ a[i].href = u; a[i].hidden = false; } else a[i].hidden = true; }
  }
  if(d.readyState === 'loading') d.addEventListener('DOMContentLoaded', wireSocial); else wireSocial();
  if(!gated) return;

  var TX = {
    en:{t:'Coming soon', p:'A pixel-art mining game in a neon city. The first 100 players get a free Pioneer miner: follow our channels to know when the doors open.', f:'Adults only. A simulation game, not an investment.', j:'Follow DegenLand'},
    es:{t:'Próximamente', p:'Un juego de minería en pixel art en una ciudad de neón. Los primeros 100 jugadores reciben gratis un minero Pionero: sigue nuestros canales para saber cuándo abrimos.', f:'Solo para mayores de edad. Un juego de simulación, no una inversión.', j:'Sigue a DegenLand'},
    ru:{t:'Скоро запуск', p:'Майнинг-игра в стиле пиксель-арт в неоновом городе. Первые 100 игроков бесплатно получат майнер Пионера: следи за нашими каналами, чтобы не пропустить открытие.', f:'Только для совершеннолетних. Игра-симулятор, а не инвестиция.', j:'Следи за DegenLand'},
    it:{t:'In arrivo', p:'Un gioco di mining in pixel art in una città al neon. I primi 100 giocatori ricevono gratis un miner Pioniere: segui i nostri canali per sapere quando apriamo.', f:'Solo per maggiorenni. Un gioco di simulazione, non un investimento.', j:'Segui DegenLand'}
  };
  var LANGS = ['en','es','ru','it'];
  function pickLang(){
    var m = location.pathname.match(/^\/(en|es|ru|it)\//); if(m) return m[1];
    try{ var g = new URLSearchParams(location.search).get('lang'); if(LANGS.indexOf(g)>=0) return g; }catch(e){}
    var s = LS('degenland_lang'); if(LANGS.indexOf(s)>=0) return s;
    var n = (navigator.language||'en').slice(0,2).toLowerCase(); return LANGS.indexOf(n)>=0 ? n : 'en';
  }
  var lang = pickLang();

  root.classList.add('dl-pv');
  var css = d.createElement('style');
  css.textContent =
    'html.dl-pv,html.dl-pv body{height:100%;overflow:hidden;margin:0}' +
    'html.dl-pv body>*:not(#dl-preview){display:none!important}' +
    '#dl-preview{position:fixed;inset:0;z-index:2147483647;overflow:auto;display:flex;align-items:center;justify-content:center;' +
      'padding:calc(24px + env(safe-area-inset-top,0px)) 20px calc(24px + env(safe-area-inset-bottom,0px));' +
      'background:#07040F;background-image:linear-gradient(180deg,#07040F 0%,#12082E 55%,#3E1060 100%);color:#F4F2FF;' +
      'font-family:"Chakra Petch",system-ui,-apple-system,"Segoe UI",sans-serif;text-align:center}' +
    '#dl-preview .pv-in{max-width:520px;width:100%}' +
    '#dl-preview .pv-art{width:148px;height:148px;margin:0 auto 22px;image-rendering:pixelated}' +
    '#dl-preview .pv-art svg{width:100%;height:100%;display:block}' +
    '#dl-preview h1{font-family:"Press Start 2P",ui-monospace,monospace;font-weight:400;font-size:clamp(24px,7vw,40px);line-height:1.2;margin:0;color:#FF2E88;text-shadow:3px 0 0 #00F0FF,5px 5px 0 #05030F}' +
    '#dl-preview .pv-t{font-family:"Press Start 2P",ui-monospace,monospace;font-size:13px;line-height:1.6;color:#F9F002;margin:22px 0 14px}' +
    '#dl-preview .pv-p{font-size:17px;line-height:1.55;color:#D9D4F5;margin:0 auto 26px;max-width:44ch}' +
    '#dl-preview .pv-j{font-size:14px;font-weight:600;color:#B9B2DD;margin:0 0 10px}' +
    '#dl-preview .pv-soc{display:flex;flex-wrap:wrap;gap:12px;justify-content:center;margin:0 0 28px}' +
    '#dl-preview .pv-soc a{display:inline-flex;align-items:center;gap:10px;padding:8px 16px 8px 8px;background:#1C1440;color:#F4F2FF;text-decoration:none;font-weight:700;font-size:16px;border:2px solid #05030F;box-shadow:0 4px 0 #05030F}' +
    '#dl-preview .pv-soc a:active{transform:translateY(3px);box-shadow:0 1px 0 #05030F}' +
    '#dl-preview .pv-soc svg{width:28px;height:28px;display:block}' +
    '#dl-preview a:focus-visible,#dl-preview button:focus-visible{outline:3px solid #00F0FF;outline-offset:2px}' +
    '#dl-preview .pv-lang{display:flex;gap:6px;justify-content:center;margin:0 0 18px}' +
    '#dl-preview .pv-lang button{font:600 13px "Chakra Petch",system-ui,sans-serif;background:transparent;color:#B9B2DD;border:2px solid #3A2D7A;padding:5px 10px;cursor:pointer}' +
    '#dl-preview .pv-lang button[aria-pressed="true"]{background:#00F0FF;color:#05030F;border-color:#00F0FF}' +
    '#dl-preview .pv-f{font-size:12px;color:#8F88B8;margin:0}';
  (d.head || root).appendChild(css);

  function socials(){
    var h = '';
    ['x','telegram','discord'].forEach(function(k){ if(S[k]) h += '<a href="'+S[k]+'" target="_blank" rel="noopener">'+ICONS[k]+'<span>'+NAMES[k]+'</span></a>'; });
    return h;
  }
  function render(){
    var t = TX[lang], box = d.getElementById('dl-preview');
    if(!box){ box = d.createElement('div'); box.id = 'dl-preview'; box.setAttribute('role','main'); d.body.appendChild(box); }
    var langs = LANGS.map(function(l){ return '<button type="button" data-l="'+l+'" aria-pressed="'+(l===lang)+'">'+l.toUpperCase()+'</button>'; }).join('');
    box.innerHTML = '<div class="pv-in"><div class="pv-art" aria-hidden="true"></div><h1>DegenLand</h1><p class="pv-t">'+t.t+'</p><p class="pv-p">'+t.p+'</p>' +
      (socials() ? '<p class="pv-j">'+t.j+'</p><div class="pv-soc">'+socials()+'</div>' : '') +
      '<div class="pv-lang" role="group" aria-label="Language">'+langs+'</div><p class="pv-f">'+t.f+'</p></div>';
    root.lang = lang; d.title = 'DegenLand · ' + t.t;
    var bs = box.querySelectorAll('[data-l]');
    for(var i=0;i<bs.length;i++) bs[i].onclick = function(){ lang = this.getAttribute('data-l'); LS('degenland_lang', lang); render(); };
    art();
  }
  function art(){
    var el = d.querySelector('#dl-preview .pv-art'); if(!el) return;
    if(window.minerSVG){ try{ el.innerHTML = window.minerSVG(6); }catch(e){} return; }
    // pagine senza sprite (About, FAQ, Termini, Privacy): carica le grafiche solo qui
    if(/^\/(game|console)\//.test(location.pathname) || d.querySelector('script[src*="art.js"]')) return;
    var s = d.createElement('script'); s.src = '/assets/art.js'; s.onload = function(){ var e = d.querySelector('#dl-preview .pv-art'); if(e && window.minerSVG) try{ e.innerHTML = window.minerSVG(6); }catch(x){} };
    d.head.appendChild(s);
  }
  if(d.readyState === 'loading') d.addEventListener('DOMContentLoaded', render); else render();
  window.addEventListener('load', art);
})();
