'use strict';
/* Painel. Login = Supabase Auth (e-mail/senha). Toda ação passa por RPC adm_* que valida
   no SERVIDOR (is_admin()). Esconder botões aqui não protege nada; quem protege é o banco. */
const S={sess:null,aba:'dash',f:{status:'',busca:'',ordem:'recentes',pg:0},sel:new Set(),cfg:{},falhas:0,bloq:0};
const SK='star_sess', PAG=20, MAXH=8*3600e3;
const ABAS=[['dash','Dashboard'],['aval','Avaliações'],['midia','Mídia'],['cont','Conteúdo']];
const ST={pendente:'Pendente',aprovado:'Aprovada',oculto:'Oculta'};
const A=$('#adm');
const MSG={rede:'Sem conexão. Tente de novo.',url_invalida:'Use um link começando com https://.',muito_longo:'Texto longo demais.'};
const aviso=t=>{const a=$('#av');a.textContent=t;a.hidden=false;clearTimeout(aviso.t);aviso.t=setTimeout(()=>a.hidden=true,3500)};
function falha(e){
  const c=e&&e.message; console.warn('painel:',String(c).slice(0,30));
  if(c==='nao_autorizado'){sair(true);telaLogin('Sua sessão expirou ou você não tem permissão. Entre novamente.');return}
  aviso(MSG[c]||'Não foi possível concluir. Tente novamente.');
}

/* ---------- autenticação ---------- */
async function authReq(path,{method='POST',body,token}={}){
  let r;
  try{r=await fetch(base()+'/auth/v1/'+path,{method,headers:{apikey:CFG.key,'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},body:body?JSON.stringify(body):undefined})}
  catch(_){throw new ApiError('rede')}
  const t=await r.text(); let j={}; try{j=t?JSON.parse(t):{}}catch(_){}
  return {ok:r.ok,j};
}
const guardar=j=>{S.sess={at:j.access_token,rt:j.refresh_token,exp:Date.now()+Math.max(30,(j.expires_in||3600)-30)*1000,ini:S.sess?S.sess.ini:Date.now()};
  localStorage.setItem(SK,JSON.stringify(S.sess))};
async function token(){
  const s=S.sess; if(!s||Date.now()-s.ini>MAXH) throw new ApiError('nao_autorizado');   // sessão máxima de 8 h
  if(Date.now()>s.exp){const r=await authReq('token?grant_type=refresh_token',{body:{refresh_token:s.rt}});
    if(!r.ok) throw new ApiError('nao_autorizado'); guardar(r.j)}
  return S.sess.at;
}
const rpc=async(f,b)=>api('rpc/'+f,b||{},await token());
async function login(email,senha){
  S.sess=null; const r=await authReq('token?grant_type=password',{body:{email,password:senha}});
  if(!r.ok) throw new ApiError('credenciais'); guardar(r.j);
  if(!await rpc('adm_registrar_login')){await sair(true);throw new ApiError('credenciais')}   // autenticado, mas não é admin
}
async function sair(mudo){
  const s=S.sess; S.sess=null; localStorage.removeItem(SK); S.sel.clear();
  if(s){try{await authReq('logout',{token:s.at})}catch(_){}}
  if(!mudo) telaLogin();
}

/* ---------- telas de acesso ---------- */
function telaLogin(msg){
  A.innerHTML=`<div class="c" style="max-width:380px;margin:40px auto"><h2 style="font-size:1.4rem;margin-bottom:6px">Painel</h2>
  <p style="margin-bottom:6px">Acesso restrito à equipe.</p>
  <form id="lf" novalidate><label class="lb" for="em">E-mail</label><input class="f" id="em" type="email" autocomplete="username" required>
  <label class="lb" for="pw">Senha</label><input class="f" id="pw" type="password" autocomplete="current-password" required>
  <p class="er" role="alert" id="le" ${msg?'':'hidden'}>${esc(msg||'')}</p>
  <button class="btn" id="lb" style="width:100%;margin-top:14px">Entrar</button></form>
  <button class="btn o s" data-act="rec" type="button" style="width:100%;margin-top:12px">Esqueci a senha</button></div>`;
  $('#lf').onsubmit=async e=>{
    e.preventDefault(); const b=$('#lb'), er=$('#le');
    if(Date.now()<S.bloq){er.textContent='Aguarde alguns segundos antes de tentar de novo.';er.hidden=false;return}
    b.disabled=true; b.textContent='Entrando…'; er.hidden=true;
    try{await login($('#em').value.trim(),$('#pw').value); S.falhas=0; await abrir()}
    catch(err){
      if(err.message!=='rede'&&++S.falhas>=5){S.bloq=Date.now()+30000;S.falhas=0}   // freio no cliente; o limite real é do Supabase Auth
      er.textContent=err.message==='rede'?'Sem conexão. Tente de novo.':'E-mail ou senha incorretos, ou sem permissão de acesso.';
      er.hidden=false; b.disabled=false; b.textContent='Entrar'; $('#pw').value='';
    }
  };
}
function telaRec(){
  A.innerHTML=`<div class="c" style="max-width:380px;margin:40px auto"><h2 style="font-size:1.4rem;margin-bottom:6px">Recuperar acesso</h2>
  <form id="rf" novalidate><label class="lb" for="em">E-mail</label><input class="f" id="em" type="email" autocomplete="username" required>
  <button class="btn" style="width:100%;margin-top:14px">Enviar instruções</button></form>
  <button class="btn o s" data-act="login" type="button" style="width:100%;margin-top:12px">Voltar</button></div>`;
  $('#rf').onsubmit=async e=>{e.preventDefault();
    try{await authReq('recover',{body:{email:$('#em').value.trim()}})}catch(_){}
    aviso('Se o e-mail estiver cadastrado, enviaremos as instruções.'); telaLogin()};   // mesma resposta sempre
}
function telaNova(at){
  A.innerHTML=`<div class="c" style="max-width:380px;margin:40px auto"><h2 style="font-size:1.4rem;margin-bottom:6px">Nova senha</h2>
  <form id="nf" novalidate><label class="lb" for="np">Nova senha <span>(mínimo 10 caracteres)</span></label><input class="f" id="np" type="password" autocomplete="new-password" minlength="10" required>
  <p class="er" role="alert" id="ne" hidden></p><button class="btn" style="width:100%;margin-top:14px">Salvar senha</button></form></div>`;
  $('#nf').onsubmit=async e=>{e.preventDefault(); const p=$('#np').value;
    if(p.length<10){$('#ne').textContent='Use pelo menos 10 caracteres.';$('#ne').hidden=false;return}
    try{const r=await authReq('user',{method:'PUT',token:at,body:{password:p}}); if(!r.ok) throw 0;
      aviso('Senha alterada. Entre com a nova senha.'); telaLogin()}
    catch(_){$('#ne').textContent='Não foi possível alterar. Peça um novo link.';$('#ne').hidden=false}};
}

/* ---------- estrutura ---------- */
async function abrir(){
  A.innerHTML=`<div class="hd" style="gap:12px;flex-wrap:wrap"><h2 style="margin:0">Painel</h2><div class="ac"><a class="btn o s" href="/">Ver site</a><button class="btn o s" data-act="sair" type="button">Sair</button></div></div>
  <div class="bar" role="tablist">${ABAS.map(([k,t])=>`<button role="tab" type="button" data-aba="${k}" aria-selected="false">${t}</button>`).join('')}</div><div id="corpo" aria-live="polite"></div>`;
  await ir(S.aba);
}
async function ir(aba){
  S.aba=aba;
  document.querySelectorAll('[data-aba][role=tab]').forEach(b=>{const on=b.dataset.aba===aba;b.classList.toggle('on',on);b.setAttribute('aria-selected',on)});
  $('#corpo').innerHTML='<p class="vz">Carregando…</p>';
  try{await {dash:vDash,aval:vAval,midia:vMidia,cont:vCont}[aba]()}
  catch(e){
    if(e.message==='nao_autorizado') return falha(e);
    $('#corpo').innerHTML=`<div class="vz"><p>Não foi possível carregar esta área.</p><button class="btn o s" data-aba="${aba}" type="button" style="margin-top:12px">Tentar novamente</button></div>`;
  }
}
const fmtDH=d=>d?new Intl.DateTimeFormat('pt-BR',{dateStyle:'short',timeStyle:'short'}).format(new Date(d)):'—';

/* ---------- dashboard ---------- */
async function vDash(){
  const [r,au]=await Promise.all([rpc('adm_resumo'),rpc('adm_auditoria',{p_limite:12})]);
  const pn=r.por_nota||{}, pm=r.por_mes||[];
  const mxn=Math.max(1,...[1,2,3,4,5].map(n=>+pn[n]||0)), mxm=Math.max(1,...pm.map(m=>+m.n||0));
  const num=(l,v)=>`<div><span>${l}</span><b>${esc(v)}</b></div>`;
  const barra=(rot,n,mx)=>`<div class="dist"><span>${esc(rot)}</span><i style="width:${Math.round((+n||0)/mx*100)}%"></i><b>${+n||0}</b></div>`;
  $('#corpo').innerHTML=`<div class="info">${num('Avaliações',r.total)}${num('Média',r.media?String(r.media).replace('.',',')+' ★':'—')}${num('Pendentes',r.pendentes)}${num('Aprovadas',r.aprovadas)}${num('Ocultas',r.ocultas)}</div>
  <div class="g g2" style="margin-top:16px"><div class="c"><h3>Notas</h3>${[5,4,3,2,1].map(n=>barra(n+' ★',pn[n],mxn)).join('')}</div>
  <div class="c"><h3>Avaliações por mês</h3>${pm.length?pm.map(m=>barra(m.mes,m.n,mxm)).join(''):'<p>Sem dados ainda.</p>'}</div></div>
  <div class="c" style="margin-top:16px"><h3>Conteúdo</h3><p>Vídeo publicado: <strong>${r.video_url?'sim':'nenhum'}</strong> · Última alteração de conteúdo: <strong>${esc(fmtDH(r.ultima_alteracao))}</strong></p></div>
  <div class="c" style="margin-top:16px"><h3>Últimas ações</h3>${au.length?au.map(a=>`<p style="font-size:.9rem"><strong>${esc(a.acao)}</strong> · ${esc(a.email||'—')} · ${esc(fmtDH(a.criado_em))}</p>`).join(''):'<p>Nenhuma ação registrada.</p>'}</div>`;
}

/* ---------- avaliações ---------- */
async function vAval(){
  const f=S.f, r=await rpc('adm_listar_avaliacoes',{p_status:f.status||null,p_busca:f.busca||null,p_ordem:f.ordem,p_limite:PAG,p_offset:f.pg*PAG});
  const pgs=Math.max(1,Math.ceil(r.total/PAG)), opt=(v,t,at)=>`<option value="${v}" ${at===v?'selected':''}>${t}</option>`;
  $('#corpo').innerHTML=`<div class="ac" style="margin-bottom:12px">
   <select class="f" id="fs" aria-label="Filtrar por status" style="width:auto">${opt('','Todas',f.status)}${opt('pendente','Pendentes',f.status)}${opt('aprovado','Aprovadas',f.status)}${opt('oculto','Ocultas',f.status)}</select>
   <select class="f" id="fo" aria-label="Ordenar" style="width:auto">${opt('recentes','Mais recentes',f.ordem)}${opt('antigas','Mais antigas',f.ordem)}${opt('nota_alta','Maior nota',f.ordem)}${opt('nota_baixa','Menor nota',f.ordem)}</select>
   <input class="f" id="fb" type="search" aria-label="Buscar" placeholder="Buscar nome ou comentário" value="${esc(f.busca)}" style="flex:1;min-width:180px"></div>
  <div class="ac" style="margin-bottom:12px"><button class="btn s" data-act="aprovarSel" type="button">Aprovar selecionadas</button><button class="btn o s" data-act="aprovarTodas" type="button">Aprovar todas pendentes</button><button class="btn o s" data-act="csv" type="button">Exportar CSV</button></div>
  <p style="margin-bottom:10px"><strong>${r.total}</strong> resultado(s) · página ${f.pg+1} de ${pgs}</p>
  ${r.itens.map(a=>{const id=esc(a.id);return `<article class="c it"><div class="tp"><label style="display:flex;gap:10px;align-items:center"><input type="checkbox" data-sel="${id}" ${S.sel.has(String(a.id))?'checked':''} aria-label="Selecionar avaliação de ${esc(a.nome)}"><span><strong>${esc(a.nome)}</strong> · ${+a.estrelas} ★ · <span style="color:var(--mut);font-size:.88rem">${esc(data(a.criado_em))}</span></span></label><span class="tag ${esc(a.status)}">${esc(ST[a.status]||a.status)}${a.destacado?' · ★ destaque':''}</span></div>
   <p style="color:var(--ink)">${a.comentario?esc(a.comentario):'<em>sem comentário</em>'}</p>
   <div class="ab"><button class="btn s" data-act="aprovar" data-id="${id}" type="button">Aprovar</button><button class="btn o s" data-act="ocultar" data-id="${id}" type="button">Ocultar</button><button class="btn o s" data-act="destacar" data-id="${id}" data-v="${a.destacado?0:1}" type="button">${a.destacado?'Tirar destaque':'Destacar'}</button><button class="btn o s" data-act="excluir" data-id="${id}" type="button" style="color:var(--red)">Excluir</button></div></article>`}).join('')||'<p class="vz">Nada por aqui.</p>'}
  <div class="ac" style="justify-content:center"><button class="btn o s" data-act="pg" data-d="-1" type="button" ${f.pg<=0?'disabled':''}>Anterior</button><button class="btn o s" data-act="pg" data-d="1" type="button" ${f.pg+1>=pgs?'disabled':''}>Próxima</button></div>`;
}
async function csv(){
  const l=await rpc('adm_exportar_avaliacoes');
  const cel=v=>{let s=String(v??''); if(/^[=+\-@\t\r]/.test(s)) s="'"+s; return '"'+s.replace(/"/g,'""')+'"'};   // evita fórmula em planilha
  const linhas=[['data','nome','nota','comentario','status','destaque'].join(';'),
    ...l.map(a=>[data(a.criado_em),a.nome,a.estrelas,a.comentario,a.status,a.destacado?'sim':'não'].map(cel).join(';'))];
  const u=URL.createObjectURL(new Blob(['\ufeff'+linhas.join('\r\n')],{type:'text/csv;charset=utf-8'}));
  const a=document.createElement('a'); a.href=u; a.download='avaliacoes-'+new Date().toISOString().slice(0,10)+'.csv'; a.click();
  setTimeout(()=>URL.revokeObjectURL(u),2000);
}

/* ---------- mídia (vídeo) ---------- */
const PREF='/storage/v1/object/public/site-media/';
async function apagarArquivo(u){   // não deixa vídeo antigo órfão no Storage
  if(!u||!u.startsWith(base()+PREF)) return;
  try{await fetch(base()+'/storage/v1/object/site-media/'+u.slice((base()+PREF).length),{method:'DELETE',headers:{apikey:CFG.key,Authorization:'Bearer '+await token()}})}catch(_){}
}
async function vMidia(){
  S.cfg=await api('rpc/config_publica')||{}; const u=urlSegura(S.cfg.video_url||'');
  $('#corpo').innerHTML=`<div class="c fm"><h3>Vídeo da página inicial</h3>
   <div class="vprev">${u?previa(u):'<p class="vz" style="position:absolute;inset:0;display:grid;place-items:center">Nenhum vídeo definido.</p>'}</div>
   <p id="vinfo" style="font-size:.88rem"></p>
   <label class="lb" for="arq">Enviar arquivo <span>MP4, WebM ou MOV · até 50 MB</span></label>
   <input class="f" type="file" id="arq" accept="video/mp4,video/webm,video/quicktime,.mp4,.webm,.mov">
   <div class="prog" id="prog" hidden><i id="pb"></i></div>
   <label class="lb" for="lnk">Ou colar um link <span>YouTube, Vimeo ou .mp4 (https)</span></label>
   <input class="f" id="lnk" placeholder="https://" value="${esc(u)}">
   <div class="ab"><button class="btn s" data-act="salvarLink" type="button">Salvar link</button><button class="btn o s" data-act="removerVideo" type="button" style="color:var(--red)">Remover vídeo</button></div></div>`;
  if(u&&u.startsWith(base()+PREF)) fetch(u,{method:'HEAD'}).then(r=>{const n=+r.headers.get('content-length');
    if(n&&$('#vinfo')) $('#vinfo').textContent='Arquivo enviado · '+(n/1048576).toFixed(1).replace('.',',')+' MB · '+fmtDH(r.headers.get('last-modified'))}).catch(()=>{});
}
async function enviarVideo(f){
  const MIME={mp4:'video/mp4',webm:'video/webm',mov:'video/quicktime'}, ext=(f.name.split('.').pop()||'').toLowerCase();
  if(!MIME[ext]) return aviso('Use MP4, WebM ou MOV.');
  if(f.type&&!Object.values(MIME).includes(f.type)) return aviso('Formato de vídeo não aceito.');
  if(f.size>50*1048576) return aviso('Arquivo acima de 50 MB. Comprima o vídeo ou use um link do YouTube.');
  $('#prog').hidden=false; aviso('Enviando… não feche a página.');
  const antigo=S.cfg.video_url, cam=await rpc('adm_preparar_upload',{p_ext:ext}), tk=await token();
  await new Promise((ok,no)=>{const x=new XMLHttpRequest();
    x.open('POST',base()+'/storage/v1/object/site-media/'+cam);
    x.setRequestHeader('apikey',CFG.key); x.setRequestHeader('Authorization','Bearer '+tk);
    x.setRequestHeader('Content-Type',f.type||MIME[ext]); x.setRequestHeader('cache-control','max-age=31536000');
    x.upload.onprogress=e=>{if(e.lengthComputable)$('#pb').style.width=(e.loaded/e.total*100)+'%'};
    x.onload=()=>x.status<300?ok():no(new ApiError(x.status===401||x.status===403?'nao_autorizado':'erro'));
    x.onerror=()=>no(new ApiError('rede')); x.send(f)});
  await rpc('adm_salvar_config',{p_dados:{video_url:base()+PREF+cam}});
  await apagarArquivo(antigo); aviso('Vídeo publicado no site.'); await ir('midia');
}

/* ---------- conteúdo ---------- */
async function vCont(){
  const c=S.cfg=await api('rpc/config_publica')||{};
  $('#corpo').innerHTML=`<div class="c fm"><h3>Textos do topo do site</h3>
   <label class="lb" for="t1">Título</label><input class="f" id="t1" maxlength="120" value="${esc(c.titulo||'')}">
   <label class="lb" for="t2">Subtítulo</label><textarea class="f" id="t2" maxlength="400">${esc(c.subtitulo||'')}</textarea>
   <label class="lb" for="t3">Legenda do vídeo</label><textarea class="f" id="t3" maxlength="400">${esc(c.legenda||'')}</textarea>
   <p style="font-size:.85rem">Campo vazio = usa o texto original do site.</p>
   <div class="ab"><button class="btn s" data-act="salvarTextos" type="button">Salvar textos</button></div></div>`;
}

/* ---------- eventos (delegação: poucos listeners) ---------- */
A.addEventListener('click',async e=>{
  const t=e.target.closest('[data-act],[data-aba]'); if(!t||t.disabled) return;
  const {act,id,aba}=t.dataset;
  try{
    if(aba) return await ir(aba);
    if(act==='sair') return await sair();
    if(act==='rec') return telaRec();
    if(act==='login') return telaLogin();
    if(act==='csv') return await csv();
    if(act==='aprovar'||act==='ocultar') await rpc('adm_atualizar_avaliacao',{p_id:id,p_status:act==='aprovar'?'aprovado':'oculto'});
    else if(act==='destacar') await rpc('adm_atualizar_avaliacao',{p_id:id,p_destacado:t.dataset.v==='1'});
    else if(act==='excluir'){if(!confirm('Excluir esta avaliação para sempre?')) return; await rpc('adm_excluir_avaliacao',{p_id:id})}
    else if(act==='aprovarSel'){if(!S.sel.size) return aviso('Selecione ao menos uma avaliação.'); await rpc('adm_aprovar_varias',{p_ids:[...S.sel]}); S.sel.clear()}
    else if(act==='aprovarTodas'){aviso((await rpc('adm_aprovar_pendentes'))+' aprovada(s).')}
    else if(act==='pg') S.f.pg=Math.max(0,S.f.pg+ +t.dataset.d);
    else if(act==='salvarLink'){const v=urlSegura($('#lnk').value.trim()); if(!v) return aviso('Cole um link começando com https://.');
      const antigo=S.cfg.video_url; await rpc('adm_salvar_config',{p_dados:{video_url:v}}); if(antigo!==v) await apagarArquivo(antigo); aviso('Link salvo.')}
    else if(act==='removerVideo'){if(!confirm('Remover o vídeo do site?')) return;
      const antigo=S.cfg.video_url; await rpc('adm_salvar_config',{p_dados:{video_url:''}}); await apagarArquivo(antigo); aviso('Vídeo removido.')}
    else if(act==='salvarTextos'){await rpc('adm_salvar_config',{p_dados:{titulo:$('#t1').value.trim(),subtitulo:$('#t2').value.trim(),legenda:$('#t3').value.trim()}}); aviso('Textos salvos.')}
    else return;
    await ir(S.aba);
  }catch(err){falha(err)}
});
A.addEventListener('change',async e=>{
  const t=e.target;
  try{
    if(t.id==='fs'){S.f.status=t.value;S.f.pg=0;await ir('aval')}
    else if(t.id==='fo'){S.f.ordem=t.value;S.f.pg=0;await ir('aval')}
    else if(t.id==='fb'){S.f.busca=t.value.trim();S.f.pg=0;await ir('aval')}
    else if(t.dataset&&t.dataset.sel!==undefined){t.checked?S.sel.add(t.dataset.sel):S.sel.delete(t.dataset.sel)}
    else if(t.id==='arq'&&t.files[0]){await enviarVideo(t.files[0])}
  }catch(err){falha(err); const p=$('#prog'); if(p) p.hidden=true}
});

/* ---------- início ---------- */
(async()=>{
  const h=new URLSearchParams(location.hash.slice(1));
  if(h.get('type')==='recovery'&&h.get('access_token')){const at=h.get('access_token');history.replaceState(null,'',location.pathname);return telaNova(at)}
  if(h.get('error')){history.replaceState(null,'',location.pathname);return telaLogin('Link inválido ou expirado. Peça um novo.')}
  try{const s=JSON.parse(localStorage.getItem(SK)||'null'); if(s&&s.ini&&Date.now()-s.ini<MAXH) S.sess=s}catch(_){}
  S.sess?abrir():telaLogin();
})();
