/* Mensajeria - cliente */

const API = {
  async post(url, data) {
    const body = data instanceof FormData ? data : new URLSearchParams(data);
    const r = await fetch(url, { method: 'POST', body, credentials: 'same-origin' });
    if (!r.ok) {
      let msg = r.statusText;
      try { msg = (await r.json()).detail || msg; } catch (e) {}
      throw new Error(msg);
    }
    return r.json();
  },
  async get(url) {
    const r = await fetch(url, { credentials: 'same-origin' });
    if (!r.ok) throw new Error(r.statusText);
    return r.json();
  },
};

const EMOJIS = [
  '😀','😃','😄','😁','😆','😅','😂','🤣','😊','😇','🙂','🙃','😉','😌','😍','🥰',
  '😘','😗','😙','😚','😋','😛','😝','😜','🤪','🤨','🧐','🤓','😎','🥳','😏','😒',
  '😞','😔','😟','😕','🙁','☹️','😣','😖','😫','😩','🥺','😢','😭','😤','😠','😡',
  '🤬','🤯','😳','🥵','🥶','😱','😨','😰','😥','😓','🤗','🤔','🤭','🤫','😶','😐',
  '😑','😬','🙄','😯','😦','😧','😮','😲','🥱','😴','🤤','😪','😵','🤐','🥴','🤢',
  '🤮','🤧','😷','🤒','🤕','🤑','🤠','😈','👿','👍','👎','👌','✌️','🤞','🤟','🤘',
  '🤙','👈','👉','👆','👇','☝️','✋','🤚','🖐️','🖖','👋','🤝','🙏','💪','👏','🙌',
  '👐','🤲','✍️','💅','🤳','👀','👁️','❤️','🧡','💛','💚','💙','💜','🖤','🤍','🤎',
  '💔','💕','💞','💓','💗','💖','💘','💝','💟','❣️','💋','🔥','✨','⭐','🌟','💫',
  '⚡','💥','💢','💨','💦','🎉','🎊','🎁','🎈','🎂','🍰','☕','🍵','🍺','🍻','🍕',
  '🍔','🍟','🍗','🍖','🍣','🍱','🍜','🍝','🍩','⚽','🏀','🏈','⚾','🎾','🏐','🏉',
  '🎱','🏓','🏸','✅','❌','⚠️','❓','❗','💯','🔔','🔕','📢','📣','💬','💭','🗯️',
  '🕐','⏰','⏳','⌛','📅','📌','📍','🎵','🎶','🚀','🌙','🌞','🌈','🌊','🌋','❄️'
];

const state = {
  me: null,
  peer: null,
  peerOnline: false,
  messages: new Map(),
  dom: new Map(),
  ws: null,
  wsRetry: 0,
  typingSentAt: 0,
  typingStopTimer: null,
};

const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

const els = {
  panels:        $$('.panel'),
  formLogin:     $('#form-login'),
  formPin:       $('#form-pin'),
  formRegister:  $('#form-register'),
  errLogin:      $('#err-login'),
  errPin:        $('#err-pin'),
  errRegister:   $('#err-register'),
  regSlots:      $('#reg-slots'),
  linkRegister:  $('#link-register'),
  btnRegCancel:  $('#btn-register-cancel'),
  btnCancel:     $('#btn-cancel'),
  btnLogout:     $('#btn-logout'),
  btnBack:       $('#btn-back'),
  convList:      $('#conv-list'),
  peerName:      $('#peer-name'),
  peerStatus:    $('#peer-status'),
  peerAvatar:    $('#peer-avatar'),
  meAvatar:      $('#me-avatar'),
  messages:      $('#messages'),
  input:         $('#input-msg'),
  btnSend:       $('#btn-send'),
  btnEmoji:      $('#btn-emoji'),
  picker:        $('#emoji-picker'),
  typing:        $('#typing-indicator'),
  connStatus:    $('#conn-status'),
  toast:         $('#toast'),
  panelApp:      $('#panel-app'),
};

function showPanel(name) {
  els.panels.forEach(p => p.classList.toggle('hidden', p.id !== 'panel-' + name));
}
function formatTime(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString('es', { hour: '2-digit', minute: '2-digit' });
}
function escapeHTML(s) {
  return s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function toast(msg, ms) {
  ms = ms || 2200;
  els.toast.textContent = msg;
  els.toast.classList.remove('hidden');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => els.toast.classList.add('hidden'), ms);
}
function setConnStatus(s) {
  els.connStatus.classList.remove('connected', 'disconnected');
  els.connStatus.classList.add(s);
  els.connStatus.textContent = s === 'connected' ? 'Conectado'
                            : s === 'disconnected' ? 'Reconectando...'
                            : 'Conectando...';
}
function setPeerOnline(on) {
  state.peerOnline = on;
  els.peerStatus.textContent = on ? 'en linea' : 'desconectado';
  els.peerStatus.classList.toggle('online', on);
  renderConversations();
}

const seenObserver = new IntersectionObserver((entries) => {
  for (const e of entries) {
    if (!e.isIntersecting) continue;
    if (document.visibilityState !== 'visible') continue;
    const id = e.target.dataset.id;
    const m = state.messages.get(id);
    if (!m || m.from === state.me || m.status === 'read') continue;
    sendWS({ type: 'message_seen', message_id: id });
    seenObserver.unobserve(e.target);
  }
}, { threshold: 0.5 });

async function boot() {
  bindEvents();
  resetIdleTimer();

  try {
    const st = await API.get('/api/status');
    if (st.can_register) {
      els.linkRegister.classList.remove('hidden');
      els.regSlots.textContent = st.slots + ' de ' + st.max_users + ' espacios disponibles';
    }
  } catch (e) {}

  let me;
  try { me = await API.get('/api/me'); }
  catch (e) { showPanel('login'); return; }

  if (!me.authenticated) { showPanel('login'); return; }
  if (me.level < 2)      { showPanel('pin');   return; }
  await enterApp(me);
}

async function enterApp(me) {
  state.me   = me.username;
  state.peer = me.peer;
  els.meAvatar.textContent   = (state.me[0] || '*').toUpperCase();
  els.peerAvatar.textContent = (state.peer ? state.peer[0] : '*').toUpperCase();
  els.peerName.textContent   = state.peer || 'Sin interlocutor';
  renderConversations();
  showPanel('app');
  setConnStatus('connected');
  connectWS();
}

function bindEvents() {
  els.formLogin.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(els.formLogin);
    const btn = els.formLogin.querySelector('button[type=submit]');
    btn.disabled = true; els.errLogin.textContent = '';
    try {
      await API.post('/api/login', fd);
      els.formPin.reset();
      showPanel('pin');
      els.formPin.pin.focus();
    } catch (err) {
      els.errLogin.textContent = err.message;
    } finally { btn.disabled = false; }
  });

  els.formPin.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(els.formPin);
    const btn = els.formPin.querySelector('button[type=submit]');
    btn.disabled = true; els.errPin.textContent = '';
    try {
      await API.post('/api/pin', fd);
      const me = await API.get('/api/me');
      await enterApp(me);
    } catch (err) {
      els.errPin.textContent = err.message;
      els.formPin.pin.value = '';
    } finally { btn.disabled = false; }
  });

  els.linkRegister.addEventListener('click', () => {
    els.formRegister.reset();
    els.errRegister.textContent = '';
    showPanel('register');
  });
  els.btnRegCancel.addEventListener('click', () => {
    showPanel('login');
  });

  els.formRegister.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(els.formRegister);
    const u  = (fd.get('username') || '').trim();
    const p  = fd.get('password') || '';
    const p2 = fd.get('password2') || '';
    const pin = (fd.get('pin') || '').trim();

    els.errRegister.textContent = '';
    if (p !== p2)              { els.errRegister.textContent = 'Las contrasenas no coinciden'; return; }
    if (u.length < 1)          { els.errRegister.textContent = 'Usuario vacio'; return; }
    if (p.length < 6)          { els.errRegister.textContent = 'Contrasena min 6'; return; }
    if (!/^\d{4,8}$/.test(pin)){ els.errRegister.textContent = 'PIN debe tener 4-8 digitos'; return; }

    const btn = els.formRegister.querySelector('button[type=submit]');
    btn.disabled = true;
    try {
      const body = new URLSearchParams({ username: u, password: p, pin: pin });
      const r = await fetch('/api/register', { method: 'POST', body, credentials: 'same-origin' });
      if (!r.ok) {
        let msg = r.statusText;
        try { msg = (await r.json()).detail || msg; } catch (e) {}
        throw new Error(msg);
      }
      toast('Cuenta creada. Ya puedes iniciar sesion.');
      showPanel('login');
      els.formLogin.username.value = u;
      els.formLogin.password.focus();
    } catch (err) {
      els.errRegister.textContent = err.message;
    } finally { btn.disabled = false; }
  });

  els.btnCancel.addEventListener('click', async () => {
    try { await API.post('/api/logout', {}); } catch (e) {}
    showPanel('login');
  });

  els.btnLogout.addEventListener('click', async () => {
    try { await API.post('/api/logout', {}); } catch (e) {}
    location.reload();
  });

  els.btnSend.addEventListener('click', sendCurrent);
  els.input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendCurrent(); }
  });
  els.input.addEventListener('input', () => {
    if (!state.ws || state.ws.readyState !== WebSocket.OPEN) return;
    const now = Date.now();
    if (now - state.typingSentAt > 2500) {
      sendWS({ type: 'typing_start' });
      state.typingSentAt = now;
    }
    clearTimeout(state.typingStopTimer);
    state.typingStopTimer = setTimeout(() => sendWS({ type: 'typing_stop' }), 1800);
  });

  els.btnBack.addEventListener('click', () => {
    els.panelApp.classList.remove('chat-open');
  });
  els.convList.addEventListener('click', () => {
    els.panelApp.classList.add('chat-open');
    setTimeout(scrollToBottom, 60);
    document.querySelectorAll('.msg.in').forEach(el => seenObserver.observe(el));
  });

  els.btnEmoji.addEventListener('click', (e) => {
    e.stopPropagation();
    if (els.picker.childElementCount === 0) buildEmojiPicker();
    els.picker.classList.toggle('hidden');
  });
  document.addEventListener('click', (e) => {
    if (!els.picker.classList.contains('hidden')
        && !els.picker.contains(e.target)
        && e.target !== els.btnEmoji) {
      els.picker.classList.add('hidden');
    }
  });

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') {
      state.dom.forEach((el, id) => {
        const m = state.messages.get(id);
        if (!m || m.from === state.me || m.status === 'read') return;
        if (isInViewport(el)) sendWS({ type: 'message_seen', message_id: id });
      });
    }
  });

  window.addEventListener('beforeunload', () => {
    try { if (state.ws) state.ws.close(); } catch (e) {}
  });
}

function isInViewport(el) {
  const r = el.getBoundingClientRect();
  return r.top < window.innerHeight && r.bottom > 0;
}

function connectWS() {
  if (state.ws && (state.ws.readyState === WebSocket.OPEN || state.ws.readyState === WebSocket.CONNECTING)) return;

  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(proto + '//' + location.host + '/ws');
  state.ws = ws;

  ws.addEventListener('open', () => {
    state.wsRetry = 0;
    setConnStatus('connected');
  });

  ws.addEventListener('message', (ev) => {
    let data;
    try { data = JSON.parse(ev.data); } catch (e) { return; }
    handleServerEvent(data);
  });

  ws.addEventListener('close', (ev) => {
    setConnStatus('disconnected');
    if (ev.code === 4401) { location.reload(); return; }
    state.wsRetry = Math.min(state.wsRetry + 1, 8);
    const delay = Math.min(1000 * Math.pow(2, state.wsRetry), 20000);
    setTimeout(connectWS, delay);
  });

  ws.addEventListener('error', () => {});
}

function sendWS(obj) {
  if (!state.ws || state.ws.readyState !== WebSocket.OPEN) return;
  try { state.ws.send(JSON.stringify(obj)); } catch (e) {}
}

function handleServerEvent(data) {
  switch (data.type) {
    case 'message':           upsertMessage(data); break;
    case 'message_delivered': setStatus(data.message_id, 'delivered'); break;
    case 'message_seen':      setStatus(data.message_id, 'read', data.expires_at); break;
    case 'message_deleted':   removeMessage(data.message_id); break;
    case 'typing_start':      showTyping(true);  break;
    case 'typing_stop':       showTyping(false); break;
    case 'presence':          setPeerOnline(!!data.peer_online); break;
    case 'presence_online':   setPeerOnline(true);  break;
    case 'presence_offline':  setPeerOnline(false); break;
  }
}

function sendCurrent() {
  const text = els.input.value.trim();
  if (!text) return;
  if (!state.ws || state.ws.readyState !== WebSocket.OPEN) {
    toast('Sin conexion, reintentando...'); return;
  }
  sendWS({ type: 'message', text: text });
  sendWS({ type: 'typing_stop' });
  els.input.value = '';
  els.input.focus();
}

function upsertMessage(data) {
  const id = data.message_id;
  const existing = state.messages.get(id);
  if (existing) {
    if (data.text != null)       existing.text       = data.text;
    if (data.status)             existing.status     = data.status;
    if (data.expires_at != null) existing.expires_at = data.expires_at;
    renderMessage(existing);
    return;
  }
  const msg = {
    id: id,
    text:       data.text,
    from:       data.from,
    created_at: data.created_at || Math.floor(Date.now() / 1000),
    status:     data.status || 'sent',
    expires_at: data.expires_at || null,
  };
  state.messages.set(id, msg);
  renderMessage(msg);
  if (msg.from !== state.me) {
    scrollToBottom();
    const el = state.dom.get(id);
    if (el) seenObserver.observe(el);
  }
}

function renderMessage(msg) {
  let el = state.dom.get(msg.id);
  const isOut = msg.from === state.me;

  if (!el) {
    el = document.createElement('div');
    el.className = 'msg ' + (isOut ? 'out' : 'in');
    el.dataset.id = msg.id;
    el.innerHTML =
      '<div class="bubble">' +
        '<div class="text"></div>' +
        '<div class="meta">' +
          '<span class="time"></span>' +
          (isOut ? '<span class="status"></span>' : '') +
        '</div>' +
      '</div>';
    state.dom.set(msg.id, el);
    els.messages.appendChild(el);
  }

  el.querySelector('.text').textContent = msg.text;
  el.querySelector('.time').textContent = formatTime(msg.created_at);

  if (isOut) {
    const st = el.querySelector('.status');
    st.className = 'status ' + msg.status;
    st.innerHTML = statusIcon(msg.status);
  }
}

function statusIcon(status) {
  if (status === 'sent') {
    return '<svg viewBox="0 0 16 11" width="15" height="11"><path fill="currentColor" d="M11.071.653a.457.457 0 0 0-.304-.102.493.493 0 0 0-.381.178l-6.19 7.636L1.792 6.09a.46.46 0 0 0-.336-.146.47.47 0 0 0-.343.146l-.311.31a.445.445 0 0 0-.14.337c0 .136.047.25.14.343l2.996 2.996a.724.724 0 0 0 .501.203.697.697 0 0 0 .546-.266l6.646-8.417a.497.497 0 0 0 .108-.299.441.441 0 0 0-.164-.336l-.363-.308z"/></svg>';
  }
  return '<svg viewBox="0 0 16 11" width="15" height="11"><path fill="currentColor" d="M15.01.368l-.816-.643a.504.504 0 0 0-.334-.129.522.522 0 0 0-.397.19L8.324 6.479 7.29 5.413a.5.5 0 0 0-.334-.14.51.51 0 0 0-.36.145l-.328.329a.462.462 0 0 0-.15.343c0 .137.05.254.15.354l1.74 1.74a.68.68 0 0 0 .5.194.66.66 0 0 0 .534-.266l5.835-7.393a.531.531 0 0 0 .127-.34.469.469 0 0 0-.176-.348zM11.06.67a.463.463 0 0 0-.335-.135.504.504 0 0 0-.382.188L4.96 6.19 3.42 5.294a.463.463 0 0 0-.336-.14.51.51 0 0 0-.36.146l-.328.329a.462.462 0 0 0-.15.343c0 .136.05.254.15.353l2.326 2.327a.67.67 0 0 0 .5.202.66.66 0 0 0 .534-.266l5.834-7.393a.532.532 0 0 0 .128-.34.469.469 0 0 0-.176-.348L11.06.67z"/></svg>';
}

function setStatus(id, status, expires_at) {
  const m = state.messages.get(id);
  if (!m) return;
  m.status = status;
  if (expires_at != null) m.expires_at = expires_at;
  renderMessage(m);
}

function removeMessage(id) {
  const m = state.messages.get(id);
  if (!m) return;
  const el = state.dom.get(id);
  if (el) {
    seenObserver.unobserve(el);
    el.animate([{ opacity: 1 }, { opacity: 0, transform: 'scale(.96)' }],
               { duration: 220, easing: 'ease-out' })
      .finished.then(() => el.remove()).catch(() => el.remove());
  }
  state.dom.delete(id);
  state.messages.delete(id);
}

function scrollToBottom() {
  els.messages.scrollTop = els.messages.scrollHeight;
}

function renderConversations() {
  if (!state.peer) return;
  const arr = [...state.messages.values()].sort((a, b) => a.created_at - b.created_at);
  const last = arr[arr.length - 1];
  const preview = last
    ? (last.from === state.me ? 'Tu: ' : '') + last.text
    : 'Sin mensajes';
  const time = last ? formatTime(last.created_at) : '';

  els.convList.innerHTML =
    '<li class="active" data-peer="' + escapeHTML(state.peer) + '">' +
      '<div class="avatar">' + (state.peer[0] || '*').toUpperCase() + '</div>' +
      '<div class="conv-info">' +
        '<div class="conv-name">' + escapeHTML(state.peer) + '</div>' +
        '<div class="conv-prev">' + escapeHTML(preview) + '</div>' +
      '</div>' +
      '<div class="conv-meta">' +
        '<div>' + time + '</div>' +
        (state.peerOnline ? '<div style="color:var(--accent);font-size:10.5px">en linea</div>' : '') +
      '</div>' +
    '</li>';
}

function showTyping(on) {
  els.typing.classList.toggle('hidden', !on);
  if (on) {
    clearTimeout(showTyping._t);
    showTyping._t = setTimeout(() => els.typing.classList.add('hidden'), 4000);
  }
}

function buildEmojiPicker() {
  const frag = document.createDocumentFragment();
  for (const e of EMOJIS) {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = e;
    b.addEventListener('click', () => {
      els.input.value += e;
      els.input.focus();
    });
    frag.appendChild(b);
  }
  els.picker.appendChild(frag);
}

let idleTimer;
function resetIdleTimer() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(async () => {
    try { await API.post('/api/logout', {}); } catch (e) {}
    location.reload();
  }, 10 * 60 * 1000);
}
['mousemove', 'keydown', 'touchstart', 'click', 'scroll'].forEach(ev =>
  document.addEventListener(ev, resetIdleTimer, { passive: true })
);

setInterval(renderConversations, 3000);

boot();
