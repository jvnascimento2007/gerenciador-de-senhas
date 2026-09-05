(() => {
  'use strict';
  let masterKey = null;
  let cofreCache = [];

  // ---------- Crypto ----------
  async function deriveKey(pwd, salt) {
    const enc = new TextEncoder();
    const base = await crypto.subtle.importKey('raw', enc.encode(pwd), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }

  async function encrypt(text, pwd) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv   = crypto.getRandomValues(new Uint8Array(12));
    const key  = await deriveKey(pwd, salt);
    const ct   = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(text));
    return { ct: btoa(String.fromCharCode(...new Uint8Array(ct))), salt: btoa(String.fromCharCode(...salt)), iv: btoa(String.fromCharCode(...iv)) };
  }

  async function decrypt(item, pwd) {
    const salt = Uint8Array.from(atob(item.salt), c => c.charCodeAt(0));
    const iv   = Uint8Array.from(atob(item.iv),   c => c.charCodeAt(0));
    const ct   = Uint8Array.from(atob(item.ct),   c => c.charCodeAt(0));
    const key  = await deriveKey(pwd, salt);
    const pt   = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return new TextDecoder().decode(pt);
  }

  // ---------- Storage ----------
  function loadCofre() {
    try {
      const data = JSON.parse(localStorage.getItem('cofre') || '[]');
      return data.filter(item => item && item.salt && item.iv && item.ct && item.site);
    } catch { return []; }
  }
  function saveCofre(c) { localStorage.setItem('cofre', JSON.stringify(c)); }
  function clearCofre() { localStorage.removeItem('cofre'); cofreCache = []; }

  // ---------- UI ----------
  const $ = id => document.getElementById(id);
  const telaAcesso = $('tela-acesso');
  const telaCofre  = $('tela-cofre');
  const tbody      = $('lista-senhas');
  const cardList   = $('card-list');
  const editIdEl   = $('edit-id');

  function showCofre() { telaAcesso.hidden = true; telaCofre.hidden = false; }
  function lockCofre() { telaAcesso.hidden = false; telaCofre.hidden = true; masterKey = null; cofreCache = []; tbody.innerHTML = ''; cardList.innerHTML = ''; $('master-key').value = ''; }

  // ---------- Render ----------
  async function render() {
    tbody.innerHTML = '';
    cardList.innerHTML = '';
    for (const item of cofreCache) {
      const pass = await decrypt(item, masterKey);
      
      // Table row (desktop)
      const tr = document.createElement('tr');
      tr.dataset.id = item.id;
      tr.innerHTML = `
        <td>${escapeHtml(item.site)}</td>
        <td class="pwd-cell" data-id="${item.id}"><span class="pwd-blur">${'•'.repeat(pass.length)}</span><span class="pwd-clear" hidden>${escapeHtml(pass)}</span></td>
        <td>
          <button class="btn-eye" data-action="toggle" data-id="${item.id}" title="Mostrar/ocultar">👁️ Mostrar</button>
          <button class="btn-copy" data-action="copy" data-id="${item.id}" title="Copiar">📋 Copiar</button>
          <button class="btn-edit" data-action="edit" data-id="${item.id}" title="Editar">✏️ Editar</button>
          <button class="btn-del"  data-action="delete" data-id="${item.id}" title="Excluir">🗑️ Excluir</button>
        </td>`;
      tbody.appendChild(tr);

      // Card (mobile)
      const card = document.createElement('div');
      card.className = 'pwd-card';
      card.dataset.id = item.id;
      card.innerHTML = `
        <div class="card-header">${escapeHtml(item.site)}</div>
        <div class="pwd-row">
          <span class="pwd-blur">${'•'.repeat(pass.length)}</span>
          <span class="pwd-clear" hidden>${escapeHtml(pass)}</span>
          <button class="btn-eye" data-action="toggle" data-id="${item.id}">👁️ Mostrar</button>
        </div>
        <div class="card-actions">
          <button class="btn-copy" data-action="copy" data-id="${item.id}">📋 Copiar</button>
          <button class="btn-edit" data-action="edit" data-id="${item.id}">✏️ Editar</button>
          <button class="btn-del" data-action="delete" data-id="${item.id}">🗑️ Excluir</button>
        </div>`;
      cardList.appendChild(card);
    }
  }

  function escapeHtml(s) {
    return s
      .replace(/&/g, '&')
      .replace(/</g, '<')
      .replace(/>/g, '>')
      .replace(/"/g, '"');
  }

  // ---------- Actions ----------
  function updateEyeButton(id, show) {
    const text = show ? '👁️ Ocultar' : '👁️ Mostrar';
    // Table
    const tableBtn = tbody.querySelector('.btn-eye[data-id="' + id + '"]');
    if (tableBtn) tableBtn.textContent = text;
    // Card
    const cardBtn = cardList.querySelector('.btn-eye[data-id="' + id + '"]');
    if (cardBtn) cardBtn.textContent = text;
  }

  function togglePwd(id) {
    // Table
    const cell = tbody.querySelector('.pwd-cell[data-id="' + id + '"]');
    if (cell) {
      const blurred = cell.querySelector('.pwd-blur');
      const clear   = cell.querySelector('.pwd-clear');
      const show = blurred.hidden;
      blurred.hidden = !show;
      clear.hidden = show;
      updateEyeButton(id, show);
    }
    // Card
    const card = cardList.querySelector('.pwd-card[data-id="' + id + '"]');
    if (card) {
      const blurred = card.querySelector('.pwd-blur');
      const clear   = card.querySelector('.pwd-clear');
      const show = blurred.hidden;
      blurred.hidden = !show;
      clear.hidden = show;
      updateEyeButton(id, show);
    }
  }

  async function copyPwd(id) {
    const item = cofreCache.find(i => i.id === id);
    if (!item) return;
    const pass = await decrypt(item, masterKey);
    await navigator.clipboard.writeText(pass);
    alert('Senha copiada!');
  }

  function editPwd(id) {
    const item = cofreCache.find(i => i.id === id);
    if (!item) return;
    $('site-reg').value = item.site;
    editIdEl.value = id;
    $('pass-reg').value = '';
    $('pass-reg').focus();
  }

  function deletePwd(id) {
    cofreCache = cofreCache.filter(i => i.id !== id);
    saveCofre(cofreCache);
    render();
  }

  // ---------- Event Listeners ----------
  $('btn-desbloquear').addEventListener('click', async () => {
    const pwd = $('master-key').value.trim();
    if (!pwd) return alert('Digite a senha mestra');
    
    cofreCache = loadCofre();
    
    // Se não há dados válidos, aceita qualquer senha (primeiro uso)
    if (cofreCache.length === 0) {
      masterKey = pwd;
      showCofre();
      render();
      return;
    }
    
    // Há dados - validar senha
    try {
      await decrypt(cofreCache[0], pwd);
      masterKey = pwd;
      showCofre();
      render();
    } catch (e) {
      alert('Senha incorreta.');
    }
  });

  $('btn-limpar').addEventListener('click', () => {
    if (confirm('TEM CERTEZA? Isso apaga TODAS as senhas permanentemente.')) {
      clearCofre();
      $('master-key').value = '';
      alert('Cofre limpo. Defina uma nova senha mestra.');
    }
  });

  $('btn-sair').addEventListener('click', lockCofre);

  $('btn-salvar').addEventListener('click', async () => {
    const site = $('site-reg').value.trim();
    const pass = $('pass-reg').value;
    if (!site || !pass) return alert('Preencha todos os campos');
    const editId = editIdEl.value ? Number(editIdEl.value) : null;
    const encrypted = await encrypt(pass, masterKey);
    const newItem = { id: editId || Date.now() + Math.random(), site, ...encrypted };
    if (editId) cofreCache = cofreCache.filter(i => i.id !== editId);
    cofreCache.push(newItem);
    saveCofre(cofreCache);
    editIdEl.value = '';
    $('site-reg').value = '';
    $('pass-reg').value = '';
    render();
  });

  // Delegação única na tabela E cards
  const handleActionClick = e => {
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;
    const id = Number(btn.dataset.id);
    switch (btn.dataset.action) {
      case 'toggle': togglePwd(id); break;
      case 'copy':   copyPwd(id);   break;
      case 'edit':   editPwd(id);   break;
      case 'delete': deletePwd(id); break;
    }
  };
  tbody.addEventListener('click', handleActionClick);
  cardList.addEventListener('click', handleActionClick);

  // Bloqueio por inatividade (5 min)
  let idleTimer;
  function resetIdle() {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(lockCofre, 5 * 60 * 1000);
  }
  ['mousemove','keydown','click','touchstart'].forEach(ev => document.addEventListener(ev, resetIdle, {passive:true}));
  resetIdle();
})();