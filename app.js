let masterKey = null;

async function deriveKey(masterPassword, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey("raw", encoder.encode(masterPassword), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
        keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
}

async function desbloquear() {
    const master = document.getElementById('master-key').value;
    const cofre = JSON.parse(localStorage.getItem('cofre') || '[]');
    if (cofre.length > 0) {
        try {
            const salt = Uint8Array.from(atob(cofre[0].salt), c => c.charCodeAt(0));
            await deriveKey(master, salt);
        } catch(e) { return alert("Senha mestre incorreta!"); }
    }
    masterKey = master;
    document.getElementById('tela-acesso').style.display = 'none';
    document.getElementById('tela-cofre').style.display = 'block';
    listarSenhas();
}

async function salvar() {
    const site = document.getElementById('site-reg').value;
    const pass = document.getElementById('pass-reg').value;
    const editId = document.getElementById('edit-id').value;
    if (!site || !pass) return alert("Preencha tudo!");
    
    let cofre = JSON.parse(localStorage.getItem('cofre') || '[]');
    if (editId) {
        cofre = cofre.filter(i => i.id != editId);
        document.getElementById('edit-id').value = '';
    }
    
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(masterKey, salt);
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(pass));
    
    cofre.push({ id: editId || Date.now(), site, ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))), salt: btoa(String.fromCharCode(...salt)), iv: btoa(String.fromCharCode(...iv)) });
    localStorage.setItem('cofre', JSON.stringify(cofre));
    listarSenhas();
}

function editar(id, site, pass) {
    document.getElementById('site-reg').value = site;
    document.getElementById('pass-reg').value = pass;
    document.getElementById('edit-id').value = id;
}

function excluir(id) {
    let cofre = JSON.parse(localStorage.getItem('cofre') || '[]');
    cofre = cofre.filter(item => item.id !== id);
    localStorage.setItem('cofre', JSON.stringify(cofre));
    listarSenhas();
}

function copiar(texto) { navigator.clipboard.writeText(texto); alert("Copiado!"); }

async function listarSenhas() {
    const cofre = JSON.parse(localStorage.getItem('cofre') || '[]');
    const tbody = document.getElementById('lista-senhas');
    tbody.innerHTML = '';
    for (const item of cofre) {
        const salt = Uint8Array.from(atob(item.salt), c => c.charCodeAt(0));
        const iv = Uint8Array.from(atob(item.iv), c => c.charCodeAt(0));
        const ciphertext = Uint8Array.from(atob(item.ciphertext), c => c.charCodeAt(0));
        const key = await deriveKey(masterKey, salt);
        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
        const pass = new TextDecoder().decode(decrypted);
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${item.site}</td>
            <td id="pass-${item.id}" style="filter:blur(5px)">${pass}</td>
            <td>
                <button onclick="document.getElementById('pass-${item.id}').style.filter='none'">👁️</button>
                <button onclick="copiar('${pass}')">📋</button>
                <button onclick="editar(${item.id}, '${item.site}', '${pass}')">✏️</button>
                <button onclick="excluir(${item.id})">🗑️</button>
            </td>`;
        tbody.appendChild(tr);
    }
}
