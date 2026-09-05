async function deriveKey(masterPassword, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey("raw", encoder.encode(masterPassword), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
        keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
}

async function salvar() {
    const master = document.getElementById('master-reg').value;
    const site = document.getElementById('site-reg').value;
    const pass = document.getElementById('pass-reg').value;
    if (!master || !site || !pass) return alert("Preencha tudo!");
    
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(master, salt);
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(pass));
    
    // Armazena como um array de senhas para facilitar a listagem
    const cofre = JSON.parse(localStorage.getItem('cofre') || '[]');
    cofre.push({
        site,
        ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
        salt: btoa(String.fromCharCode(...salt)),
        iv: btoa(String.fromCharCode(...iv))
    });
    localStorage.setItem('cofre', JSON.stringify(cofre));
    alert("Senha salva!");
}

async function abrirCofre() {
    const master = document.getElementById('master-open').value;
    const cofre = JSON.parse(localStorage.getItem('cofre') || '[]');
    const lista = document.getElementById('lista-senhas');
    lista.innerHTML = '';
    
    for (const item of cofre) {
        try {
            const salt = Uint8Array.from(atob(item.salt), c => c.charCodeAt(0));
            const iv = Uint8Array.from(atob(item.iv), c => c.charCodeAt(0));
            const ciphertext = Uint8Array.from(atob(item.ciphertext), c => c.charCodeAt(0));
            const key = await deriveKey(master, salt);
            const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
            lista.innerHTML += `<p><strong>${item.site}:</strong> ${new TextDecoder().decode(decrypted)}</p>`;
        } catch {
            lista.innerHTML += `<p style="color:red">${item.site}: Senha inválida</p>`;
        }
    }
}
