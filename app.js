async function deriveKey(masterPassword, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey("raw", encoder.encode(masterPassword), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
        keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
}

async function salvar() {
    const master = document.getElementById('master-password').value;
    const site = document.getElementById('site').value;
    const pass = document.getElementById('password').value;
    if (!master || !site || !pass) return alert("Preencha todos os campos!");
    
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(master, salt);
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(pass));
    
    localStorage.setItem(site, JSON.stringify({
        ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
        salt: btoa(String.fromCharCode(...salt)),
        iv: btoa(String.fromCharCode(...iv))
    }));
    alert("Senha salva!");
}

async function buscar() {
    const master = document.getElementById('master-password').value;
    const site = document.getElementById('site-busca').value;
    const data = JSON.parse(localStorage.getItem(site));
    if (!data) return alert("Site não encontrado.");
    
    const salt = Uint8Array.from(atob(data.salt), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(data.iv), c => c.charCodeAt(0));
    const ciphertext = Uint8Array.from(atob(data.ciphertext), c => c.charCodeAt(0));
    
    try {
        const key = await deriveKey(master, salt);
        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
        document.getElementById('resultado').innerText = "Senha: " + new TextDecoder().decode(decrypted);
    } catch {
        alert("Mestre senha incorreta!");
    }
}
