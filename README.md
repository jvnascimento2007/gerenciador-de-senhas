# Gerenciador de Senhas

Aplicação web client-side para gerenciamento seguro de senhas, com criptografia de ponta a ponta no navegador.

## Funcionalidades

- **Cofre criptografado** — senhas armazenadas apenas localmente no `localStorage`, nunca saem do navegador
- **Acesso por senha mestra** — derivção de chave PBKDF2 (600.000 iterações) + AES-256-GCM
- **Interface responsiva** — tabela no desktop, cards empilhados no mobile
- **CRUD completo** — criar, ler (mostrar/ocultar), copiar, editar, excluir
- **Auto-lock** — bloqueia automaticamente após 5 min de inatividade
- **Limpeza total** — botão "Limpar cofre" para resetar tudo (recuperação de senha esquecida)
- **Indicador de carregamento** — overlay com spinner em operações assíncronas

## Como funciona a criptografia

### Derivação de chave (PBKDF2)
```
Senha mestra + Salt (16 bytes aleatórios) 
  → PBKDF2-HMAC-SHA256 (600.000 iterações) 
  → Chave AES-256 (256 bits)
```
- Salt único por entrada — impede rainbow tables e ataques de dicionário
- 600.000 iterações — segue recomendação OWASP 2024 para PBKDF2

### Criptografia (AES-256-GCM)
```
Chave derivada + IV (12 bytes aleatórios) + Texto plano
  → AES-256-GCM (authenticated encryption)
  → Ciphertext + Tag de autenticação
```
- AES-GCM fornece confidencialidade + integridade + autenticidade em uma operação
- IV único por entrada — evita reutilização de nonce
- Tag de autenticação integrada no ciphertext — detecta qualquer adulteração

### Armazenamento (localStorage)
Cada entrada salva como JSON:
```json
{
  "id": "uuid-v4",
  "site": "exemplo.com",
  "ct": "base64(ciphertext+tag)",
  "salt": "base64(salt-16-bytes)",
  "iv": "base64(iv-12-bytes)"
}
```
- **Nenhum dado sensível em texto plano** — apenas cifrado, salt e IV
- `localStorage` persiste entre sessões/fechamento do navegador
- Dados **nunca saem do dispositivo** — zero rede, zero servidor

### Fluxo de abertura do cofre
1. Usuário digita senha mestra
2. Para cada entrada no `localStorage`: tenta descriptografar com a senha
3. Se **qualquer** entrada descriptografa com sucesso → senha correta
4. Chave derivada mantida apenas em memória (variável JS) enquanto cofre aberto
5. Auto-lock após 5 min de inatividade → limpa memória

## Segurança

| Item | Especificação |
|------|---------------|
| KDF | PBKDF2-HMAC-SHA256, 600.000 iterações |
| Cifra | AES-256-GCM (authenticated encryption) |
| Salt | 16 bytes (crypto.getRandomValues) por entrada |
| IV/Nonce | 12 bytes (crypto.getRandomValues) por entrada |
| Chave | 256 bits derivada via PBKDF2 |
| IDs | crypto.randomUUID() (criptograficamente seguro) |
| Escape HTML | Completo (& < > " ') |
| Memória | Chave apenas em RAM, limpa no lock/close |

## Requisitos

- Navegador moderno com suporte a **Web Crypto API** (`crypto.subtle`) e **localStorage**
- HTTPS ou localhost (Web Crypto API requer contexto seguro)

## Como usar

1. Acesse a página
2. Defina uma **senha mestra** forte e clique em **Abrir**
3. Use **Nova senha** para adicionar entradas (site + senha)
4. Ações por entrada: 👁️ mostrar/ocultar, 📋 copiar, ✏️ editar, 🗑️ excluir
5. **Sair** bloqueia o cofre; **Limpar cofre** apaga tudo permanentemente

## Licença

MIT — uso livre, modifique à vontade.
