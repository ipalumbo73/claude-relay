# LokiFix — Architettura del Tunnel e Flusso di Connessione

> Documento tecnico per comprendere come lokifix-agent si connette al server MCP e permette a Claude Code di operare su un PC remoto.

---

## Panoramica

LokiFix e un sistema a due componenti che permette a Claude Code (sul PC dell'operatore) di eseguire comandi e operazioni su un PC remoto, senza installare Claude Code sulla macchina remota.

```
PC OPERATORE                                 PC REMOTO (cliente)
============                                 ===================

Claude Code                                  lokifix-agent.exe
    |                                             |
    | stdio (JSON-RPC)                            | (esegue comandi,
    |                                             |  legge file, ecc.)
    v                                             |
lokifix-mcp.exe                                   |
    |                                             |
    |-- WebSocket Server (porta random)           |
    |-- Auth Manager (codici + token)             |
    |-- Tunnel cloudflared                        |
    |        |                                    |
    |        v                                    v
    |   cloudflared tunnel              connessione WebSocket
    |   (crea URL pubblico              in USCITA verso il
    |    *.trycloudflare.com)           tunnel Cloudflare
    |        |                                    |
    +--------+----------INTERNET------------------+
                  (TLS + AES-256-GCM E2E)
```

---

## I tre layer di comunicazione

### Layer 1: Claude Code <-> lokifix-mcp.exe (stdio)

Claude Code avvia `lokifix-mcp.exe` come processo figlio. Comunicano tramite **stdin/stdout** usando il protocollo MCP (Model Context Protocol) in formato JSON-RPC.

- Claude Code scrive su stdin di lokifix-mcp
- lokifix-mcp risponde su stdout
- Formato: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{...}}\n`
- E un protocollo standard di Claude Code — qualsiasi MCP server funziona cosi

**Configurazione MCP** (registra lokifix-mcp in Claude Code):
```bash
claude mcp add lokifix-remote -- "C:\percorso\build\lokifix-mcp.exe"
```

### Layer 2: lokifix-mcp.exe <-> lokifix-agent.exe (WebSocket)

I due componenti comunicano tramite WebSocket con messaggi JSON "envelope":

```json
{
  "type": "request",
  "id": "req-42",
  "ts": 1712000000000,
  "payload": {
    "tool": "shell_exec",
    "params": {"command": "Get-Service", "shell": "powershell"}
  }
}
```

Tipi di messaggio:
- `request` — MCP server invia un comando all'agent
- `response` — Agent risponde con il risultato
- `ping` / `pong` — Keep-alive ogni 30 secondi
- `audit_log_batch` — Agent invia log centralizzati (futuro)

### Layer 3: Crittografia E2E (AES-256-GCM)

Dopo l'handshake di autenticazione, **tutti i messaggi** sono cifrati con AES-256-GCM:

1. La chiave viene derivata dal token di autenticazione usando **HKDF-SHA256**
2. Ogni messaggio viene cifrato: `nonce (12 byte) + ciphertext + GCM tag (16 byte)`
3. Inviato come WebSocket **binario** (non testo)
4. Il ricevente decifra e ottiene il JSON originale

```
PRIMA dell'auth:  messaggi WebSocket TEXT (JSON in chiaro)
DOPO l'auth:      messaggi WebSocket BINARY (AES-256-GCM cifrato)
```

Questo significa che **Cloudflare non puo leggere** il contenuto dei messaggi. Vede solo blob binari cifrati.

---

## Il Tunnel Cloudflare: come funziona

### Problema da risolvere

Il PC del cliente e tipicamente dietro NAT/firewall. Non puoi aprire porte o configurare port-forwarding. Serve un modo per connettere i due PC senza toccare il router.

### Soluzione: Cloudflare Quick Tunnel

Cloudflare offre "Quick Tunnels" gratuiti: un URL pubblico temporaneo che punta a un servizio locale.

```
lokifix-mcp avvia:
  cloudflared tunnel --url http://localhost:{porta} --no-autoupdate

cloudflared:
  1. Si connette ai server Cloudflare (connessione in USCITA)
  2. Cloudflare assegna un URL casuale: https://abc123-def456.trycloudflare.com
  3. Qualsiasi richiesta a quell'URL viene inoltrata a http://localhost:{porta}
```

**Caratteristiche chiave:**
- **Zero porte aperte**: cloudflared fa solo connessioni in uscita (come navigare un sito)
- **TLS automatico**: Cloudflare gestisce i certificati
- **URL temporaneo**: cambia a ogni avvio, non e indovinabile
- **Gratuito**: non serve account Cloudflare
- **Nessuna configurazione**: basta un singolo comando

### Conversione URL per WebSocket

cloudflared restituisce un URL HTTPS. Lokifix lo converte per WebSocket:

```
cloudflared output:  https://abc123-def456.trycloudflare.com
lokifix converte:    wss://abc123-def456.trycloudflare.com
```

Il WebSocket viaggia sulla stessa connessione HTTPS (upgrade protocol).

### Estrazione dell'URL (codice)

lokifix-mcp avvia cloudflared e legge stderr con una regex per catturare l'URL:

```go
// regex applicata su stderr di cloudflared
urlRegex := regexp.MustCompile(`https://[a-zA-Z0-9-]+\.trycloudflare\.com`)

// timeout: 30 secondi per ottenere l'URL
// se scade, fallback a connessione locale ws://localhost:{porta}
```

---

## Flusso di connessione completo (passo-passo)

### Fase 1: Avvio del server MCP

```
1. Claude Code avvia lokifix-mcp.exe (come processo stdio)

2. lokifix-mcp.exe:
   a. Crea un Auth Manager (gestisce codici e token)
   b. Avvia un WebSocket Server su una porta TCP casuale (es. porta 54321)
   c. Cerca cloudflared.exe:
      - Prima in build/ accanto all'eseguibile
      - Poi nel PATH di sistema
      - Se non trovato, lo scarica da GitHub
   d. Avvia cloudflared:
      cloudflared tunnel --url http://localhost:54321 --no-autoupdate
   e. Aspetta fino a 30s che cloudflared stampi l'URL del tunnel
   f. Ottiene: wss://abc123-def456.trycloudflare.com

3. Genera un codice di connessione:
   a. Crea un token random di 32 byte (crypto/rand)
   b. Codifica: base64url(wss://abc123-def456.trycloudflare.com/ws|token_base64)
   c. Genera un codice di sessione a 6 caratteri (alfabeto: ABCDEFGHJKLMNPQRSTUVWXYZ23456789)
   d. Il token scade dopo 15 minuti
   e. E monouso (una volta validato, viene cancellato)

4. Salva il codice in ~/lokifix-connection.txt e lo stampa su stderr

5. Avvia il server MCP su stdin/stdout (protocollo JSON-RPC)
   - Espone 19 tool a Claude Code
   - Resta in attesa di richieste da Claude Code
   - Resta in attesa della connessione dell'agent sul WebSocket
```

### Fase 2: Connessione dell'agent

```
1. L'operatore comunica il codice di connessione al cliente
   (telefono, chat, email — qualsiasi canale)

2. Il cliente avvia lokifix-agent.exe e inserisce il codice

3. lokifix-agent.exe:
   a. Decodifica il codice: base64url decode -> estrae URL + token
   b. Si connette al WebSocket: wss://abc123-def456.trycloudflare.com/ws
      (questa connessione e in USCITA — nessuna porta da aprire)
   c. Invia un messaggio di handshake:
      {
        "type": "response",
        "id": "auth",
        "payload": {
          "token": "abc123...",        // il token dal codice
          "session_token": "",          // vuoto alla prima connessione
          "hostname": "PC-CLIENTE",
          "os": "windows",
          "arch": "amd64"
        }
      }

4. Il WebSocket server (dentro lokifix-mcp) riceve l'handshake:
   a. Valida il token (constant-time compare) ✓
   b. Il token era valido e non scaduto ✓
   c. Genera un session token (32 byte random, valido 24h)
   d. Risponde:
      {
        "accepted": true,
        "message": "connected",
        "session_token": "xyz789..."  // per le riconnessioni future
      }

5. ENCRYPTION HANDSHAKE (implicito):
   a. Entrambi i lati derivano la stessa chiave AES-256:
      chiave = HKDF-SHA256(token, salt="lokifix-e2e-v1", info="aes-256-gcm")
   b. Da questo momento, TUTTI i messaggi sono cifrati AES-256-GCM
   c. Il tunnel Cloudflare vede solo blob binari illeggibili

6. Connessione stabilita!
   - lokifix-mcp notifica Claude Code: "Remote agent connected: PC-CLIENTE"
   - L'agent avvia il ping loop (ogni 30s)
   - L'agent mostra "Connesso" nella console con log in tempo reale
```

### Fase 3: Esecuzione di un comando remoto

```
Claude Code vuole eseguire: "Get-Service | Where Status -eq Running"

1. Claude Code -> lokifix-mcp (stdio JSON-RPC):
   {"jsonrpc":"2.0","id":5,"method":"tools/call","params":{
     "name":"remote_shell",
     "arguments":{"command":"Get-Service | Where Status -eq Running"}
   }}

2. lokifix-mcp:
   a. Mappa "remote_shell" -> "shell_exec" (nome protocollo interno)
   b. Crea envelope request:
      {"type":"request","id":"req-5","ts":1712345678,"payload":{
        "tool":"shell_exec",
        "params":{"command":"Get-Service | Where Status -eq Running"}
      }}
   c. Serializza in JSON
   d. CIFRA con AES-256-GCM -> blob binario
   e. Invia via WebSocket (MessageBinary) all'agent

3. Il messaggio viaggia:
   lokifix-mcp -> WebSocket locale -> cloudflared -> Cloudflare CDN
   -> cloudflared (implicito, client nel tunnel) -> WebSocket -> agent
   
   Cloudflare vede: blob binario cifrato (non sa cosa contiene)

4. lokifix-agent riceve:
   a. Riceve MessageBinary dal WebSocket
   b. DECIFRA con AES-256-GCM -> JSON in chiaro
   c. Parsa l'envelope, estrae tool="shell_exec"
   d. Controlla se e un'operazione pericolosa:
      - "Get-Service" non matcha nessun pattern pericoloso -> OK
   e. Esegue in PowerShell:
      powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Get-Service | Where Status -eq Running"
   f. Cattura stdout, stderr, exit code
   g. Logga nell'audit trail locale (SHA-256 hash chain)
   h. Mostra nella console: "✓ 14:30:15 OK SHELL_EXEC [powershell] Get-Service..."

5. lokifix-agent risponde:
   a. Crea envelope response:
      {"type":"response","id":"req-5","ts":1712345679,"payload":{
        "success":true,
        "data":{"exit_code":0,"stdout":"Running  AppIDSvc\nRunning  ...","stderr":""}
      }}
   b. CIFRA con AES-256-GCM
   c. Invia via WebSocket

6. lokifix-mcp riceve:
   a. DECIFRA la risposta
   b. Matcha "req-5" con la richiesta pendente
   c. Formatta per MCP e scrive su stdout:
      {"jsonrpc":"2.0","id":5,"result":{
        "content":[{"type":"text","text":"...output formattato..."}],
        "isError":false
      }}

7. Claude Code riceve l'output e lo analizza/presenta all'utente
```

### Fase 4: Riconnessione automatica

```
Se la connessione cade (rete instabile, PC in sleep):

1. L'agent rileva la disconnessione (WebSocket read error)
2. Aspetta 2 secondi, poi riprova
3. Si riconnette allo STESSO URL del tunnel
4. Invia handshake con il SESSION TOKEN (non il codice originale):
   {"session_token": "xyz789...", "token": ""}
5. Il server valida il session token (valido 24h) -> OK
6. Nuova chiave AES derivata dal session token
7. Connessione ripristinata senza reinserire il codice

Tentativi: 5 con backoff esponenziale (2s, 4s, 6s, 8s, 10s)
Se tutti falliscono: l'agent si ferma e mostra l'errore
```

---

## Configurazione e flag

### lokifix-mcp.exe

| Flag/Env | Effetto |
|----------|---------|
| (nessun flag) | Comportamento standard: tunnel + MCP |
| `--no-tunnel` | Nessun tunnel, usa `ws://localhost:{porta}` (per test locali) |
| `--standalone` | Solo WebSocket server, niente MCP stdio (per debug) |
| `LOKIFIX_TUNNEL_URL` | Forza un URL tunnel specifico (salta cloudflared) |

### lokifix-agent.exe

| Input | Effetto |
|-------|---------|
| Argomento CLI | Codice di connessione passato come argomento |
| Prompt interattivo | Se nessun argomento, chiede il codice all'avvio |

---

## Sicurezza del tunnel

### Cosa protegge

| Minaccia | Protezione |
|----------|-----------|
| **Intercettazione Cloudflare** | AES-256-GCM E2E — Cloudflare vede solo blob cifrati |
| **Brute force del codice** | Token 32 byte random + scadenza 15 min + monouso |
| **Replay attack** | Nonce unico per ogni messaggio (GCM) |
| **Timing attack su token** | Confronto constant-time (crypto/subtle) |
| **Connessione non autorizzata** | Handshake con timeout 5s, reject immediato se token invalido |
| **Man-in-the-middle** | TLS (Cloudflare) + AES-256-GCM (applicativo) = doppio layer |

### Cosa NON protegge

| Minaccia | Note |
|----------|------|
| **Codice intercettato** | Se qualcuno intercetta il codice nei 15 min di validita, puo connettersi |
| **Compromissione del PC** | Se il PC dell'operatore o del cliente e compromesso, l'attaccante ha accesso |
| **Cloudflare down** | Se Cloudflare e irraggiungibile, il tunnel non funziona (fallback: --no-tunnel) |

---

## Diagramma dei port/protocolli

```
PC OPERATORE                    CLOUDFLARE                     PC CLIENTE
============                    ==========                     ==========

lokifix-mcp.exe                                                lokifix-agent.exe
  |                                                              |
  |-- WebSocket Server                                           |
  |   porta: random (es. 54321)                                  |
  |   bind: 0.0.0.0                                              |
  |                                                              |
  |-- cloudflared                                                |
  |   connessione USCITA       Cloudflare CDN                    |
  |   porta 443 (HTTPS) -----> *.trycloudflare.com              |
  |                             |                                |
  |                             |         connessione USCITA     |
  |                             +<------- porta 443 (WSS) ------+
  |                                                              |
  |-- Claude Code (stdio)                                        |
      stdin/stdout                                               |
      (JSON-RPC MCP)                                             |
                                                                 |
PORTE APERTE: NESSUNA          PORTE APERTE: 443 (standard)    PORTE APERTE: NESSUNA
```

**Nota critica**: Nessuno dei due PC apre porte in ingresso. Entrambi fanno solo connessioni in uscita sulla porta 443 (HTTPS standard). Per questo funziona anche dietro firewall aziendali restrittivi.

---

## File e percorsi

| File | Posizione | Scopo |
|------|-----------|-------|
| `lokifix-mcp.exe` | `build/` sul PC operatore | MCP server + tunnel |
| `lokifix-agent.exe` | Qualsiasi posizione sul PC cliente | Agent portabile |
| `cloudflared.exe` | `build/` o PATH | Tunnel Cloudflare |
| `~/lokifix-connection.txt` | Home dell'operatore | Codice di connessione (cancellato dopo la connessione) |
| `~/lokifix-logs/` | Home dell'operatore | Audit log operatore |
| `./lokifix-logs/` | Accanto a lokifix-agent.exe | Audit log remoto |

---

## Registrazione in Claude Code

Per usare LokiFix, deve essere registrato come MCP server in Claude Code:

```bash
# CLI (Claude Code terminal / VS Code extension)
claude mcp add lokifix-remote -- "C:\percorso\completo\build\lokifix-mcp.exe"

# Verifica
claude mcp list
```

Dopo la registrazione, Claude Code avvia automaticamente `lokifix-mcp.exe` quando usa uno dei 19 tool remoti.

---

## Tool disponibili (19 totali)

| # | Tool MCP | Tool Protocollo | Tipo |
|---|----------|----------------|------|
| 1 | `remote_shell` | `shell_exec` | Esecuzione comandi PowerShell/CMD |
| 2 | `remote_file_read` | `file_read` | Lettura file con numeri di riga |
| 3 | `remote_file_write` | `file_write` | Scrittura file |
| 4 | `remote_file_edit` | `file_edit` | Sostituzione stringa (+ replace_all) |
| 5 | `remote_file_list` | `file_list` | Elenco directory |
| 6 | `remote_file_delete` | `file_delete` | Eliminazione ricorsiva |
| 7 | `remote_file_upload` | `file_upload_chunk` | Transfer operatore -> remoto (chunked) |
| 8 | `remote_file_download` | `file_download_chunk` | Transfer remoto -> operatore (chunked) |
| 9 | `remote_glob` | `glob` | Ricerca file con ** ricorsivo |
| 10 | `remote_grep` | `grep` | Ricerca regex completa (output_mode, context, type) |
| 11 | `remote_sysinfo` | `sys_info` | Info sistema |
| 12 | `remote_processes` | `processes` | Processi (top 50 CPU) |
| 13 | `remote_services` | `services` | Servizi Windows |
| 14 | `remote_registry` | `registry_read` | Registro Windows |
| 15 | `remote_netinfo` | `net_info` | Interfacce di rete |
| 16 | `remote_env_vars` | `env_vars` | Variabili d'ambiente |
| 17 | `remote_installed_software` | `installed_software` | Software installato |
| 18 | `remote_event_log` | `event_log` | Event Log Windows |
| 19 | `remote_connection_status` | _(locale)_ | Stato connessione (non richiede agent) |
