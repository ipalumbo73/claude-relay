# Claude Relay

> **Disclaimer — Progetto di Ricerca sulla Sicurezza**
>
> Questo progetto e un **laboratorio di ricerca** creato con l'obiettivo di:
>
  **Comprendere il funzionamento** del meccanismo di autenticazione OAuth di Claude Code e dell'API Anthropic
>
> Tutti i risultati, le tecniche e le scoperte documentate in questo repository sono intesi come **responsible disclosure** e ricerca difensiva. L'autore utilizza esclusivamente le proprie credenziali e il proprio abbonamento, senza accesso non autorizzato a sistemi di terze parti.
>

---

Proxy server che permette di utilizzare i modelli Anthropic (Claude) attraverso le credenziali OAuth di Claude Code (abbonamento Max/Pro), esponendo un'interfaccia compatibile sia con l'API nativa Anthropic che con il formato OpenAI chat completions.

Progettato per integrarsi con **OpenClaw** **PI Agent** **Hermes AI** e qualsiasi client che utilizza il formato OpenAI.

## Risultati della Ricerca

Durante lo sviluppo di questo laboratorio sono stati documentati i seguenti risultati:

| Scoperta | Dettaglio |
|----------|-----------|
| **Fingerprint del system prompt** | Anthropic valida la dimensione/hash del system prompt. Un prompt di 59K chars (vs 26K originale) viene rifiutato con HTTP 400. |
| **Header fingerprinting** | Le richieste richiedono headers specifici (`x-stainless-*`, `anthropic-beta`, `user-agent`) per essere accettate come traffico Claude Code. |
| **Body enrichment** | Campi come `thinking: {type: "adaptive"}`, `context_management` e `output_config` fanno parte del profilo di richiesta atteso. |
| **Beta endpoint** | Claude Code usa `/v1/messages?beta=true`, non il path standard `/v1/messages`. |
| **OAuth vs API key** | Claude Code usa `Authorization: Bearer` (OAuth), non `x-api-key` (API tradizionale). |
| **Rate limiting differenziato** | Richieste senza system prompt CC ricevono 429 (rate limit), con prompt CC ricevono 200. |

Queste informazioni sono condivise in buona fede per aiutare Anthropic a rafforzare i propri meccanismi di sicurezza.

## Funzionalita

- **Doppio endpoint**: API nativa Anthropic (`/v1/messages`) e OpenAI-compatible (`/v1/chat/completions`)
- **Auto-refresh token**: rinnovo automatico dei token OAuth prima della scadenza
- **System prompt injection**: preserva il fingerprint del system prompt di Claude Code
- **Streaming SSE**: supporto completo per streaming in entrambi i formati
- **Research logging**: log JSONL per analisi delle richieste
- **Zero dipendenze**: usa solo moduli built-in di Node.js
- **File watcher**: ricarica automatica del system prompt quando il file cambia

## Prerequisiti

- **Node.js 22+**
- **Credenziali OAuth di Claude Code** (`~/.claude/.credentials.json`)
- **System prompt di Claude Code** catturato (vedi [Cattura System Prompt](#cattura-system-prompt))

## Quick Start

```bash
# 1. Clona il repo
git clone git@github.com:ipalumbo73/claude-relay.git
cd claude-relay

# 2. Configura le credenziali
# Assicurati che ~/.claude/.credentials.json esista (generato da `claude login`)

# 3. Cattura il system prompt (vedi sezione dedicata)
# Il file cc-system-prompt.txt deve essere nella root del progetto

# 4. Avvia
node proxy.mjs
```

## Configurazione

Il file `config.json` contiene tutte le impostazioni:

```json
{
  "port": 3456,
  "targetHost": "api.anthropic.com",
  "targetPath": "/v1/messages",
  "anthropicVersion": "2023-06-01",
  "credentialsPath": "~/.claude/.credentials.json",
  "systemPromptPath": "./cc-system-prompt.txt",
  "logDir": "./logs",
  "logLevel": "info",
  "tokenRefreshMarginMs": 300000,
  "corsOrigin": "*"
}
```

| Parametro | Descrizione | Default |
|-----------|-------------|---------|
| `port` | Porta del proxy | `3456` |
| `credentialsPath` | Path al file credenziali OAuth | `~/.claude/.credentials.json` |
| `systemPromptPath` | Path al system prompt catturato | `./cc-system-prompt.txt` |
| `logDir` | Directory per i log JSONL | `./logs` |
| `logLevel` | Livello di log (`error`, `warn`, `info`, `debug`) | `info` |
| `tokenRefreshMarginMs` | Millisecondi prima della scadenza per il refresh | `300000` (5 min) |
| `corsOrigin` | Header CORS Allow-Origin | `*` |

## API Endpoints

### `POST /v1/messages` — API Nativa Anthropic

Accetta richieste nel formato Anthropic Messages API e le inoltra con le credenziali OAuth.

```bash
curl http://localhost:3456/v1/messages \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet-4-6",
    "max_tokens": 100,
    "messages": [{"role": "user", "content": "Ciao!"}]
  }'
```

### `POST /v1/chat/completions` — OpenAI-Compatible

Accetta richieste nel formato OpenAI chat completions e le traduce automaticamente nel formato Anthropic.

```bash
curl http://localhost:3456/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "anthropic/claude-sonnet-4-6",
    "max_tokens": 100,
    "messages": [
      {"role": "system", "content": "Rispondi in italiano."},
      {"role": "user", "content": "Hello!"}
    ]
  }'
```

**Traduzione dei modelli:**

| ID OpenAI | ID Anthropic |
|-----------|-------------|
| `anthropic/claude-sonnet-5` | `claude-sonnet-5` |
| `anthropic/claude-opus-5` | `claude-opus-5` |
| `anthropic/claude-haiku-4-5` | `claude-haiku-4-5-20251001` |

**Ruoli supportati**: `system`, `developer`, `user`, `assistant` — i ruoli `system` e `developer` vengono estratti e iniettati come messaggi nella conversazione.

### `GET /v1/models` — Lista Modelli

Restituisce i modelli disponibili in formato OpenAI.

### `GET /health` — Health Check

```json
{
  "status": "ok",
  "version": "0.1.0",
  "tokenStatus": "valid",
  "systemPromptLoaded": true,
  "systemPromptBlocks": 3
}
```

## Cattura System Prompt

Il proxy necessita del system prompt autentico di Claude Code per funzionare. Il file deve essere in formato JSON array con 3 blocchi `{type, text}`.

### Metodo: Intercept Proxy

1. Avvia un proxy di intercettazione sulla macchina dove Claude Code e installato:

```javascript
// intercept.js
const http = require('http');
const https = require('https');
const fs = require('fs');

const server = http.createServer((req, res) => {
  let body = '';
  req.on('data', c => body += c);
  req.on('end', () => {
    try {
      const parsed = JSON.parse(body);
      if (parsed.system) {
        fs.writeFileSync('cc-system-prompt.txt', JSON.stringify(parsed.system, null, 2));
        console.log('System prompt captured!');
      }
    } catch {}
    // Forward to Anthropic
    const options = {
      hostname: 'api.anthropic.com',
      path: req.url,
      method: req.method,
      headers: { ...req.headers, host: 'api.anthropic.com' }
    };
    const upstream = https.request(options, upRes => {
      res.writeHead(upRes.statusCode, upRes.headers);
      upRes.pipe(res);
    });
    upstream.write(body);
    upstream.end();
  });
});
server.listen(8899, () => console.log('Intercept proxy on :8899'));
setTimeout(() => process.exit(), 60000); // auto-exit after 60s
```

2. Esegui Claude Code puntando al proxy:

```bash
ANTHROPIC_BASE_URL=http://localhost:8899 claude -p "Say hello" --max-turns 1
```

3. Il file `cc-system-prompt.txt` verra creato con il prompt catturato.

> **Nota**: Il system prompt deve essere ricatturato quando Claude Code viene aggiornato in modo significativo.

## Integrazione con OpenClaw

### 1. Configura il provider

Aggiungi in `/data/.openclaw/agents/main/agent/models.json`:

```json
{
  "providers": {
    "anthropic-proxy": {
      "baseUrl": "http://172.17.0.1:3456/v1",
      "apiKey": "not-needed",
      "auth": "api-key",
      "api": "openai-completions",
      "models": [
        {
          "id": "anthropic/claude-sonnet-4-6",
          "name": "Claude Sonnet 4.6 (Direct)",
          "reasoning": true,
          "input": ["text", "image"],
          "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0},
          "contextWindow": 200000,
          "maxTokens": 128000,
          "compat": {"supportsStore": true, "supportsDeveloperRole": true}
        }
      ]
    }
  }
}
```

### 2. Aggiungi il default in `openclaw.json`

```json
{
  "agents": {
    "defaults": {
      "models": {
        "anthropic-proxy/anthropic/claude-sonnet-4-6": {
          "alias": "Claude Sonnet 4.6 (Direct)"
        }
      }
    }
  }
}
```

### 3. Networking Docker

Il proxy gira sull'host. Dal container Docker, usa `172.17.0.1` (bridge gateway) come indirizzo, non `localhost`.

## Deploy come Servizio Systemd

```bash
# Copia i file
sudo mkdir -p /opt/claude-relay
sudo cp proxy.mjs config.json package.json /opt/claude-relay/

# Copia il system prompt catturato
sudo cp cc-system-prompt.txt /opt/claude-relay/

# Crea il servizio
sudo tee /etc/systemd/system/claude-relay.service << 'EOF'
[Unit]
Description=Claude Relay - Anthropic OAuth Proxy
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/claude-relay
ExecStart=/usr/bin/node proxy.mjs
Restart=always
RestartSec=5
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

# Abilita e avvia
sudo systemctl daemon-reload
sudo systemctl enable claude-relay
sudo systemctl start claude-relay

# Verifica
curl http://localhost:3456/health
```

## Auto-Refresh Token

Il proxy gestisce automaticamente il rinnovo dei token OAuth:

- **Check periodico**: ogni 10 minuti
- **Refresh preventivo**: 5 minuti prima della scadenza
- **Endpoint**: `https://platform.claude.com/v1/oauth/token`
- **Mutex**: previene refresh concorrenti
- **Salvataggio**: aggiorna automaticamente il file credentials

Se il refresh fallisce, il proxy continua a funzionare con il token corrente finche non scade.

## Architettura

```
Client (OpenClaw/curl/app)
    |
    | POST /v1/chat/completions (OpenAI format)
    | POST /v1/messages (Anthropic format)
    v
+-------------------+
|   Claude Relay    |
|                   |
|  1. Parse request |
|  2. Translate fmt |
|  3. Inject CC     |
|     system prompt |
|  4. Add OAuth tok |
|  5. Forward       |
+-------------------+
    |
    | POST /v1/messages (Anthropic format)
    | Authorization: Bearer sk-ant-oat01-...
    v
api.anthropic.com
```

### Design critico: Fingerprint del System Prompt

Il system prompt di Claude Code deve essere inviato **byte-identico** all'originale. Anthropic valida il fingerprint (dimensione/hash) del prompt. Se il client invia un system prompt proprio (es. OpenClaw), questo viene iniettato come messaggio `<system-reminder>` nella conversazione, **mai** aggiunto ai blocchi del system prompt CC.

## Log e Monitoraggio

### Log di servizio
```bash
journalctl -u claude-relay -f
```

### Research log (JSONL)
Ogni richiesta viene loggata in `./logs/research-YYYY-MM-DD.jsonl`:

```json
{
  "id": "abc123",
  "timestamp": "2026-04-12T21:18:14.586Z",
  "request": {"model": "claude-sonnet-4-6", "stream": true, "format": "openai-compat"},
  "response": {"status": 200, "detectionBlocked": false, "streamed": true},
  "timing": {"ttfb": 1331, "total": 2615},
  "token": {"expired": false, "subscription": "max"}
}
```

## Etica e Responsible Disclosure

Questo progetto segue i principi della ricerca responsabile sulla sicurezza:

- **Solo credenziali proprie**: nessun accesso a credenziali o account di terzi
- **Documentazione aperta**: tutte le scoperte sono documentate per trasparenza
- **Scopo difensivo**: l'obiettivo e aiutare Anthropic a identificare e correggere potenziali vulnerabilita
- **Nessuna distribuzione malevola**: il repository e privato e non inteso per uso abusivo

Se sei un membro del team di sicurezza di Anthropic e desideri discutere queste scoperte, contattami.

## Licenza

Uso privato — progetto di ricerca sulla sicurezza. Non distribuire.
