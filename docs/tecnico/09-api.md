# Documentação da API — HidraNet

**Versão 1.0** · Todos os serviços ligam apenas a `127.0.0.1`.

> ⚠️ **Nenhum endpoint deve ser exposto à rede pública.** A API não tem
> autenticação, porque assume que só processos locais lhe chegam. Expô-la em
> `0.0.0.0` entrega o controlo do nó a quem o alcançar.

---

## 1. Portas

| Porta | Serviço | Protocolo |
|---|---|---|
| 9051 | API do nó | HTTP/JSON |
| 9050 | Proxy | SOCKS5 |
| 8084 | SevenNine | HTTP |
| 8082 | Painel de análise | HTTP/JSON |
| 8080 | HidraMail autónomo | HTTP/JSON |
| 8081 | HidraChat autónomo | HTTP/WebSocket |
| 8090 | Aplicações do browser | HTTP |
| 9150 | Rede entre nós | TCP (Noise) |
| 7000 | DHT | UDP |

---

## 2. API do nó — porta 9051

### `GET /api/status`

```bash
curl http://127.0.0.1:9051/api/status
```

```json
{
  "node_id": "a3f9c2...",
  "state": "running",
  "relay_count": 3,
  "uptime_seconds": 8420,
  "dht_peers": 27
}
```

### `GET /api/resolve`

Resolve um nome `.hidra` para um endereço de rede.

| Parâmetro | Tipo | Descrição |
|---|---|---|
| `name` | string | Nome sem o sufixo `.hidra` |

```bash
curl "http://127.0.0.1:9051/api/resolve?name=7k2mx9qpvz3nd8fw4h6j"
```

```json
{ "address": "127.0.0.1:8084", "found": true }
```

Não encontrado:

```json
{ "found": false }
```

---

## 3. API do HidraMail — porta 8080

Disponível com `hidra-node --apps` ou `--mail`.

### `GET /api/identity`

```json
{ "address": "k3mz7qp2vx@hidra", "created": 1758412800 }
```

### `GET /api/pubkey`

```json
{ "pubkey": "BFq2n8...", "format": "raw-p256-base64" }
```

### `GET /api/inbox`

```json
{
  "messages": [
    {
      "mid": "m1758412800123",
      "from": "x9k2mqp4vz@hidra",
      "subject": "Assunto",
      "date": 1758412800000,
      "read": false
    }
  ],
  "total": 1
}
```

> **Nota de segurança:** o campo `from` é uma afirmação não assinada. Não o use
> para autorização. Ver Whitepaper §4.2.

### `GET /api/sent`

Mesma estrutura que `/api/inbox`.

### `GET /api/mail/{mid}`

```bash
curl http://127.0.0.1:8080/api/mail/m1758412800123
```

```json
{
  "mid": "m1758412800123",
  "from": "x9k2mqp4vz@hidra",
  "to": "k3mz7qp2vx@hidra",
  "subject": "Assunto",
  "body": "Corpo decifrado.",
  "date": 1758412800000
}
```

### `POST /api/send`

```bash
curl -X POST http://127.0.0.1:8080/api/send \
  -H 'Content-Type: application/json' \
  -d '{"to":"x9k2mqp4vz@hidra","subject":"Olá","body":"Mensagem."}'
```

| Campo | Tipo | Obrigatório |
|---|---|---|
| `to` | string | sim |
| `subject` | string | sim |
| `body` | string | sim |

Sucesso:

```json
{ "ok": true, "mid": "m1758412800456" }
```

Erro:

```json
{ "ok": false, "error": "Endereço não encontrado na rede" }
```

Limite: ~500 KB de corpo.

### `POST /api/deliver`

Entrega interna entre nós. Recebe a mensagem já cifrada; o nó não a consegue
ler. Não se destina a uso por aplicações.

### `DELETE /api/mail/{mid}`

```json
{ "ok": true }
```

---

## 4. API de análise — porta 8082

Disponível com `hidra-node --dashboard`. **Agrega apenas métricas operacionais
do próprio nó; não regista conteúdo nem quem se liga a quê.**

### `GET /api/stats`

```json
{
  "total_circuits": 1482,
  "active_circuits": 12,
  "bytes_relayed": 8402934721,
  "uptime_seconds": 864000
}
```

### `GET /api/traffic`

```json
{
  "series": [
    { "t": 1758412800, "in_bytes": 84029, "out_bytes": 91882 }
  ]
}
```

### `GET /api/geo`

Distribuição agregada de pares por região, para dimensionamento da rede.

```json
{ "regions": [ { "code": "PT", "peers": 4 } ] }
```

---

## 5. Proxy SOCKS5 — porta 9050

SOCKS5 padrão (RFC 1928), sem autenticação, apenas em loopback.

```bash
curl --socks5-hostname 127.0.0.1:9050 https://example.com
```

> Use `--socks5-hostname`, **não** `--socks5`. A primeira forma resolve o DNS
> através do proxy; a segunda resolve localmente e **vaza o DNS**, revelando os
> domínios que visita ao seu fornecedor de internet.

Python:

```python
import requests

proxies = {
    "http":  "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}
r = requests.get("https://example.com", proxies=proxies, timeout=30)
```

> `socks5h://` — o `h` faz a resolução DNS passar pelo proxy. Sem ele, vaza.

Node.js:

```js
const { SocksProxyAgent } = require('socks-proxy-agent');
const agent = new SocksProxyAgent('socks5h://127.0.0.1:9050');
fetch('https://example.com', { agent });
```

---

## 6. Aplicações do browser — porta 8090

Servidas pelo processo do browser. Só respondem a pedidos com `Host` e `Origin`
próprios — proteção contra *DNS rebinding*.

| Caminho | Método | Descrição |
|---|---|---|
| `/` | GET | HidraChat |
| `/mail` | GET | HidraMail |
| `/forum` | GET | Fórum |
| `/search` | GET | HidraSearch |
| `/reviews` | GET | HidraReview |
| `/sites`, `/publish` | GET | Publicação |
| `/site?addr=` | GET | Visualizar site `.hidra` |
| `/prefs` | GET, POST | Preferências |
| `/search/api?q=&p=&lang=` | GET | Pesquisa (JSON) |

```bash
curl "http://127.0.0.1:8090/search/api?q=exemplo&p=1&lang=pt-PT"
```

```json
{
  "results": [
    { "title": "…", "url": "https://…", "snippet": "…", "engine": "duckduckgo" }
  ],
  "total": 10,
  "query": "exemplo",
  "elapsed_ms": 842
}
```

---

## 7. Códigos de estado

| Código | Significado |
|---|---|
| 200 | OK |
| 400 | Pedido inválido |
| 403 | Origem não confiável (proteção anti-rebinding) |
| 404 | Recurso não encontrado |
| 500 | Erro interno |
| 503 | Serviço indisponível (nó a arrancar) |

---

## 8. Estabilidade

A API está em **v1 e pode mudar**. Alterações incompatíveis serão anunciadas
no `CHANGELOG` com pelo menos uma versão menor de antecedência.

Para integrações, fixe a versão do `hidra-node` que testou.

---

## 9. Exemplo completo

Enviar correio pela HidraNet a partir de um script:

```python
#!/usr/bin/env python3
"""Envia um HidraMail através do nó local."""
import json
import urllib.request

NODE = "http://127.0.0.1:8080"


def api(path, method="GET", payload=None):
    data = json.dumps(payload).encode() if payload else None
    req = urllib.request.Request(
        f"{NODE}{path}",
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


me = api("/api/identity")
print("O meu endereço:", me["address"])

result = api("/api/send", "POST", {
    "to": "x9k2mqp4vz@hidra",
    "subject": "Teste via API",
    "body": "Enviado a partir de um script.",
})

print("Enviado" if result["ok"] else f"Falhou: {result['error']}")
```
