# Segurança da Landing Page — HidraNet

Este documento explica, com honestidade técnica, **o que foi blindado na página** e
**o que precisa ser feito na infraestrutura** (porque não dá para resolver dentro de um
arquivo HTML).

---

## ⚠️ Verdade técnica importante

Uma landing page é **um arquivo estático** servido para quem visita. Por isso:

| Pedido | Dá para fazer no HTML? | Onde se resolve de verdade |
|--------|------------------------|----------------------------|
| "Fechar todas as portas" | ❌ Não | No host/firewall. Em hosts gerenciados, **não existem portas suas** para abrir. |
| "Blindar contra DDoS" | ❌ Não | Na CDN/WAF (ex.: **Cloudflare**) na frente do site. |
| "Criptografar tudo" | ⚠️ Em trânsito, sim (HTTPS) | TLS/HTTPS do host. O conteúdo da página é **público por natureza**. |
| Anti-XSS / anti-clickjacking / hardening | ✅ Sim | Headers de segurança (este repositório já traz). |

Quem promete "blindei o HTML contra DDoS" está enganando. A proteção real é por **camadas**.

---

## 1. Portas

Em **GitHub Pages, Netlify, Vercel e Cloudflare Pages** você **não administra nenhum
servidor** — logo, **não há portas para você abrir ou fechar**. A plataforma expõe só:

- **443** (HTTPS)
- **80** (redireciona para 443)

Todo o resto já fica fechado por padrão. Ou seja: "fechar todas as portas" já é o estado
padrão desses hosts. Se um dia você rodar em **VPS próprio**, aí sim configure o firewall:

```bash
# Exemplo (UFW, Linux) — deixa só HTTPS e HTTP, fecha o resto
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp
sudo ufw enable
```

---

## 2. DDoS (a parte que realmente importa)

A defesa contra DDoS **não fica no site** — fica numa **CDN/WAF na frente dele**.

### Recomendado: Cloudflare (plano grátis já resolve a maioria)
1. Crie conta em cloudflare.com e adicione seu domínio.
2. Aponte o DNS do domínio para o Cloudflare (muda os nameservers no registrador).
3. Ative **proxy (nuvem laranja)** nos registros → isso **esconde o IP de origem**.
4. Ative:
   - **DDoS Protection** (L3/L4/L7) — já vem ligado.
   - **WAF** (Web Application Firewall) — regras contra ataques comuns.
   - **Rate Limiting** — limita requisições por IP.
   - **Bot Fight Mode** — barra bots.
   - **"Under Attack Mode"** — ligue durante um ataque ativo.
5. Bônus: o Cloudflare também **adiciona os headers de segurança** (via *Transform
   Rules → Response Headers*) e **força HTTPS**.

> GitHub Pages / Netlify / Vercel já têm proteção DDoS básica embutida (estão atrás de
> CDNs grandes). Para algo "blindado" de verdade, coloque **Cloudflare na frente**.

---

## 3. Criptografia / HTTPS

- **Em trânsito:** TLS/HTTPS é **automático e grátis** em GitHub Pages, Netlify, Vercel
  e Cloudflare. Tudo entre o visitante e o servidor já vai criptografado.
- **Forçar HTTPS:** o header `Strict-Transport-Security` (HSTS) e a diretiva
  `upgrade-insecure-requests` (ambos já configurados) impedem acesso por HTTP puro.
- **"Criptografar o conteúdo da página"** não se aplica: a landing é **marketing
  público**, feita para ser lida por qualquer um. Cifrar o HTML seria inútil (a chave
  teria que estar na própria página). A criptografia séria (Noise + Kyber, roteamento
  cebola) está **no app HidraNet**, que a página divulga — não na página.

---

## 4. Headers de segurança (já incluídos neste repositório)

Arquivos prontos para deploy:

- **`_headers`** → para **Netlify** e **Cloudflare Pages** (lido automaticamente).
- **`vercel.json`** → para **Vercel** (lido automaticamente).

Headers aplicados:

| Header | Protege contra |
|--------|----------------|
| `Strict-Transport-Security` | Downgrade para HTTP / sslstrip |
| `Content-Security-Policy` | XSS, injeção de script, recursos de terceiros |
| `X-Frame-Options: DENY` + `frame-ancestors 'none'` | Clickjacking (embutir seu site em iframe) |
| `X-Content-Type-Options: nosniff` | MIME sniffing |
| `Referrer-Policy: no-referrer` | Vazamento de para onde o usuário veio/vai |
| `Permissions-Policy` | Acesso indevido a câmera, microfone, localização, etc. |
| `Cross-Origin-Opener-Policy` | Ataques cross-origin (Spectre-like) |

### ⚠️ GitHub Pages NÃO suporta headers customizados
Se você publicar **direto no GitHub Pages**, os arquivos `_headers`/`vercel.json` são
**ignorados** (GitHub Pages não deixa configurar headers). Soluções:
- **Coloque Cloudflare na frente** e adicione os headers lá (recomendado — já ganha DDoS junto), **ou**
- Publique em **Netlify / Cloudflare Pages / Vercel**, que respeitam esses arquivos.

---

## 5. Hardening já aplicado no `index.html`

- `<meta name="referrer" content="no-referrer">` — não vaza o referrer.
- Todos os links externos com `rel="noopener noreferrer"` — evita `window.opener`
  hijacking e vazamento de referrer.
- Sem dependências externas além do Google Fonts.

---

## 6. Próximos passos opcionais (mais blindagem ainda)

1. **Auto-hospedar as fontes** (em vez do Google Fonts): elimina qualquer requisição a
   terceiros → mais privacidade e permite remover `fonts.googleapis.com`/`fonts.gstatic.com`
   da CSP. (Posso fazer isso se você quiser.)
2. **CSP estrita sem `'unsafe-inline'`**: mover o `<script>` e os `onerror` inline para um
   arquivo `.js` externo e usar hashes/nonces. Deixa a CSP nota A+.
3. **`security.txt`** (RFC 9116) em `/.well-known/security.txt` para canal de reporte de
   vulnerabilidades.
4. Testar tudo em https://securityheaders.com e https://observatory.mozilla.org após o deploy.
