# Guia de Instalação — HidraNet

Cobre a instalação do **HidraNet Browser** e a operação de um **nó da rede**.

---

## Parte I — HidraNet Browser

### Requisitos

| Sistema | Versão mínima |
|---|---|
| Windows | 10 (64 bits) |
| macOS | 11 Big Sur (Intel e Apple Silicon) |
| Linux | distribuição de 64 bits com glibc 2.31+ |

Recomendado: 4 GB de RAM, 500 MB de disco, ligação à internet sem filtragem de
portas de saída.

### Instalação a partir do site

1. Descarregue de https://hidranet.org o pacote do seu sistema.
2. **Verifique a soma de verificação** antes de executar:

```bash
# Linux / macOS
sha256sum HidraNet-Browser-1.0.0-linux-x64.zip
# Windows (PowerShell)
Get-FileHash .\HidraNet-Browser-1.0.0-win-x64.zip -Algorithm SHA256
```

Compare com o valor publicado em `SHA256SUMS` no site. **Se não corresponder,
não execute o ficheiro.** Um pacote alterado num browser de privacidade é o pior
cenário possível.

3. Extraia e execute:

| Sistema | Executável |
|---|---|
| Windows | `HidraNet Browser.exe` |
| macOS | `HidraNet Browser.app` |
| Linux | `./hidranet-browser` |

### Primeira execução

Ao abrir, o browser inicia automaticamente o Tor embutido. O painel mostra o
progresso de *bootstrap* (tipicamente 20 a 40 segundos).

Quando concluir, o painel indica o **IP de saída verificado**. Se indicar que
não conseguiu confirmar o IP, o browser está ligado mas a verificação
independente falhou — não trate a sessão como anónima até confirmar.

### macOS — primeira abertura

O pacote **não é assinado nem notarizado pela Apple**. Isto tem duas
consequências, e a primeira é a que engana mais gente.

**No Apple Silicon (M1–M4), o macOS diz que a app está danificada.**

```
"HidraNet.app is damaged and can't be opened. You should move it to the Trash."
```

O download não está corrompido. O que acontece é que o núcleo do macOS recusa
carregar código arm64 sem assinatura válida, e a mensagem que a Apple escolheu
mostrar é "danificado". É indistinguível, para quem lê, de um ficheiro
corrompido — e é a razão pela qual utilizadores reportam isto como "não
consegui descarregar".

**Solução — no Terminal, na pasta extraída:**

```bash
xattr -cr HidraNet.app
codesign --force --sign - \
  HidraNet.app/Contents/Resources/bin/tor/tor
codesign --force --deep --sign - HidraNet.app
open HidraNet.app
```

As ordens `codesign` são as que resolvem: aplicam assinaturas *ad-hoc* locais,
que é o que permite ao macOS carregar o código. Limpar a quarentena, por si só,
**não basta** em Apple Silicon.

**O Tor tem de ser assinado à parte, e antes da app.** Vive em
`Contents/Resources/bin/tor/tor`, e o `--deep` não chega lá — só desce para os
locais padrão de código aninhado (`Frameworks`, `PlugIns`, `XPCServices`,
`Helpers`). Se assinar apenas o bundle, a app abre, mas nada liga: o núcleo mata
o Tor sem assinatura no instante em que o browser o lança, e o painel reporta
`tor exited with code null`.

Se o `codesign` não existir: `xcode-select --install`.

O ZIP inclui `Start HidraNet.command`, que executa todos os passos, e
`README-macOS.txt` com o procedimento completo.

**Se o macOS continuar a bloquear:**

Em **macOS 15 (Sequoia) e posterior**, o truque de clique direito → Abrir
**deixou de funcionar** — a Apple removeu esse caminho. Em vez disso:

1. Tente abrir a app uma vez (vai ser bloqueada)
2. **Ajustes do Sistema → Privacidade e Segurança**
3. Desça até à linha sobre a HidraNet ter sido bloqueada
4. **Abrir Mesmo Assim**, e confirme com palavra-passe ou Touch ID

Em macOS 14 e anteriores, clique direito na app → Abrir → Abrir também funciona.

> **Nota para a equipa:** isto resolve-se definitivamente com uma conta Apple
> Developer paga e notarização. Até lá, estas instruções são a alternativa
> honesta — e devem estar visíveis no site, não escondidas num README dentro
> do ZIP.

### Compilar a partir do código

```bash
git clone https://github.com/NeurexBK/HidraNet.git
cd HidraNet/hidra-browser
npm install
npm run fetch-tor     # descarrega o binário do Tor para a sua plataforma
npm start
```

Pacotes de distribuição:

```bash
npm run build:win        # Windows x64
npm run build:linux      # Linux x64
npm run build:mac        # macOS (arm64 + x64)
npm run pack             # portátil, com Tor incluído
```

---

## Parte II — Operar um nó

Operar um nó contribui capacidade para a rede. É a forma mais direta de ajudar
o projeto.

### Requisitos

| Recurso | Mínimo | Recomendado |
|---|---|---|
| CPU | 1 núcleo | 2 núcleos |
| RAM | 512 MB | 2 GB |
| Disco | 1 GB | 5 GB |
| Largura de banda | 5 Mbps simétricos | 50 Mbps+ |
| Disponibilidade | — | permanente |

### Compilar

Requer Rust 1.80 ou superior (edição 2024).

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

git clone https://github.com/NeurexBK/HidraNet.git
cd HidraNet/hidra-node
cargo build --release
```

O binário fica em `target/release/hidra-node`.

### Configuração

Crie `config.toml` junto ao binário:

```toml
[node]
name = "o-meu-no"

[network]
listen_addr = "0.0.0.0"
listen_port = 9150

[logging]
level = "info"        # use "info" em produção, não "debug"
format = "json"       # "json" para recolha automatizada; "pretty" para consola

[paths]
keys_dir = "keys"

[dht]
port = 7000
enabled = true
bootstrap_nodes = []  # endereços de arranque da rede

[proxy]
listen_addr = "127.0.0.1"   # NUNCA 0.0.0.0 — ver aviso abaixo
port = 9050

[hidden_service]
enabled = false
local_port = 8080
```

> ⚠️ **`proxy.listen_addr` deve ser sempre `127.0.0.1`.**
> Se o expuser em `0.0.0.0`, qualquer pessoa na rede passa a poder usar a sua
> máquina como proxy aberto, e o tráfego de terceiros sai com o seu IP e sob a
> sua responsabilidade.

### Chaves

Na primeira execução, o nó gera as suas chaves em `keys/`.

```bash
chmod 700 keys/
```

**Faça cópia de segurança de `keys/` e guarde-a cifrada.** A identidade do nó na
rede é essa pasta. Perdê-la significa perder a identidade; expô-la significa
perder o controlo dela.

### Modos de execução

```bash
./hidra-node                          # modo relay (predefinido)
./hidra-node --server                 # modo servidor completo
./hidra-node --proxy                  # gateway SOCKS5 para o browser
./hidra-node --sevennine              # construtor de sites .hidra (porta 8084)
./hidra-node --dashboard              # painel de análise (porta 8082)
./hidra-node --apps                   # HidraMail (8080) + HidraChat (8081)
./hidra-node --config /caminho/config.toml
```

Diagnóstico:

```bash
./hidra-node --dht-discover           # testa a descoberta na DHT
./hidra-node --connect 1.2.3.4:9150   # testa ligação a um par
```

### Portas

| Porta | Serviço | Exposição |
|---|---|---|
| 9150 | Rede entre nós | **Pública** |
| 7000 | DHT | **Pública** |
| 9050 | Proxy SOCKS5 | Apenas loopback |
| 9051 | API do nó | Apenas loopback |
| 8084 | SevenNine | Apenas loopback |
| 8082 | Painel | Apenas loopback |

Firewall (Linux):

```bash
sudo ufw allow 9150/tcp
sudo ufw allow 7000/udp
sudo ufw enable
```

### Executar como serviço (systemd)

`/etc/systemd/system/hidra-node.service`:

```ini
[Unit]
Description=HidraNet Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=hidra
Group=hidra
WorkingDirectory=/opt/hidranet
ExecStart=/opt/hidranet/hidra-node --config /opt/hidranet/config.toml
Restart=on-failure
RestartSec=10

# Endurecimento
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/hidranet
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -s /usr/sbin/nologin hidra
sudo chown -R hidra:hidra /opt/hidranet
sudo systemctl daemon-reload
sudo systemctl enable --now hidra-node
sudo journalctl -u hidra-node -f
```

### Docker

```dockerfile
FROM rust:1.80 AS build
WORKDIR /src
COPY hidra-node .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -r -u 10001 hidra
COPY --from=build /src/target/release/hidra-node /usr/local/bin/
USER hidra
WORKDIR /data
EXPOSE 9150 7000
ENTRYPOINT ["hidra-node"]
```

```bash
docker build -t hidranet/node .
docker run -d --name hidra \
  -p 9150:9150 -p 7000:7000/udp \
  -v hidra-keys:/data/keys \
  -v $(pwd)/config.toml:/data/config.toml:ro \
  --restart unless-stopped \
  hidranet/node
```

---

## Resolução de problemas

| Sintoma | Causa provável | Solução |
|---|---|---|
| Tor não passa dos 0% | Rede bloqueia o Tor | Configurar *bridge*; ver Guia do Utilizador |
| "porta 9052 já ocupada" | Instância anterior ainda a terminar | Aguardar 10 s; ou fechar a outra janela |
| "porta 8090 ocupada" | Segunda cópia do browser aberta | Fechar a outra janela e reiniciar |
| Nó não encontra pares | `bootstrap_nodes` vazio | Preencher com nós de arranque |
| `binário do Tor não encontrado` | Tor não descarregado | `npm run fetch-tor` |
| Nó não recebe ligações | Firewall ou NAT | Abrir 9150/tcp e 7000/udp; verificar encaminhamento |

Suporte: ver o Guia de Contribuição para canais e para como reportar um
problema de forma útil.
