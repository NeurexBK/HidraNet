# 03 — Produto e Tecnologia

**Regra deste documento:** só entra aqui o que está verificado no código do
repositório. O que é plano está na secção 5, marcado como plano. Um deck que
apresenta roadmap como produto existente não sobrevive à due diligence técnica.

---

## 1. O que existe hoje (verificado no repositório)

### 1.1 `hidra-node` — o motor, em Rust

~17.000 linhas de Rust (edição 2024).

> **Correção a uma versão anterior deste documento.** Estava aqui escrito que o
> motor "compila limpo, verificado". **Era falso**, e a verificação foi mal
> feita: confiou-se num código de saída em vez de se ler a saída. O que se
> passava, apurado depois:
>
> - `disable_core_dumps()` está sob `#[cfg(target_os = "linux")]` e usa
>   `libc::prctl`, mas `libc` não constava do `Cargo.toml`. **Em Linux o binário
>   não compilava.** Em Windows e macOS entra a variante `cfg(not(linux))`, que
>   é a razão pela qual passou despercebido — e pela qual o alvo `build:linux`
>   nunca poderia ter funcionado.
> - Os quatro ficheiros em `tests/` fazem `use hidra_node::…`, mas não existia
>   alvo de biblioteca. **Nunca compilaram nem correram.**
>
> Ambos corrigidos: `libc` declarado como dependência só de Linux, e `src/lib.rs`
> criado a expor a árvore de módulos que já existia em `src/`.
>
> **Estado atual, verificado lendo a saída:** `cargo build` e
> `cargo check --all-targets` a zero erros; **`cargo test --all` com 71 testes,
> todos a passar** (41 unitários + 30 de integração). `cargo clippy` continua a
> falhar no binário — 26 avisos estilísticos que o `#![deny(warnings)]` do
> `main.rs` transforma em erros; não são defeitos funcionais e estão listados
> como dívida técnica.

| Componente | Estado | Notas |
|---|---|---|
| Encaminhamento em cebola (onion routing) | Implementado | Construção de circuitos, células, camadas |
| Criptografia pós-quântica | Implementado | **Kyber1024** (`pqc_kyber`) |
| Criptografia clássica | Implementado | X25519, Ed25519, ChaCha20-Poly1305, AES-GCM, BLAKE3, Argon2 |
| DHT (Kademlia) | Implementado | k-buckets, descoberta, bootstrap |
| Proxy SOCKS5 | Implementado | Gateway para o browser |
| Relay / registry / router | Implementado | |
| Sites `.hidra` (SevenNine) | Implementado | Construtor e alojamento de sites ocultos |
| HidraChat / HidraMail (motor) | Implementado | |
| Testes de integração | **A passar** | 30 testes: `onion_routing`, `dht_discovery`, `key_agreement`, `integration` |

**Diferenciador técnico real:** a combinação de encaminhamento em cebola com
**Kyber1024** em produção. O Tor está a caminhar para pós-quântico mas a
HidraNet já o tem no núcleo. Isto é material para uma candidatura ao NGI Zero
Entrust (fundo de privacidade e confiança) e é o argumento técnico mais forte
que temos.

**Dívida técnica a declarar (honestidade em due diligence):** `main.rs` tem
~9.600 linhas com todos os módulos embutidos, e existe em paralelo uma árvore
`src/` com os mesmos módulos em ficheiros separados. Um CTO de fundo vai ver
isto em cinco minutos. É melhor levá-lo já resolvido, ou declarado como item
conhecido com data. Ver [roadmap](08-roadmap.md), T1.

### 1.2 `hidra-browser` — o browser, em Electron

~7.800 linhas. Empacota o Tor e adiciona camadas de proteção:

| Proteção | Estado | Notas |
|---|---|---|
| Tor embutido, com bootstrap visível | Implementado | Gestor próprio, portas 9052/9053, controlo por cookie |
| Verificação independente do IP de saída | Implementado | Consulta `check.torproject.org` — o browser **confirma** o anonimato em vez de o afirmar |
| Nova identidade (`SIGNAL NEWNYM`) | Implementado | Com fecho de ligações abertas e reconfirmação do IP |
| Isolamento por separador | Implementado | Partição de sessão própria, em memória, apagada ao fechar |
| Fingerprint aleatório por separador | Implementado | Canvas, WebGL, áudio, fuso horário, ecrã — perfis internamente consistentes |
| Remoção de client hints (`Sec-CH-UA-*`) | Implementado | |
| Remoção de referer entre origens | Implementado | Mantém o same-origin, que é funcional |
| Proteção contra DNS rebinding no servidor de apps | Implementado | Verificação de `Host` e `Origin` |
| **Kill switch de rede** | **Implementado** | Ver 1.4 |

### 1.3 Aplicações

Servidas pelo próprio browser em `127.0.0.1:8090` (não dependem do motor estar a
correr — decisão acertada, reduz pontos de falha):

- **HidraSearch** — meta-pesquisa (DuckDuckGo + SearXNG), 109 idiomas, pedidos
  encaminhados pelo Tor.
- **HidraChat** — E2E no cliente, via relay.
- **HidraMail** — correio da rede.
- **Fórum**.
- **HidraReview** — reviews de estabelecimentos, endereço `.hidra` por
  estabelecimento para cartões NFC, aviso ao dono por HidraMail, painel do dono.
  **É o produto comercial.** Ver [04](04-modelo-de-negocio.md).
- **SevenNine** — publicação de sites `.hidra`.

### 1.4 Lacuna conhecida e em correção: janela de fuga de IP

Declarada aqui por honestidade e porque a correção está em curso.

No arranque, o browser cria e mostra o primeiro separador enquanto o Tor ainda
está a fazer bootstrap (20–40 s). Durante essa janela o tráfego sai direto ou
pelo motor local — ou seja, **pelo IP real do utilizador** — enquanto o painel
mostra "a iniciar o Tor". O mesmo acontecia se o Tor falhasse ou morresse a
meio da sessão.

**Corrigido.** O *kill switch* (`src/main/network-lock.js`) arranca fechado e só
abre quando o Tor atinge 100% de bootstrap e as regras estão aplicadas a todas as
sessões — a sessão por omissão e a partição de cada separador. Volta a fechar ao
desconectar e quando o Tor morre sem lhe ser pedido. Tudo o que não seja loopback,
`file://`, `data:` ou `hidra://` é bloqueado até lá, e uma navegação bloqueada
mostra ao utilizador o motivo em vez de um erro do Chromium.

Verificado com a aplicação a correr e o Tor indisponível: a API de pesquisa
responde `"A pesquisa está bloqueada até o Tor estar pronto"`, e as aplicações
locais continuam a servir.

**Porque é que isto está no deck:** um investidor com assessoria técnica vai
procurar exatamente isto. Apresentar a falha já corrigida, com o raciocínio,
demonstra maturidade de engenharia. Escondê-la e ser apanhado em due diligence
mata a ronda.

### 1.5 Distribuição

- Landing page + PWA (`landing/`), downloads gratuitos.
- Scripts de empacotamento para Windows, Linux e macOS.
- Painel de operação (`hidra-monitor/`) com beacon de nó.
- Licença **MIT** — relevante: é pré-requisito de elegibilidade para o NGI Zero.

---

## 2. Arquitetura, em uma frase para o deck

> Um motor em Rust que faz encaminhamento em cebola com criptografia
> pós-quântica, um browser que embrulha o Tor e aleatoriza a impressão digital
> por separador, e um conjunto de aplicações que dá à rede uma razão para
> existir — sendo a primeira delas um produto de reputação para comércio local.

---

## 3. O que nos diferencia tecnicamente

1. **Pós-quântico já em produção** (Kyber1024) — o Tor ainda não.
2. **Anonimato verificado, não afirmado** — o browser confere o IP de saída
   contra o verificador do próprio Tor Project e, se não conseguir confirmar,
   **diz que não conseguiu** em vez de mentir ao utilizador. É uma escolha de
   produto rara e defensável.
3. **Isolamento por separador com fingerprint consistente** — cada separador é
   um utilizador diferente e internamente coerente (um UA Windows não vem com
   GPU da Apple).
4. **Aplicações integradas** — Tor Browser é só um browser. A HidraNet traz
   pesquisa, correio, chat, fórum e reviews na rede.

---

## 4. O que *não* nos diferencia (e é preciso dizer)

- **O anonimato em si é do Tor**, não nosso. A rede de voluntários que dá o
  anonimato real é a do Tor Project. O motor próprio, com os relays apontados a
  `127.0.0.1` na configuração atual, cifra em camadas mas sai da própria máquina
  do utilizador — não muda o IP. O código já documenta isto corretamente. **Não
  se pode dizer a um investidor que temos rede própria de anonimato em
  funcionamento.** Temos o protocolo; não temos ainda os voluntários.
- **Electron** — um browser em Electron tem um teto de desempenho e de superfície
  de ataque face a um fork do Firefox (Tor Browser, Mullvad Browser). É uma
  escolha defensável para chegar depressa ao mercado; é uma dívida a assumir.

---

## 5. Plano (ainda não construído)

| Item | Porquê | Quando |
|---|---|---|
| Rede de relays real, com voluntários | Sem isto, "rede HidraNet" é protocolo, não rede | Ver roadmap |
| Separar `main.rs` em módulos | Dívida técnica visível em due diligence | T1 |
| HidraReview como SaaS multi-tenant com faturação | É a linha de receita | T1–T2 |
| Registo de domínios `.hidra` | Linha de receita recorrente | T2 |
| Auditoria de segurança externa | Exigência de credibilidade; o NGI Zero oferece-a aos financiados | T2–T3 |
| Apps móveis | Onde está o utilizador de reviews | T3–T4 |

---

*Verificações feitas em 21 de setembro de 2026 contra o commit `da05f65` do
repositório NeurexBK/HidraNet.*
