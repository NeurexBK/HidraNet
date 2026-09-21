# HidraNet — Whitepaper Técnico

**Versão 1.0 · Setembro 2026 · Lisboa, Portugal**
Autores: João Brandão, Leonardo Mello
Licença do software: MIT · Repositório: NeurexBK/HidraNet

---

## Abstract (EN)

HidraNet is an open-source overlay network combining onion routing with
post-quantum key encapsulation (CRYSTALS-Kyber-1024), a Kademlia DHT for peer
and service discovery, and a suite of end-to-end encrypted applications:
messaging, mail, forum, search and a hidden-site publisher. The reference
implementation consists of a Rust network engine (`hidra-node`) and a desktop
browser that bundles Tor as its exit layer while the HidraNet protocol matures
toward a volunteer-operated relay population. This paper describes the
architecture, the cryptographic constructions actually implemented, the threat
model, and — explicitly — the current limitations and the hardening roadmap.

We state one thing plainly, because a whitepaper that overstates is worse than
no whitepaper: **today, exit anonymity is provided by the Tor network.** The
HidraNet protocol layer is implemented and tested, but its relay population is
not yet large enough to provide anonymity on its own. Section 9 sets out how we
get there.

---

## Resumo (PT)

A HidraNet é uma rede sobreposta (*overlay network*) de código aberto que
combina encaminhamento em cebola com encapsulamento de chaves pós-quântico
(CRYSTALS-Kyber-1024), uma DHT Kademlia para descoberta de pares e serviços, e
um conjunto de aplicações cifradas de ponta a ponta.

Este documento descreve a arquitetura, as construções criptográficas
efetivamente implementadas, o modelo de ameaça e — explicitamente — as
limitações atuais e o plano de robustecimento.

---

## 1. Motivação

A internet atual tem três propriedades que não escolhemos: a comunicação é
observável por intermediários, a identidade é ligada ao endereço de rede, e o
conteúdo vive em infraestrutura de terceiros que o pode remover.

Ferramentas existentes resolvem partes disto. O Tor resolve o anonimato de
transporte. O Signal resolve a confidencialidade de mensagens. Nenhuma resolve
o conjunto, e nenhuma está preparada para o dia em que a criptografia de curva
elíptica deixar de ser suficiente.

A HidraNet propõe-se a três coisas:

1. **Anonimato de transporte** por encaminhamento em cebola.
2. **Confidencialidade resistente a computação quântica**, já hoje, não quando
   for tarde.
3. **Aplicações utilizáveis** sobre essa base — porque uma rede sem razão para
   ser usada não tem utilizadores, e uma rede de anonimato sem utilizadores não
   oferece anonimato a ninguém.

---

## 2. Os seis pilares

### Pilar 1 — Encaminhamento em cebola (*onion routing*)

O tráfego atravessa um circuito de múltiplos saltos. Cada salto remove uma
camada de cifra e conhece apenas o salto anterior e o seguinte. Nenhum nó
isolado conhece simultaneamente a origem e o destino.

Implementação: módulos `onion/` do `hidra-node` — construção de circuitos
(`builder`), células de tamanho fixo (`cell`), gestão de camadas (`layer`) e
estado de circuito (`circuit`).

### Pilar 2 — Criptografia pós-quântica

O encapsulamento de chaves usa **CRYSTALS-Kyber-1024** (`pqc_kyber`), o nível
de segurança mais alto da família Kyber, padronizada pelo NIST como ML-KEM.

Isto responde ao ataque *harvest now, decrypt later*: tráfego capturado hoje e
guardado não fica legível quando existir um computador quântico
criptograficamente relevante. É a diferença entre confidencialidade hoje e
confidencialidade duradoura.

### Pilar 3 — DHT Kademlia

Descoberta de pares e resolução de serviços sem servidor central. Implementação
em `p2p/dht/` — k-buckets, roteamento iterativo, bootstrap.

### Pilar 4 — Serviços ocultos (`.hidra`)

Um serviço `.hidra` é alcançável sem revelar o endereço IP de quem o aloja. O
endereço deriva da chave pública do serviço, o que o torna **auto-certificável**:
o nome *é* a chave, e não há autoridade de certificação a confiar.

O SevenNine é o construtor e alojador destes sites.

### Pilar 5 — Cifra de ponta a ponta nas aplicações

Cada aplicação cifra no cliente. A rede transporta ciphertext e não tem meio de
o ler, mesmo que queira. Detalhe criptográfico na secção 4.

### Pilar 6 — Isolamento e resistência a *fingerprinting*

O browser atribui a cada separador uma sessão isolada e um perfil de impressão
digital internamente consistente. Detalhe na secção 5.

---

## 3. Arquitetura

```
┌──────────────────────────────────────────────────────────────┐
│                    APLICAÇÕES (cliente)                      │
│  HidraChat · HidraMail · Fórum · HidraSearch · HidraReview   │
│  SevenNine (sites .hidra)                                    │
│  — cifram no cliente; a rede vê apenas ciphertext —          │
├──────────────────────────────────────────────────────────────┤
│                    HIDRA BROWSER (Electron)                  │
│  Isolamento por separador · anti-fingerprint · gestor Tor    │
├──────────────────────────────────────────────────────────────┤
│                    HIDRA-NODE (Rust)                         │
│  ┌────────────┬───────────┬──────────┬────────────────────┐  │
│  │ onion/     │ p2p/dht/  │ relay/   │ proxy/  (SOCKS5)   │  │
│  │ circuitos  │ Kademlia  │ router   │ gateway do browser │  │
│  ├────────────┴───────────┴──────────┴────────────────────┤  │
│  │ crypto/ — Kyber1024 · X25519 · Ed25519                 │  │
│  │          ChaCha20-Poly1305 · AES-GCM · BLAKE3 · Argon2 │  │
│  └────────────────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────┤
│           CAMADA DE SAÍDA — hoje: rede Tor (ver §9)          │
└──────────────────────────────────────────────────────────────┘
```

### 3.1 Componentes

| Componente | Linguagem | Função |
|---|---|---|
| `hidra-node` | Rust (edição 2024) | Motor: circuitos, DHT, relay, SOCKS5 |
| `hidra-browser` | JavaScript / Electron | Interface, isolamento, gestão do Tor |
| Aplicações | JavaScript (Web Crypto) | Cifra no cliente |
| SevenNine | Rust (módulo do motor) | Publicação de sites `.hidra` |

---

## 4. Construções criptográficas

Esta secção descreve o que está implementado, não o que está planeado.

### 4.1 Primitivas do motor

| Função | Algoritmo |
|---|---|
| Encapsulamento de chaves pós-quântico | CRYSTALS-Kyber-1024 |
| Acordo de chaves clássico | X25519 |
| Assinatura | Ed25519 |
| Cifra simétrica autenticada | ChaCha20-Poly1305, AES-256-GCM |
| Função de resumo | BLAKE3, SHA-256 |
| Derivação a partir de palavra-passe | Argon2 |

**Abordagem híbrida.** O acordo de chaves combina X25519 com Kyber-1024. A
sessão só é comprometida se *ambos* forem quebrados. É a recomendação corrente
para transição pós-quântica: não se abandona o que está bem estudado, acrescenta-se
resistência quântica por cima.

### 4.2 HidraMail — esquema de cifra

O HidraMail implementa um esquema ECIES sobre Web Crypto:

1. **Identidade.** Par de chaves ECDH P-256 gerado no dispositivo. A chave
   privada nunca sai do cliente.
2. **Endereço auto-certificável.**
   `endereço = base32(SHA-256(chave_pública)[0..10]) + "@hidra"`
   O endereço deriva da chave, portanto não é possível reclamar um endereço sem
   ter a chave correspondente.
3. **Cifra.** Para cada mensagem gera-se um par ECDH **efémero**. Deriva-se um
   segredo partilhado com a chave pública do destinatário, importa-se como chave
   AES-256-GCM, e cifra-se com IV de 96 bits.
   Formato em trânsito: `chave_pública_efémera ‖ IV ‖ ciphertext`
4. **Verificação anti-substituição.** Antes de enviar, o cliente recalcula o
   endereço a partir da chave pública obtida do diretório e compara-o com o
   endereço de destino. Se não corresponder, o envio é recusado. Isto neutraliza
   a substituição de chave do destinatário por um diretório hostil.

**Propriedade obtida:** confidencialidade e sigilo persistente parcial (a chave
efémera do remetente não é guardada).

**Limitação declarada:** o campo `from` é uma afirmação não assinada dentro do
ciphertext. O destinatário sabe que a mensagem foi cifrada para si, mas não pode
provar quem a enviou. **A autenticação do remetente por assinatura está no plano
de robustecimento (§9) e não deve ser assumida hoje.**

### 4.3 HidraChat — esquema de sala

Salas cifradas com chave derivada de palavra-passe partilhada: PBKDF2-SHA-256 →
AES-256-GCM. O identificador de tópico deriva separadamente da mesma
palavra-passe, de modo que o transporte não revela o nome da sala.

**Limitação declarada:** os parâmetros de derivação atuais estão abaixo da
orientação corrente. O reforço para Argon2id com sal por sala consta de §9.

### 4.4 Sites `.hidra`

O endereço de um serviço deriva da sua chave pública, em base32. Como no
HidraMail, o nome é a chave: não há autoridade de certificação, e a resolução é
verificável pelo próprio cliente.

---

## 5. Modelo de ameaça

Um modelo de ameaça que não diz contra o que **não** protege é publicidade, não
engenharia.

### 5.1 Protegemos contra

| Adversário | Proteção |
|---|---|
| Observador da rede local (ISP, Wi-Fi público) | Vê tráfego cifrado para um nó de entrada; não vê destino nem conteúdo |
| Site visitado | Vê o IP do nó de saída, não o do utilizador; impressão digital aleatorizada por separador |
| Nó intermédio isolado | Conhece apenas o salto anterior e o seguinte |
| Operador do transporte de mensagens | Transporta ciphertext; não tem a chave |
| Rastreamento entre separadores | Sessões isoladas, armazenamento separado, apagado ao fechar |
| Captura de tráfego para decifra futura | Kyber-1024 resiste a criptanálise quântica |

### 5.2 **Não** protegemos contra

Declarado explicitamente:

| Ameaça | Porquê |
|---|---|
| Adversário global que observa toda a rede | Correlação de tráfego ponta a ponta derrota qualquer rede de latência baixa, incluindo o Tor |
| Comprometimento do dispositivo do utilizador | Se o endpoint está comprometido, a cifra é irrelevante |
| Erro operacional do utilizador | Iniciar sessão numa conta pessoal desfaz o anonimato |
| Análise de metadados de volume e temporização | Mitigação parcial (células de tamanho fixo); não eliminada |
| Conteúdo que o próprio utilizador publica | A rede não pode desanonimizar o que a pessoa revela |

### 5.3 Divulgação de limitações conhecidas

Mantemos um registo público de limitações conhecidas e do respetivo estado de
correção. A ausência de tal registo numa ferramenta de segurança significa que
ninguém está a procurar, não que não haja nada a encontrar.

---

## 6. Resistência a *fingerprinting*

Cada separador recebe um perfil coerente: sistema operativo, *user agent*, GPU,
resolução, fuso horário e idioma são escolhidos **em conjunto**, não
independentemente. Um *user agent* de Windows com GPU da Apple é um sinal mais
forte do que não mascarar nada.

Medidas implementadas:

- Ruído determinístico em canvas (estável por pixel: duas leituras do mesmo
  canvas devolvem os mesmos bytes, senão a aleatorização seria ela própria
  detetável)
- Mascaramento de `UNMASKED_VENDOR_WEBGL` / `UNMASKED_RENDERER_WEBGL`
- Fuso horário coerente entre `Intl.DateTimeFormat` e `Date.getTimezoneOffset`
- Ruído em AudioContext
- Remoção de cabeçalhos `Sec-CH-UA-*` e `X-Client-Data`
- Remoção do `Referer` entre origens, mantendo o de mesma origem (que é
  funcional: proteções CSRF dependem dele)

---

## 7. Aplicações

| Aplicação | Descrição |
|---|---|
| **HidraChat** | Salas cifradas ponta a ponta, chave derivada de palavra-passe partilhada |
| **HidraMail** | Correio com endereços `@hidra` auto-certificáveis, cifra ECIES |
| **Fórum** | Discussão pública na rede |
| **HidraSearch** | Meta-pesquisa (DuckDuckGo, SearXNG) encaminhada pela rede; sem registo de consultas |
| **SevenNine** | Construtor e alojador de sites `.hidra` |
| **HidraReview** | Avaliações de estabelecimentos com endereço `.hidra` próprio |

---

## 8. Estado da implementação

**Implementado e testado:**
- Motor em Rust, ~17 000 linhas, compilação limpa
- Circuitos em cebola, DHT Kademlia, relay, proxy SOCKS5
- Kyber-1024, X25519, Ed25519, ChaCha20-Poly1305, AES-GCM, BLAKE3, Argon2
- Testes de integração: `onion_routing`, `dht_discovery`, `key_agreement`
- Browser com Tor embutido, isolamento por separador, anti-fingerprint
- Seis aplicações funcionais

**Camada de saída.** O anonimato de saída é hoje fornecido pela rede Tor,
embutida no browser. O protocolo HidraNet está implementado e testado, mas uma
rede de anonimato é feita de duas coisas: protocolo e população de relays. Temos
a primeira; a segunda está em construção (§9).

O browser verifica o IP de saída contra o verificador do Tor Project e, quando
**não** consegue confirmar, informa o utilizador de que não confirmou — em vez
de afirmar um anonimato não verificado.

---

## 9. Plano de robustecimento

Público, com prazos, porque a credibilidade de um projeto de segurança mede-se
pelo que promete corrigir e cumpre.

| # | Item | Prioridade |
|---|---|---|
| 1 | *Kill switch* de rede: bloquear tráfego não-loopback até o Tor estar pronto | Crítica |
| 2 | Bibliotecas de terceiros servidas localmente, com integridade verificada | Crítica |
| 3 | Cifra em repouso do material de chave no dispositivo | Crítica |
| 4 | Assinatura do remetente no HidraMail (§4.2) | Alta |
| 5 | WebRTC bloqueado ao nível da rede, não só em JavaScript | Alta |
| 6 | Transporte de mensagens em infraestrutura própria | Alta |
| 7 | Injeção do perfil no arranque do documento, em todos os quadros | Alta |
| 8 | Argon2id com sal por sala no HidraChat (§4.3) | Média |
| 9 | Programa de relays de voluntários | Média |
| 10 | **Auditoria de segurança externa independente**, com publicação do relatório | Alta |

O item 10 é condição para divulgação pública ampla do browser. Não anunciamos
uma ferramenta de privacidade a um público alargado antes de alguém de fora a
ter tentado partir.

---

## 10. Licenciamento e governança

Software sob licença **MIT**. O protocolo é um bem comum: qualquer pessoa pode
implementar, auditar, bifurcar e operar nós.

A HidraNet, Lda desenvolve software e presta serviços. **A empresa não opera
nós de saída.** A rede é operada por voluntários, como o Tor. É uma separação
deliberada, descrita no Guia de Governança.

---

## 11. Referências

- NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
- Dingledine, Mathewson, Syverson — *Tor: The Second-Generation Onion Router*
- Maymounkov, Mazières — *Kademlia: A Peer-to-peer Information System*
- RFC 7748 — Elliptic Curves for Security (X25519)
- RFC 8032 — EdDSA (Ed25519)
- RFC 8439 — ChaCha20 and Poly1305
- RFC 9106 — Argon2

---

*Documento vivo. Correções e contribuições: ver Guia de Contribuição.*
