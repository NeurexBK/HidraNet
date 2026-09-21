# 02 — Análise de Mercado

**Data da pesquisa:** Setembro 2026. Todos os números têm fonte no fim do documento.
Onde as fontes divergem, está indicado o intervalo em vez de um número único — um
TAM apresentado com falsa precisão é a forma mais rápida de perder credibilidade
numa reunião de investimento.

---

## 1. O mercado de privacidade em 2026

### 1.1 Dimensão

O proxy mais próximo para o mercado endereçável da HidraNet é o mercado de VPN,
porque é onde está a disposição a pagar por anonimato de rede:

| Fonte | Mercado VPN 2026 | CAGR |
|---|---|---|
| The Business Research Company | 86,02 mil M$ (de 71,25 mil M$ em 2025) | 20,7% |
| Precedence / IMARC | 83,16 mil M$ | — |
| Outras estimativas | 108,57 mil M$ | — |

**Intervalo honesto: 83–108 mil M$ em 2026**, com projeção de 182 mil M$ em 2030
(CAGR ~20,6%). A dispersão entre fontes (~30%) reflete definições diferentes de
mercado — umas incluem VPN empresarial, outras só consumo.

> **Como apresentar isto a um VC:** nunca dizer "o nosso mercado vale 100 mil
> milhões". Dizer "o mercado de VPN de consumo, o nosso proxy mais próximo de
> disposição a pagar, está entre 83 e 108 mil M$ e cresce a ~20% ao ano; o nosso
> SAM real está no ponto 1.4".

### 1.2 Financiamento de risco no setor

O capital existe e está a crescer:

- Cibersegurança e privacidade captaram **10,6 mil M$** em 2026 (todas as fases).
- Só no **Q2 2026**: 4,4 mil M$ entre seed e growth.
- 2025 fechou com **~14 mil M$ em 392 rondas** — subida de **47%** face aos
  9,5 mil M$ de 2024.
- Na Europa, pre-seed situa-se tipicamente em **500 k€–3 M€** e seed em
  **1–5 M€**.

**Leitura:** há capital disponível, mas a fasquia subiu com ele. Em 2026 um seed
europeu de 1–5 M€ em privacidade exige tração demonstrável, não uma demo.

### 1.3 A procura estrutural: o contexto regulatório é o nosso vento de cauda

O **Chat Control** (regulamento CSAR da UE, que obrigaria a varrimento do lado do
cliente antes da cifragem, contornando na prática o E2E) foi **rejeitado a 26 de
março de 2026, por um voto**, e devolvido ao Conselho da UE. Não está morto nem
em vigor.

Isto é relevante para a HidraNet de duas maneiras opostas, e ambas têm de estar
no deck:

- **A favor:** cada ciclo de Chat Control produz um pico mensurável de adoção de
  ferramentas de privacidade. É procura gerada pelo próprio legislador.
- **Contra:** se passar numa forma que abranja "serviços de comunicação
  interpessoal independentes do número", o HidraChat e o HidraMail ficam
  potencialmente no âmbito. Ver [documento 10](10-risco-legal-regulatorio.md).

Nota adicional: já há sinais de risco de **proibição de facto** para fornecedores
sem registos ("no-logs") com base de clientes significativa na UE.

### 1.4 TAM / SAM / SOM

Construído de baixo para cima, não de cima para baixo. Cada linha tem de ser
defensável.

**TAM — Total Addressable Market**
Mercado global de privacidade de consumo e reputação local onde a HidraNet tem
produto: 83–108 mil M$ (VPN/privacidade) + o mercado de reputação e reviews
locais. Número de vaidade; serve só para enquadrar.

**SAM — Serviceable Addressable Market**
O que conseguimos servir com os produtos que existem hoje, em Portugal, Brasil e
UE lusófona:
- ~2–2,5 milhões de utilizadores diários da rede Tor globalmente — o nosso
  público inicial natural de rede de anonimato.
- Microempresas e estabelecimentos locais em PT + BR com presença em reviews:
  é aqui que está o SAM *pago*. Ver 2.2.

**SOM — Serviceable Obtainable Market (36 meses)**
Modelado no [documento 07](07-projecoes-financeiras.md): centenas a baixos
milhares de estabelecimentos pagantes no HidraReview + dezenas de milhares de
utilizadores do browser. Um SOM pequeno e credível vale mais numa reunião do que
um SOM grande e inventado.

---

## 2. Os dois mercados da HidraNet

Esta é a análise central do pacote. A HidraNet opera hoje em dois mercados com
economias opostas.

### 2.1 Mercado A — Rede de anonimato e browser de privacidade

**Dimensão:** enorme. **Disposição a pagar: perto de zero.**

Referências reais da rede Tor em 2026:
- **2,0–2,5 milhões** de utilizadores diretos por dia (algumas fontes apontam
  ~3 M; picos reportados muito acima disso).
- **7.500–9.500 relays** ativos, dos quais apenas **1.500–2.000 são nós de saída**.
- **~800.000 serviços onion v3** ativos por dia.

O dado mais importante para nós: **a rede Tor estabilizou**. Utilizadores diários
na casa dos baixos milhões há anos, contagem de onion services estável. Não é um
mercado em explosão — é infraestrutura madura. Isto corta a narrativa fácil de
"o Tor está a crescer e nós apanhamos a onda".

**O problema económico deste mercado:** os concorrentes diretos são gratuitos.
Tor Browser: gratuito, sem fins lucrativos. Mullvad Browser: gratuito, sem
qualquer negócio de publicidade. Brave: gratuito. Não existe um mercado de
"browser de privacidade pago" porque o preço de referência é zero.

**Conclusão:** o Mercado A é onde está a missão, a tecnologia diferenciadora e a
elegibilidade a fundos públicos. **Não é onde está a receita de curto prazo.**

### 2.2 Mercado B — HidraReview: reputação e reviews para comércio local

**Dimensão:** muito menor. **Disposição a pagar: comprovada.**

- Mercado de cartões NFC de review: **31,38 M$ em 2026 → 90,01 M$ em 2035**.
  Pequeno, mas é hardware — a camada de software por cima é que vale.
- **Taxa de conversão NFC: 60–80%**, contra 35–50% do QR code. Esta é a métrica
  de venda: um estabelecimento passa de ~40% para ~70% de conversão em pedidos
  de avaliação.
- Reviews são um dos principais sinais de ranking de pesquisa local. Um
  estabelecimento local tem receita diretamente ligada a isto.

**Porque é que este é o mercado que financia o outro:** um dono de restaurante
paga 19 €/mês por mais avaliações porque consegue ligar isso a faturação. Um
utilizador de browser de privacidade não paga 19 €/mês por anonimato que o Tor
lhe dá de graça.

### 2.3 A tensão estratégica — e a resposta

| | Mercado A (Rede) | Mercado B (HidraReview) |
|---|---|---|
| TAM | 83–108 mil M$ | dezenas de M$ (hardware) + SaaS |
| Cliente | Consumidor individual | Estabelecimento local (B2B) |
| Disposição a pagar | ~0 | 9–29 €/mês, comprovada |
| Concorrência | Tor, Brave, Mullvad — gratuitos, anos à frente | Fragmentada, muitos pequenos |
| Ciclo de venda | Viral / nenhum | Venda direta, presencial |
| Elegível a fundos públicos | **Sim, fortemente** | Não |

**A resposta a dar ao investidor não é escolher um.** É esta:

> O HidraReview é o produto comercial. Cada estabelecimento que adere recebe um
> endereço `.hidra` e passa a ser um nó da rede. O negócio de reputação local
> paga as contas e, ao mesmo tempo, popula a rede com conteúdo e utilizadores
> reais — o problema que mata todas as redes descentralizadas novas. A rede não
> é um segundo produto: é o fosso competitivo do primeiro.

Esta narrativa só funciona se for verdade no produto. Ver
[documento 08 — Roadmap](08-roadmap.md), onde está o trabalho necessário para a
tornar verdadeira.

---

## 3. Como o setor da privacidade ganha dinheiro (evidência)

Quatro modelos, todos reais, com números:

| Empresa | Modelo | Receita | Utilizadores |
|---|---|---|---|
| **Brave** | Publicidade sem rastreio + partilha de receita de pesquisa; fica com 30% dos anúncios ao utilizador e 15% dos de editor | **>100 M$ ARR** (2025–26), de 52 M$ em 2024 | **100 M MAU** (set. 2025) |
| **Proton** | Freemium por subscrição em serviços úteis (mail, VPN, drive) | **97,5 M$ ARR** (2024), de 70 M$ em 2022 | — |
| **Mullvad** | Preço fixo, sem escalões, sem publicidade, sem conta | — | — |
| **Tor Project** | Sem fins lucrativos: donativos e subvenções | — | 2–2,5 M/dia |

**As três lições que isto dá à HidraNet:**

1. **O modelo Brave está fora de alcance.** Exige ~100 M de utilizadores para
   chegar aos 100 M$. Com zero utilizadores, não é um plano — é um destino.
2. **O modelo Proton é o caminho viável.** Freemium sobre *serviços úteis*, não
   sobre a camada de privacidade em si. Ninguém paga pela privacidade; paga por
   email, armazenamento, domínios — e escolhe o fornecedor privado. A HidraNet
   tem HidraMail, `.hidra` e HidraReview: são esses os serviços cobráveis.
3. **O modelo Tor Project é o que financia o arranque.** Subvenções para a
   camada de protocolo, código aberto. Não é alternativa ao negócio: é o que o
   sustenta antes de haver receita.

---

## 4. Riscos de mercado

| Risco | Probabilidade | Impacto | Mitigação |
|---|---|---|---|
| Concorrentes gratuitos (Tor/Brave/Mullvad) tornam a rede não monetizável | **Alta** | Alto | Receita vem do Mercado B; a rede é diferenciação, não linha de receita |
| Chat Control aprovado em forma que abranja HidraChat/HidraMail | Média | **Alto** | Ver doc. 10; arquitetura sem conhecimento do conteúdo, entidade fora do âmbito |
| Associação reputacional a mercados ilícitos | Média | **Alto** | Posicionamento em comércio local legítimo (HidraReview) desde o dia um |
| Recusa de banca / processadores de pagamento a serviços de anonimato | **Alta** | Alto | Faturar o HidraReview como SaaS de reputação, não como serviço de anonimato |
| Mercado Tor estável, não em crescimento | Confirmada | Médio | Não depender de crescimento orgânico da procura por anonimato |
| Dois produtos, dois GTM, dois fundadores | **Alta** | Alto | Foco explícito: HidraReview comercial, rede em código aberto financiada por subvenções |

---

## Fontes

- [The Business Research Company — VPN Global Market Report](https://www.thebusinessresearchcompany.com/report/virtual-private-network-global-market-report)
- [Precedence Research — VPN Market](https://www.precedenceresearch.com/virtual-private-network-market)
- [IMARC — Virtual Private Network Market](https://www.imarcgroup.com/virtual-private-network-market)
- [Crunchbase News — 2026 Is A Solid Year For Cybersecurity Startup Funding](https://news.crunchbase.com/cybersecurity/solid-startup-venture-funding-growth-h1-2026/)
- [Crunchbase News — Cybersecurity Funding Holds Up At Robust Levels](https://news.crunchbase.com/cybersecurity/data-robust-venture-funding-ai-q1-2026/)
- [SQ Magazine — Tor Statistics 2026](https://sqmagazine.co.uk/tor-statistics/)
- [Tor Metrics (fonte primária)](https://metrics.torproject.org/)
- [Sacra — Brave revenue, valuation & funding](https://sacra.com/c/brave/)
- [Stan Ventures — Brave Reaches 100M Users and $100M Revenue](https://www.stanventures.com/news/brave-hits-100-million-users-and-100-million-revenue-5746/)
- [GetLatka — Proton AG Revenue](https://getlatka.com/companies/protonmail)
- [Wikipedia — Chat Control](https://en.wikipedia.org/wiki/Chat_Control)
- [TechRadar — Chat Control: Can the EU Parliament save our encrypted chats?](https://www.techradar.com/vpn/vpn-privacy-security/chat-control-can-the-eu-parliament-save-our-encrypted-chats)
- [RFIDtag — Google Review Cards for local businesses](https://rfidtag.com/how-google-review-cards-help-local-businesses-get-more-5-star-reviews/)
- [Pitchwise — Startup Funding Rounds Explained 2026](https://www.pitchwise.se/blog/the-complete-guide-to-seed-and-series-funding-rounds-for-founders-in-2026)
