# 14 — Pitch Deck

12 slides. Conteúdo pronto a montar. Regra: **um slide, uma ideia, um número.**

---

### 1 — Capa
> # HidraNet
> **Reputação para o comércio local, sobre uma rede de privacidade pós-quântica.**
>
> Leonardo Mello · João Brandão · Setembro 2026

---

### 2 — O problema
> Um restaurante com 12 avaliações perde para o da esquina com 200.
> A diferença não é a comida — é quantos clientes foram convidados a avaliar.
>
> Hoje esse convite é um QR code numa mesa: **converte 35 a 50%**.
>
> E a página com as avaliações não é do restaurante. É do Google.

---

### 3 — A solução
> Um cartão NFC na mesa. Um toque. **Converte 60 a 80%.**
>
> A página é do estabelecimento, com endereço próprio `.hidra`, e não
> desaparece se o Google mudar de política.

*Visual: fotografia de um cartão numa mesa + página no telemóvel.*

---

### 4 — Produto (o que já existe)
> - **HidraReview** — reviews, NFC, painel do dono, aviso por HidraMail
> - **HidraNet Browser** — Tor embutido, isolamento por separador, anonimato verificado
> - **hidra-node** — 17.000 linhas de Rust: encaminhamento em cebola + **Kyber1024** (pós-quântico)
> - HidraSearch · HidraChat · HidraMail · Fórum · sites `.hidra`
>
> Código aberto, MIT.

*Visual: captura do painel do dono, não diagrama de arquitetura.*

---

### 5 — Mercado
> **Onde vendemos:** microempresas e comércio local em PT e BR.
> Cartões NFC de review: **31,4 M$ (2026) → 90 M$ (2035)**.
>
> **Onde estamos posicionados:** privacidade e VPN, **83–108 mil M$** em 2026,
> a crescer ~20%/ano.
>
> **Vento de cauda:** o Chat Control foi rejeitado por **um voto** em março de
> 2026 e voltou ao Conselho. Cada ciclo destes gera procura por privacidade que
> o legislador não consegue travar.

---

### 6 — Modelo de negócio
> | | Preço |
> |---|---|
> | Grátis | 0 € |
> | **Pro** | **19 €/mês** + cartão NFC |
> | Multi (5 locais) | 49 €/mês |
>
> **Pressupostos a validar:** LTV ~400 € · CAC ~60 € · margem 85%
>
> *Segunda linha:* domínios `.hidra`, recorrente, custo marginal ~0.

---

### 7 — Porque é que isto é um fosso
> O Birdeye copia o cartão NFC em três meses.
>
> **Não copia a rede.**
>
> Cada estabelecimento que adere torna-se um nó com endereço próprio. O negócio
> de reputação paga as contas; a rede é o que nenhum concorrente de reviews
> consegue replicar.

*Este é o slide que decide a reunião. Ensaiar até sair em 30 segundos.*

---

### 8 — Concorrência
> | | Preço | Dono dos dados | NFC | PT/BR |
> |---|---|---|---|---|
> | Google Business | Grátis | Google | ✗ | parcial |
> | Birdeye/Podium | 200–400 €/mês | Plataforma | add-on | ✗ |
> | Cartões NFC | 15–30 € | — | só hardware | ✗ |
> | **HidraNet** | **0–49 €/mês** | **Estabelecimento** | **✓** | **✓** |
>
> Não substituímos o Google. Somos o que faz o Google funcionar melhor para o
> estabelecimento — e o que lhe dá uma página que é dele.

---

### 9 — Go-to-market
> **Fase 1** — uma cidade, venda direta, 100 clientes, churn medido
> **Fase 2** — revendedores (agências locais, contabilistas), 450 clientes
> **Fase 3** — Brasil
>
> O browser não se vende: é credibilidade técnica e topo de funil.

---

### 10 — Tração e financiamento
> **Hoje:** produto construído, código aberto, pré-receita.
>
> **Em curso:** candidatura ao **NGI Zero** (NLnet) — 5–50 k€ **não-diluidores**,
> mais auditoria de segurança externa.
>
> **Marcos:** 20 clientes com 3 meses de histórico → 100 clientes → ronda.

*Se, à data do pitch, já houver clientes ou o NGI Zero estiver aprovado, este
slide passa para posição 3.*

---

### 11 — Equipa
> **Leonardo Mello**, 28 — *[papel e percurso]*
> **João Brandão**, 26 — *[papel e percurso]*
>
> **O que nos falta:** vendas. Plano: fundadores vendem os primeiros 100;
> primeiro comercial ao 100.º cliente.

*Assumir a lacuna. É mais forte do que escondê-la.*

---

### 12 — O pedido
> **300–500 k€ de pre-seed**, 18 meses de pista.
>
> 45% vendas · 25% produto · 15% marketing · 10% jurídico e auditoria · 5% contingência
>
> **Para chegar a:** 450 clientes pagantes, churn <5%, canal de revendedores a
> funcionar, Brasil preparado.

---

## Apêndice (slides de reserva, para perguntas)

| # | Slide | Para a pergunta |
|---|---|---|
| A1 | Arquitetura técnica | "Como funciona?" |
| A2 | Risco legal e mitigação | "E o Chat Control?" — [10](10-risco-legal-regulatorio.md) |
| A3 | Modelo financeiro detalhado | "Mostra-me os números" |
| A4 | Sensibilidade ao churn | "E se o churn for o dobro?" |
| A5 | Porquê PT e não EE/BR | "Onde vão constituir?" |
| A6 | Roadmap 24 meses | "O que fazem com o dinheiro?" |

---

## Regras de apresentação

1. **Não dizer "o nosso mercado vale 108 mil milhões".** Dizer o SOM.
2. **Não esconder que são dois produtos.** Levantar antes que perguntem, com o
   slide 7 como resposta.
3. **Não apresentar projeções como previsões.** Dizer "pressupostos"; oferecer
   mexer no modelo ao vivo.
4. **Não prometer rede própria de anonimato a funcionar.** Hoje é protocolo
   próprio + rede Tor. Dizer isso.
5. **Levantar o Chat Control primeiro.** Um VC de privacidade conhece-o melhor
   do que nós.
