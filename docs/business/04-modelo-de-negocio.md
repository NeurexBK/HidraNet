# 04 — Modelo de Negócio

## 1. O princípio orientador

A evidência do setor (ver [02, secção 3](02-analise-mercado.md)) diz uma coisa
com clareza: **ninguém paga pela privacidade; paga por serviços úteis e escolhe o
fornecedor que respeita a privacidade.**

O Proton chegou a 97,5 M$ ARR a vender email, armazenamento e VPN — não a vender
criptografia. O Brave chegou a >100 M$ com publicidade sem rastreio, mas precisou
de 100 milhões de utilizadores para lá chegar. O Tor Project, que vende
anonimato puro, é uma organização sem fins lucrativos sustentada por donativos.

A HidraNet segue o modelo Proton, com uma diferença: **o primeiro serviço
cobrável é B2B, não B2C**, porque um estabelecimento comercial tem orçamento e um
utilizador de browser não tem.

---

## 2. As linhas de receita

Cinco linhas, ordenadas por quando começam a dar dinheiro.

### Linha 1 — HidraReview SaaS *(receita principal, arranca já)*

Assinatura mensal por estabelecimento, mais margem no hardware NFC.

| Escalão | Preço/mês | Inclui |
|---|---|---|
| **Grátis** | 0 € | Página pública, 1 endereço `.hidra`, reviews ilimitadas |
| **Pro** | 19 € | Cartão NFC, painel do dono, aviso por HidraMail, resposta a reviews, selo confirmado |
| **Multi** | 49 € | Até 5 estabelecimentos, relatórios, comparação entre locais |
| **Cadeia** | sob consulta | +5 locais, API, gestor de conta |

**Hardware:** cartão/placa NFC com margem. Custo unitário na ordem de 1–3 €,
venda a 15–25 € ou incluído no escalão Pro com fidelização. O mercado de cartões
NFC de review vale 31,4 M$ em 2026, mas o valor está no software por cima, não
no plástico.

**Porque é que um estabelecimento paga:** cartões NFC convertem a **60–80%**
contra 35–50% do QR code, e as avaliações são um dos principais sinais de
ranking na pesquisa local. É uma venda com retorno demonstrável, não uma venda
ideológica.

### Linha 2 — HidraNet Pro *(B2C, modelo Proton)*

Freemium sobre serviços úteis, não sobre a privacidade:

| | Grátis | Pro (~5 €/mês) |
|---|---|---|
| Browser + Tor | ✅ | ✅ |
| HidraSearch | ✅ | ✅ |
| HidraMail | básico | armazenamento alargado, domínio próprio |
| Domínios `.hidra` | 1 | 10 |
| Prioridade de circuito | — | ✅ |
| Apoio | comunidade | direto |

**Nota de realismo:** esta linha só tem sentido acima de ~50.000 utilizadores
ativos. Antes disso, a taxa de conversão típica de freemium (1–3%) gera receita
irrelevante. Está no plano, não no arranque.

### Linha 3 — Domínios `.hidra` *(recorrente, margem alta)*

Registo e renovação de endereços legíveis na rede. Cada estabelecimento do
HidraReview já tem um — é upsell natural. Custo marginal quase nulo.

### Linha 4 — Licenciamento do motor *(B2B, oportunista)*

O `hidra-node` é encaminhamento em cebola com **Kyber1024** em Rust, sob MIT.
Há procura empresarial por camadas de transporte resistentes a computação
quântica. Licença comercial, suporte e integração — receita de alto valor e
baixo volume. Não planear para isto; aceitar quando aparecer.

### Linha 5 — Subvenções e donativos *(não-diluidor, começa já)*

Não é receita contabilística no sentido clássico, mas é dinheiro que financia a
camada de protocolo sem custo de capital. Ver
[documento 13](13-fundos-candidaturas.md). O NGI Zero (5–50 k€) devia estar
submetido no próximo prazo.

---

## 3. O que rejeitamos, e porquê

Um investidor vai perguntar. Ter a resposta pronta vale mais do que a resposta.

| Opção | Porque não |
|---|---|
| **Venda de dados de utilizador** | Destrói a única proposta de valor que temos. Não negociável. |
| **Publicidade com rastreio** | Idem. |
| **Token / criptomoeda (modelo BAT)** | Sob MiCA, na UE, emitir token é um encargo regulatório pesado, atrasa a empresa em meses e afasta a comunidade de privacidade, que é o nosso público inicial. O Brave fez isto em 2017, noutro contexto regulatório. |
| **Operar nós de saída como empresa** | Herda queixas de abuso e pedidos judiciais. É uma decisão de arquitetura, não de produto. Ver [documento 10](10-risco-legal-regulatorio.md). |
| **Vender anonimato como produto principal** | O concorrente cobra zero. |

---

## 4. Unit economics (pressupostos, a validar)

> **Estes números são pressupostos declarados, não previsões.** Substituir por
> dados reais assim que houver 20 clientes pagantes. Apresentá-los a um VC como
> factos é a forma mais rápida de perder a reunião seguinte.

**HidraReview Pro, por estabelecimento:**

| Métrica | Pressuposto | Nota |
|---|---|---|
| ARPU | 19 €/mês → 228 €/ano | Escalão Pro |
| Margem bruta | ~85% | SaaS; custo de servidor marginal |
| Custo do cartão NFC | 1–3 € | Uma vez, amortizado |
| CAC (venda direta) | 40–80 € | Venda porta-a-porta / telefone; **o mais incerto de todos** |
| Churn mensal | 3–5% | Típico em SaaS de microempresa; é alto e é o risco principal |
| Tempo de vida | ~20–33 meses | 1/churn |
| **LTV** | **~390–640 €** | ARPU × margem × tempo de vida |
| **LTV:CAC** | **~5:1 a 8:1** | Saudável **se** o CAC se confirmar |

**O número que decide o negócio é o churn.** SaaS vendido a microempresas tem
churn estruturalmente alto. Se o churn real for 8%, o tempo de vida cai para 12
meses e o LTV para ~190 € — e a economia deixa de funcionar com venda direta.
**Primeira métrica a medir, antes de contratar qualquer comercial.**

---

## 5. Como as duas metades se sustentam

```
  SUBVENÇÕES (NGI Zero, EIC)          →  financiam o protocolo e o browser
            │                             (código aberto, sem diluição)
            ▼
  REDE + BROWSER                      →  credibilidade técnica, utilizadores,
            │                             diferenciação
            ▼
  HIDRAREVIEW (B2B, paga)             →  receita recorrente, que financia a equipa
            │
            ▼
  Cada estabelecimento = 1 endereço   →  conteúdo e utilizadores reais na rede,
  .hidra na rede                         que é o que mata as redes novas
            │
            └──────────────────────────┘  (o ciclo fecha)
```

**A frase para o deck:** *"O negócio de reputação local paga as contas. A rede é
o fosso competitivo. Cada cliente que fecha é um nó novo na rede."*

Isto só é verdade se o produto o tornar verdade — ver
[roadmap](08-roadmap.md), onde está o trabalho para lá chegar.
