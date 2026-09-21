# 01 — Sumário Executivo

**HidraNet** · Setembro 2026 · Leonardo Mello (28) · João Brandão (26)

---

## Em uma frase

Vendemos reputação a comércio local, sobre uma rede de privacidade
pós-quântica de código aberto que nenhum concorrente de reviews consegue copiar.

---

## O problema

Um estabelecimento local tem receita diretamente ligada às avaliações online.
O convite a avaliar é hoje um QR code numa mesa, que **converte 35 a 50%**. E a
página com as avaliações pertence ao Google, não ao estabelecimento.

## A solução

Um cartão NFC: um toque, **60 a 80% de conversão**. A página é do
estabelecimento, com endereço próprio `.hidra` na rede HidraNet.

## O que já existe

| Componente | Estado |
|---|---|
| `hidra-node` — motor em Rust, onion routing + **Kyber1024** pós-quântico | ~17.000 linhas, compila limpo |
| `hidra-browser` — Tor embutido, isolamento por separador, **anonimato verificado** | ~7.800 linhas |
| HidraReview, HidraSearch, HidraChat, HidraMail, Fórum, sites `.hidra` | Funcionais |
| Landing page, PWA, empacotamento Win/Linux/macOS | Feito |
| Licença MIT | ✅ elegível a fundos europeus |

**Estado comercial: pré-receita.**

## Mercado

- Cartões NFC de review: **31,4 M$ (2026) → 90 M$ (2035)** — pequeno, mas o
  valor está no SaaS por cima.
- Privacidade/VPN, onde estamos posicionados: **83–108 mil M$** em 2026, ~20%/ano.
- **Vento de cauda regulatório:** o Chat Control foi rejeitado por **um voto** em
  março de 2026 e voltou ao Conselho da UE. Cada ciclo gera procura por
  privacidade que o legislador não trava.

## Modelo de negócio

Grátis · **Pro 19 €/mês** + cartão NFC · Multi 49 €/mês · Cadeia sob consulta.
Segunda linha: domínios `.hidra`, recorrente, custo marginal ~0.

Pressupostos a validar: LTV ~400 €, CAC ~60 €, margem 85%.

## O pedido

**300–500 k€ de pre-seed**, 18 meses, para provar o motor de vendas do
HidraReview em Portugal e preparar o Brasil.

Antes disso: **NGI Zero (NLnet), 5–50 k€ não-diluidores**, a submeter no
próximo prazo.

---

## As três coisas que este plano assume e que podem estar erradas

Postas aqui de propósito. Um sumário executivo que só tem boas notícias não
sobrevive a uma segunda reunião.

**1. Que o churn seja ~4%.**
SaaS vendido a microempresas tem churn estruturalmente alto. A 8%, o LTV cai
para metade e a venda direta deixa de fechar. É a primeira métrica a medir, e
até lá o modelo é uma hipótese.

**2. Que a rede seja mesmo um fosso.**
Hoje a ligação entre o HidraReview e a rede é um endereço `.hidra` por
estabelecimento. Para ser um fosso a sério, tem de dar ao estabelecimento algo
que ele valorize — e isso é trabalho por fazer, não é uma funcionalidade
existente.

**3. Que se consiga vender sem equipa de vendas.**
São dois fundadores, sem histórico de vendas declarado, a vender a um cliente
que exige presença física. Os primeiros 100 clientes são vendidos por eles ou
não são vendidos.

---

## O que este projeto tem, que a maioria não tem

- **Produto construído e a funcionar**, não uma apresentação.
- **Diferenciação técnica real e verificável**: encaminhamento em cebola com
  Kyber1024 em produção, que o Tor ainda não tem.
- **Elegibilidade imediata a dinheiro não-diluidor** — MIT, descentralizado,
  privacidade: é literalmente o mandato do NGI Zero, com 21,6 M€ + 9,6 M€ em
  fundos abertos até 2027.
- **Um caminho de receita que não depende de convencer ninguém a pagar por
  privacidade** — depende de convencer um restaurante a querer mais avaliações,
  que é uma venda muito mais fácil.
- **Honestidade como funcionalidade de produto:** o browser confere o IP de
  saída contra o verificador do Tor Project e, quando não consegue confirmar,
  **diz ao utilizador que não conseguiu**, em vez de afirmar um anonimato que
  não verificou. É uma escolha rara, e é o melhor indicador do tipo de empresa
  que isto pode ser.

---

## Próximos passos (30 dias)

| # | Ação |
|---|---|
| 1 | **Submeter ao NGI Zero** — não precisa de empresa constituída |
| 2 | Consulta com advogado de direito digital |
| 3 | Constituir **HidraNet, Lda** (Portugal — ver [11](11-jurisdicao-comparativo.md)) |
| 4 | Acordo parassocial com **vesting** e cessão de PI |
| 5 | Fechar as lacunas de privacidade do browser ([03 §1.4](03-produto-e-tecnologia.md)) |
| 6 | HidraReview faturável + 10 pilotos presenciais |

---

*Documento de apoio. O pacote completo está em [`00-INDICE.md`](00-INDICE.md).*
