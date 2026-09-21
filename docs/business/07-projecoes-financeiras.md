# 07 — Projeções Financeiras

> **Aviso, e é para levar a sério.** Tudo o que se segue são **pressupostos
> declarados**, não previsões. Uma startup pré-receita não tem projeções — tem
> um modelo que mostra como pensa. O valor deste documento está nos pressupostos
> estarem explícitos e serem discutíveis, não nos totais.
>
> Um investidor experiente vai ignorar os números e atacar os pressupostos.
> É exatamente para isso que servem.

---

## 1. Pressupostos-chave

| # | Pressuposto | Valor | Confiança | Como validar |
|---|---|---|---|---|
| P1 | ARPU HidraReview Pro | 19 €/mês | Média | Testar 15 € vs 19 € vs 29 € nos pilotos |
| P2 | **Churn mensal** | **4%** | **Baixa** | **Medir nos primeiros 20 clientes — é a métrica que decide tudo** |
| P3 | CAC venda direta | 60 € | Baixa | Medir na fase 1 |
| P4 | Margem bruta SaaS | 85% | Alta | Padrão do setor |
| P5 | Conversão grátis→Pro | 15% | Baixa | Medir |
| P6 | Novos clientes/mês (ano 1, a partir do mês 4) | 10 → 30 | Média | Venda direta, uma cidade |
| P7 | Custo servidores/cliente | 0,50 €/mês | Alta | Infraestrutura leve |
| P8 | Salário dos fundadores | 1.500 €/mês bruto cada, a partir do mês 6 | — | Decisão |

**P2 é o pressuposto crítico.** Com 4% de churn, o tempo de vida é 25 meses e o
LTV ~400 €. Com 8%, cai para 12,5 meses e ~200 € — e a venda direta a 60 € de
CAC deixa de ser confortável. **Medir isto antes de contratar quem quer que seja.**

---

## 2. Cenário base — 36 meses

### Ano 1 (validação)

| | T1 | T2 | T3 | T4 | **Ano 1** |
|---|---|---|---|---|---|
| Clientes pagantes (fim) | 0 | 15 | 45 | 100 | **100** |
| MRR (fim, €) | 0 | 285 | 855 | 1.900 | **1.900** |
| Receita (€) | 0 | 500 | 1.700 | 4.100 | **6.300** |
| Subvenções (NGI Zero) | — | 25.000 | — | — | **25.000** |
| Custos (€) | 4.000 | 8.000 | 12.000 | 15.000 | **39.000** |
| **Resultado (€)** | −4.000 | +17.500 | −10.300 | −10.900 | **−7.700** |

### Ano 2 (escala numa geografia)

| | Ano 2 |
|---|---|
| Clientes pagantes (fim) | **450** |
| MRR (fim) | **8.550 €** |
| Receita anual | **~62.000 €** |
| Subvenções | 25.000 € (2.ª fase NGI Zero) |
| Equipa | 2 fundadores + 1 comercial + 1 dev |
| Custos | ~120.000 € |
| **Resultado** | **−33.000 €** |

### Ano 3 (multi-cidade + pre-seed)

| | Ano 3 |
|---|---|
| Clientes pagantes (fim) | **1.400** |
| MRR (fim) | **26.600 €** |
| Receita anual | **~230.000 €** |
| Equipa | 8 pessoas |
| Custos | ~290.000 € |
| **Resultado** | **−60.000 €** |

**Leitura:** o negócio não se autofinancia em 36 meses com venda direta. É por
isso que existe a ronda pre-seed do ano 2. **Um modelo que mostra lucro no ano 2
sem financiamento seria sinal de que os pressupostos não foram levados a sério.**

---

## 3. Estrutura de custos (ano 1 detalhado)

| Rubrica | Ano 1 (€) | Notas |
|---|---|---|
| Salários dos fundadores (do mês 6) | 21.000 | 1.500 €/mês × 2 × 7 meses |
| Constituição e contabilidade | 3.000 | Lda + contabilista certificado |
| **Jurídico** | **3.500** | Ver [10](10-risco-legal-regulatorio.md) — não cortar aqui |
| Infraestrutura (servidores, domínios) | 1.200 | |
| Hardware NFC (stock inicial) | 1.500 | ~500 cartões |
| Ferramentas e software | 1.200 | |
| Marketing e deslocações | 3.600 | Venda presencial |
| Seguro de responsabilidade civil | 800 | |
| Contingência (10%) | 3.200 | |
| **Total** | **39.000** | |

**Necessidade de capital do ano 1: ~39.000 €**, dos quais **25.000 € podem vir
do NGI Zero sem diluição**. O remanescente (~14.000 €) é capital dos fundadores
ou receita inicial. **É um arranque viável sem investidor** — e essa é a
posição negocial mais forte que podem ter quando chegar a altura de falar com um.

---

## 4. Necessidade de capital e ronda

| Fase | Montante | Origem | Diluição |
|---|---|---|---|
| Arranque (ano 1) | ~39.000 € | NGI Zero + fundadores | **0%** |
| Pre-seed (ano 2) | 300.000–500.000 € | VC / anjos | 10–18% |
| Seed (ano 3–4) | 1,5–3 M€ | VC | 15–20% |

**Uso do pre-seed (300–500 k€), 18 meses de pista:**
- 45% equipa comercial (é o gargalo: o produto existe, a distribuição não)
- 25% produto e engenharia
- 15% marketing e aquisição
- 10% jurídico, conformidade e auditoria de segurança
- 5% contingência

**Contexto:** pre-seed europeu situa-se tipicamente em 500 k€–3 M€ e seed em
1–5 M€. 300–500 k€ é o limite inferior — é deliberado. Pedir o mínimo necessário
para atingir o marco seguinte preserva diluição e é sinal de disciplina.

---

## 5. Análise de sensibilidade — o que parte o modelo

| Variável | Cenário mau | Efeito | Que fazer |
|---|---|---|---|
| **Churn 4% → 8%** | LTV cai ~50%, para ~200 € | **Modelo deixa de fechar com venda direta** | Parar de vender, corrigir o produto |
| CAC 60 € → 150 € | LTV:CAC cai para ~1,3:1 | Insustentável | Mudar de canal (revendedores, associações) |
| ARPU 19 € → 12 € | Receita −37% | Sobrevivível | Subir escalões, upsell de domínios `.hidra` |
| NGI Zero recusado | −25.000 € no ano 1 | Atraso de ~6 meses | Recandidatar (prazos de 2 em 2 meses) + Portugal 2030 |
| Google lança NFC próprio | Diferenciação erodida | **Alto** | O fosso é a rede e a propriedade dos dados, não o NFC |

**A linha do churn é a que decide se isto é uma empresa.** Todas as outras se
gerem.

---

## 6. Marcos que desbloqueiam a ronda seguinte

| Marco | Porquê |
|---|---|
| **20 clientes pagantes com 3 meses de histórico** | Dá churn e CAC reais; substitui P2 e P3 por factos |
| 100 clientes pagantes | Prova que o canal repete |
| NGI Zero aprovado | Validação técnica independente + auditoria de segurança |
| Auditoria de segurança concluída | Desbloqueia o lançamento público do browser |
| Churn <5% durante 3 meses | Prova que o produto retém |

**Sem os dois primeiros, qualquer conversa com VC é prematura.**

---

## 7. Ficheiro de modelo

Estes números devem passar para folha de cálculo com as células de pressupostos
**separadas e ligadas**, para que um investidor possa mexer no churn e ver o
efeito ao vivo. Fazer isso numa reunião é dos gestos que mais credibilidade dá:
mostra que os números são um modelo, não um argumento de venda.
