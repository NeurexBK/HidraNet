# Tabela de Capitalização (Cap Table) — HidraNet

**Versão 1.0 · Setembro 2026**
Fundadores: João Brandão · Leonardo Mello

> ⚠️ **Documento de trabalho.** Os valores refletem a ronda pretendida e devem
> ser confirmados por advogado e contabilista antes de qualquer subscrição. A
> secção 6 levanta uma questão estrutural que deve ser decidida **antes** de
> constituir.

---

## 1. Parâmetros da ronda

| Parâmetro | Valor |
|---|---|
| Ronda | Seed |
| Investimento | **US$ 50.000** |
| Participação cedida | **5%** |
| Valuation *post-money* | **US$ 1.000.000** |
| Valuation *pre-money* | **US$ 950.000** |
| Option pool (ESOP) | **10%**, criado antes da entrada do investidor |

**Total de participações (base totalmente diluída): 1.000.000 unidades**
Preço por unidade: **US$ 1,00**

---

## 2. Antes da ronda

| Detentor | Unidades | % |
|---|---|---|
| João Brandão | 500.000 | 50,0% |
| Leonardo Mello | 500.000 | 50,0% |
| **Total** | **1.000.000** | **100%** |

> Ver secção 5 quanto à repartição 50/50.

---

## 3. Depois da ronda Seed

| Detentor | Unidades | % | Notas |
|---|---|---|---|
| João Brandão | 425.000 | **42,5%** | Sujeito a *vesting* |
| Leonardo Mello | 425.000 | **42,5%** | Sujeito a *vesting* |
| **Fundadores (subtotal)** | **850.000** | **85,0%** | |
| Option pool (ESOP) | 100.000 | **10,0%** | Não atribuído |
| Investidor Seed | 50.000 | **5,0%** | US$ 50.000 |
| **Total** | **1.000.000** | **100%** | |

### Quem suporta a diluição

Ponto que costuma gerar mal-entendidos e é melhor esclarecer já:

| | Antes | Depois | Diluição |
|---|---|---|---|
| Fundadores | 100% | 85% | **−15 pontos** |
| — dos quais, pelo pool | | | −10 pontos |
| — dos quais, pelo investidor | | | −5 pontos |

**O option pool é criado *pre-money*.** Significa que a diluição de 10% é
suportada integralmente pelos fundadores, não pelo investidor — que entra já
depois de o pool existir. É a prática habitual, mas é negociável: um pool criado
*post-money* dilui todos proporcionalmente.

**Vale a pena negociar.** A diferença, nesta ronda, é de cerca de 5 pontos
percentuais para os fundadores.

---

## 4. Evolução projetada

Cenário ilustrativo, para mostrar a trajetória de diluição. **Não é previsão.**

| | Hoje | Pós-Seed | Pós-Pre-seed alargada | Pós-Série A |
|---|---|---|---|---|
| **Fundadores** | 100% | **85,0%** | ~70% | ~52% |
| ESOP | — | 10,0% | 12% | 15% |
| Investidor Seed | — | 5,0% | 4,1% | 3,1% |
| Investidores seguintes | — | — | ~13,9% | ~29,9% |
| **Valuation** | — | US$ 1 M | US$ 4–6 M | US$ 15–25 M |

**Objetivo de governança:** manter os fundadores com maioria confortável após a
Série A. Acima de 50% combinados na Série A é uma posição saudável; abaixo de
40% começa a limitar a capacidade de decisão.

---

## 5. A repartição entre fundadores

A tabela acima assume **50/50**. É a repartição mais comum e é a que mais
problemas cria.

**O problema:** em caso de desacordo, não existe mecanismo de desempate. A
empresa bloqueia precisamente quando precisa de decidir depressa. É uma das
causas mais frequentes de falência de startups em fase inicial, e não tem nada
a ver com o mérito de nenhum dos dois.

**Alternativa recomendada:** repartição ligeiramente assimétrica, acordada
agora, quando ainda não custa nada acordá-la.

| Opção | João | Leonardo | Comentário |
|---|---|---|---|
| A — 50/50 | 42,5% | 42,5% | Simples, sem desempate |
| **B — 52/48** | 44,2% | 40,8% | **Recomendada** — desempate mínimo |
| C — 55/45 | 46,75% | 38,25% | Se as contribuições forem claramente distintas |

Critérios para decidir: quem teve a ideia inicial, quem investiu mais tempo até
aqui, quem assume o papel de CEO, quem entra a tempo inteiro primeiro.

**Se optarem por 50/50**, incluam no acordo parassocial uma cláusula de
desempate — por exemplo, um terceiro independente que decida em caso de bloqueio,
ou voto de qualidade do CEO em matérias operacionais.

---

## 6. ⚠️ Questão estrutural: Lda ou SA?

**Esta decisão tem de ser tomada antes da constituição.**

Uma **sociedade por quotas (Lda)** não tem ações — tem **quotas**. A cessão de
quotas exige, em regra, escritura ou documento particular autenticado e registo,
e está sujeita a direito de preferência dos restantes sócios. Isto torna um
plano de opções para colaboradores (ESOP) **operacionalmente pesado**: cada
exercício de opção é uma cessão de quota, com custos e formalidades.

Uma **sociedade anónima (SA)** tem ações, transmissíveis por mero registo,
admite diferentes categorias de ações e acomoda naturalmente planos de opções e
entradas sucessivas de investidores.

| | Lda | SA |
|---|---|---|
| Capital mínimo | 1 € | 50.000 € |
| Custo e rapidez de constituição | Menor | Maior |
| Transmissão de participações | Pesada | Simples |
| Viabilidade prática de ESOP | **Difícil** | **Natural** |
| Preferência de investidores de VC | Menor | **Maior** |

**Recomendação:** constituir como **Lda** se o ESOP ficar para depois e a ronda
for pequena — é mais barato e rápido. Transformar em **SA** antes da primeira
ronda institucional. A transformação é possível e corrente, mas tem custo e
demora: **decidir com antecedência evita fazê-lo sob pressão de prazo de uma
ronda**, que é quando sai caro.

Confirmar com advogado societário e contabilista antes de avançar.

---

## 7. *Vesting* dos fundadores

**Não negociável, e deve constar do acordo parassocial desde a constituição.**

| Parâmetro | Valor |
|---|---|
| Período | 4 anos |
| *Cliff* | 12 meses |
| Aquisição após o *cliff* | Mensal (1/48 por mês) |
| Aceleração em aquisição da empresa | 50% (*single trigger*) |
| Cláusula de *bad leaver* | Perda das participações não adquiridas |

**Porquê, mesmo entre pessoas que confiam uma na outra:** se um dos dois sair ao
fim de 8 meses, sem *vesting* leva metade da empresa e o outro trabalha anos
para um sócio ausente. Nenhum investidor institucional entra numa empresa sem
*vesting* de fundadores — vai exigi-lo na ronda, e nessa altura a negociação é
muito mais difícil do que hoje, quando a empresa ainda não vale nada.

---

## 8. Observação sobre a dimensão da ronda

US$ 50.000 por 5% é uma ronda pequena — na prática, entre *friends and family* e
um anjo individual.

**Implicações a ter presentes:**

- A 1 M$ de *valuation*, US$ 50.000 dão pista curta. Ao ritmo de custos do plano
  financeiro, cobre poucos meses de operação.
- Uma *valuation* baixa numa primeira ronda **condiciona as seguintes**. Se a
  ronda seguinte for a 4 M$, é um múltiplo saudável; se a empresa precisar de
  levantar antes de progredir, o risco é uma *down round*.
- **Alternativa a considerar:** um instrumento convertível (SAFE ou nota
  convertível) com *valuation cap*, que adia a fixação do preço para quando
  houver métricas. Para uma empresa pré-receita, costuma ser mais favorável aos
  fundadores do que fixar 1 M$ agora.

Vale a pena discutir esta alternativa com o investidor antes de fechar preço.

---

## 9. Registo de movimentos

A manter atualizado. Todo o movimento de capital deve ser registado aqui **na
data em que ocorre**, não reconstruído mais tarde — um cap table reconstruído é
um problema em due diligence.

| Data | Evento | Detentor | Unidades | Preço/un. | Total |
|---|---|---|---|---|---|
| [data] | Constituição | João Brandão | 500.000 | — | — |
| [data] | Constituição | Leonardo Mello | 500.000 | — | — |
| [data] | Criação do ESOP | Pool | 100.000 | — | — |
| [data] | Ronda Seed | [Investidor] | 50.000 | US$ 1,00 | US$ 50.000 |

---

## 10. Documentos associados

| Documento | Finalidade |
|---|---|
| Pacto social / estatutos | Base legal |
| Acordo parassocial entre fundadores | *Vesting*, desempate, saída |
| Acordo de cessão de PI | **Crítico** — transfere o código para a empresa |
| Regulamento do ESOP | Ver documento 16 |
| Acordo de subscrição | Formaliza a entrada do investidor |
| Acordo parassocial com investidores | Direitos de informação e de voto |

> **Aviso sobre o acordo de cessão de PI:** todo o código escrito até hoje
> pertence aos fundadores a título pessoal. Tem de ser formalmente transferido
> para a empresa. Sem essa cessão, a empresa não é proprietária do produto que
> diz vender — e é bloqueio absoluto em due diligence.
