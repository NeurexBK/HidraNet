# HidraNet — Índice de Documentação

**Versão 1.0 · Setembro 2026 · Lisboa, Portugal**
Fundadores: João Brandão · Leonardo Mello

---

## Documentos

### 📐 Técnico — `docs/tecnico/`

| # | Documento | Público |
|---|---|---|
| 01 | [Whitepaper Técnico](tecnico/01-whitepaper.md) | Investidores, avaliadores de fundos, comunidade técnica |
| 07 | [Guia de Instalação](tecnico/07-guia-instalacao.md) | Utilizadores, operadores de nós |
| 08 | [Guia do Utilizador](tecnico/08-guia-utilizador.md) | Utilizadores |
| 09 | [Documentação da API](tecnico/09-api.md) | Programadores, integradores |

### ⚖️ Legal — `docs/legal/`

| # | Documento | Estado |
|---|---|---|
| 03 | [Termos e Condições](legal/03-termos-de-uso.md) | ⚠️ Modelo — rever com advogado |
| 04 | [Política de Privacidade](legal/04-politica-privacidade.md) | ⚠️ Modelo — RGPD + LGPD |
| 05 | [Política de Uso Aceitável](legal/05-politica-uso-aceitavel.md) | ⚠️ Modelo |
| 06 | [NDA](legal/06-nda.md) | ⚠️ Modelo bilateral |

### 💼 Societário — `docs/societario/`

| # | Documento | Nota |
|---|---|---|
| 02 | [Cap Table](societario/02-cap-table.md) | Seed US$ 50k / 5% · Ver §6: Lda ou SA |
| 16 | [Política de Stock Options (ESOP)](societario/16-esop.md) | Pool 10% · Ver §8: fiscalidade |
| 18 | [Guia de Governança](societario/18-governanca.md) | Separação empresa / rede |

### 🔒 Segurança — `docs/seguranca/`

| # | Documento |
|---|---|
| 14 | [Política de Segurança da Informação](seguranca/14-politica-seguranca-informacao.md) |
| 15 | [Plano de Resposta a Incidentes](seguranca/15-plano-resposta-incidentes.md) |

### 🤝 Comunidade — `docs/comunidade/`

| # | Documento | Idioma |
|---|---|---|
| 10 | [Guia de Contribuição](comunidade/10-guia-contribuicao.md) | PT + EN |
| 11 | [Código de Conduta](comunidade/11-codigo-conduta.md) | PT + EN |
| 19 | [Programa de Embaixadores](comunidade/19-programa-embaixadores.md) | PT |

### 🎨 Marca e Comunicação — `docs/marca/`

| # | Documento | Nota |
|---|---|---|
| 12 | [Manual de Marca](marca/12-manual-marca.md) | ⚠️ Ver §1: duas identidades a unificar |
| 13 | [Kit de Imprensa](marca/13-kit-imprensa.md) | |
| 20 | [FAQ](marca/20-faq.md) | |

### 👥 Interno — `docs/interno/`

| # | Documento |
|---|---|
| 17 | [Manual de Onboarding](interno/17-onboarding.md) |

### 📊 Negócio — `docs/business/`

Pacote anterior: mercado, modelo de negócio, concorrência, go-to-market,
projeções, roadmap, risco legal, jurisdição, fundos, pitch deck, data room.
Ver [`business/00-INDICE.md`](business/00-INDICE.md).

---

## Antes de usar: seis pontos a resolver

Levantados durante a elaboração. Não são opinião — decorrem de verificação no
código e nos números.

### 1. ⚠️ O whitepaper não afirma rede de anonimato própria em produção

Verificado no código: os relays do motor estão configurados em
`127.0.0.1:7001-7003`, e o próprio código documenta que o circuito próprio sai
da máquina do utilizador sem alterar o IP. O anonimato de saída vem hoje do
**Tor embutido**.

O protocolo está implementado e testado; a **população de relays** está em
construção. O whitepaper (§8) diz isto expressamente, porque a afirmação
contrária não sobrevive a verificação técnica — e perder credibilidade técnica
num projeto de criptografia é irreversível.

**A mesma cautela aplica-se ao número de nós ativos:** use apenas números que
consiga demonstrar.

### 2. ⚠️ Lda ou SA — decidir antes de constituir

Uma Lda tem **quotas**, não ações. Cada exercício de opção é uma cessão de
quota, com escritura, registo e direito de preferência. Torna um ESOP
operacionalmente pesado.

Ver [Cap Table §6](societario/02-cap-table.md). Corrigir depois custa uma
transformação societária, normalmente sob pressão de prazo de uma ronda.

### 3. ⚠️ Fiscalidade das opções

Em Portugal, o colaborador pode ser tributado no exercício sobre um ganho que
ainda não realizou em dinheiro, por as participações serem ilíquidas. É um
problema real e recorrente.

**Obter parecer fiscal antes da primeira atribuição.** Ver
[ESOP §8](societario/16-esop.md).

### 4. ⚠️ Cessão de propriedade intelectual

Todo o código escrito até hoje pertence aos fundadores **a título pessoal**.
Sem cessão formal, a empresa não é proprietária do produto que diz vender.

É bloqueio absoluto em due diligence. Assinar na constituição.

### 5. ⚠️ Duas identidades visuais

O site usa verde neon `#00ff88`; o produto usa teal `#00d4aa`. São marcas
diferentes. Decisão e contrastes verificados em
[Manual de Marca §1 e §3.3](marca/12-manual-marca.md).

Nota de acessibilidade verificada: o teal **falha** sobre branco (1,91:1) — usar
`#00695c` em fundos claros e impressão.

### 6. ⚠️ Token HIDRA e MiCA

Sob o regulamento MiCA, uma empresa sediada na UE que emita token assume
encargo regulatório significativo, com impacto em prazos, custo de conformidade
e relação com a banca.

Não está incluído nestes documentos por decisão de âmbito. **Obter
aconselhamento jurídico especializado antes de qualquer anúncio ou emissão.**

---

## Estado dos documentos

| Categoria | Estado |
|---|---|
| Técnico | ✅ Prontos — verificados contra o código |
| Legal | ⚠️ Modelos — **revisão por advogado obrigatória** |
| Societário | ⚠️ Decisões estruturais em aberto (pontos 2 e 3) |
| Segurança | ✅ Prontos |
| Comunidade | ✅ Prontos |
| Marca | ⚠️ Decisão de unificação por aplicar |
| Interno | ✅ Pronto — campos `[nome]` a preencher |

**Os documentos legais não são aconselhamento jurídico.** Preparam a conversa
com um advogado de direito digital; não a substituem. Uma rede de anonimato tem
particularidades que um advogado generalista não cobre.

---

## Convenções

- Português europeu
- Inglês nos documentos de comunidade (10, 11) e no resumo do whitepaper
- Campos entre `[colchetes]` a preencher
- ⚠️ assinala decisão pendente ou risco a tratar
- Markdown, convertível para PDF/DOCX com `pandoc`

```bash
pandoc docs/tecnico/01-whitepaper.md -o whitepaper.pdf
```
