# 12 — Documentos da Empresa (checklist completo)

Pedido: *"todos os documentos que uma empresa deve ter"*. Aqui está, por fase.
Pressupõe **Portugal, Lda** ([ver 11](11-jurisdicao-comparativo.md)); os
princípios aplicam-se às outras jurisdições com nomes diferentes.

Legenda: 🔴 obrigatório por lei · 🟡 exigido por investidores · 🟢 boa prática

---

## A. Constituição

| | Documento | Notas |
|---|---|---|
| 🔴 | **Certificado de admissibilidade de firma** | RNPC — reservar "HidraNet" |
| 🔴 | **Pacto social / estatutos** | Com vesting e direito de preferência. Não usar o modelo genérico do Empresa na Hora sem revisão. |
| 🔴 | **Certidão permanente** | Prova de existência |
| 🔴 | **NIPC** | |
| 🔴 | **Declaração de início de atividade (AT)** | CAE correto — ver aviso em [10 §5](10-risco-legal-regulatorio.md) |
| 🔴 | **Registo de beneficiário efetivo (RCBE)** | Prazo apertado após a constituição |
| 🔴 | Ata n.º 1 — designação de gerência | |
| 🟡 | **Acordo parassocial entre fundadores** | Vesting, saída, desempate, não-concorrência |
| 🟡 | **Acordo de cessão de PI** | **Crítico** — ver [09 §6](09-equipa-e-governance.md) |
| 🟢 | Livro de atas | Digital serve |

---

## B. Operação corrente

| | Documento | Notas |
|---|---|---|
| 🔴 | Contabilidade organizada | Contabilista certificado obrigatório |
| 🔴 | Faturação certificada (software AT) | |
| 🔴 | IES anual | |
| 🔴 | IVA (periódico) | |
| 🔴 | IRC anual (Modelo 22) | |
| 🔴 | Declarações à Segurança Social | |
| 🔴 | Contratos de trabalho | |
| 🔴 | Seguro de acidentes de trabalho | Obrigatório com o 1.º trabalhador |
| 🟢 | Seguro de responsabilidade civil profissional | Ver [10 §7](10-risco-legal-regulatorio.md) — recomendado |
| 🟢 | Política de despesas | |

---

## C. Produto e clientes

| | Documento | Notas |
|---|---|---|
| 🔴 | **Termos e Condições de Serviço** | |
| 🔴 | **Política de Privacidade** | Tem de descrever o que o software faz **mesmo** |
| 🔴 | Política de Cookies | Landing page |
| 🔴 | **Política de Conteúdo / Uso Aceitável** | Reviews, sites `.hidra`, fórum |
| 🔴 | Mecanismo de notificação e ação (DSA) | Alojamento de conteúdo de terceiros |
| 🔴 | Contrato-tipo de cliente (SaaS) | |
| 🟢 | SLA | A partir do escalão Cadeia |
| 🟢 | Política de reembolso | |

---

## D. RGPD

| | Documento | Notas |
|---|---|---|
| 🔴 | **Registo de atividades de tratamento** | Artigo 30.º — documento obrigatório e frequentemente esquecido |
| 🔴 | Contratos com subcontratantes | Alojamento, pagamentos, email, analítica |
| 🔴 | Procedimento de resposta a direitos do titular | |
| 🔴 | **Procedimento de notificação de violações (72h)** | Escrever **antes** de precisar |
| 🟡 | **Avaliação de impacto (DPIA)** | Provavelmente aplicável |
| 🟢 | Política interna de proteção de dados | |
| 🟢 | Registo de formação da equipa | |

---

## E. Propriedade intelectual

| | Documento | Notas |
|---|---|---|
| 🟡 | **Cessão de PI dos fundadores** | Repetido de propósito: é o mais esquecido |
| 🟡 | Cessão de PI de colaboradores e freelancers | Em **todos** os contratos |
| 🟢 | **Registo da marca "HidraNet"** | INPI (PT) e EUIPO (UE). ~250–850 €. Fazer cedo — a marca é o ativo mais fácil de perder. |
| 🟢 | Registo de domínios (defensivo) | `.pt`, `.com`, `.eu` |
| 🟢 | Inventário de licenças de código aberto | Due diligence vai pedir |
| 🟢 | Ficheiro de licença (MIT) e CONTRIBUTING | Requisito de facto para o NGI Zero |

---

## F. Financiamento

| | Documento | Notas |
|---|---|---|
| 🟡 | **Cap table** | Atualizado, em folha de cálculo |
| 🟡 | Pitch deck ([14](14-pitch-deck.md)) | |
| 🟡 | Modelo financeiro ([07](07-projecoes-financeiras.md)) | Com células de pressupostos editáveis |
| 🟡 | Data room ([15](15-data-room.md)) | |
| 🟡 | Term sheet (quando houver oferta) | **Nunca assinar sem advogado** |
| 🟡 | Acordo de subscrição | |
| 🟡 | Acordo parassocial com investidores | |
| 🟢 | Relatórios trimestrais a investidores | Começar **antes** de ter investidores — ganha o hábito e impressiona |

---

## G. Específicos de uma empresa de privacidade

Estes não aparecem em nenhum checklist genérico e são os que distinguem a
HidraNet de uma startup qualquer:

| | Documento | Porquê |
|---|---|---|
| 🟢 | **Transparency Report** | Publicação periódica de pedidos de autoridades recebidos e respondidos. É o padrão do setor (Tor, Proton, Mullvad). **Vale mais em marketing do que qualquer campanha paga.** |
| 🟢 | **Warrant canary** | Declaração periódica de que não foram recebidos pedidos secretos. Usar com cuidado e com aconselhamento jurídico. |
| 🟢 | **Política de resposta a pedidos de autoridades** | Escrever com calma **antes** do primeiro pedido, nunca durante |
| 🟢 | **Declaração de dados não recolhidos** | Documentar por desenho o que a HidraNet **não** guarda — simplifica o RGPD e é argumento de venda |
| 🟢 | **Relatório de auditoria de segurança** | Publicar. Via NGI Zero ([13](13-fundos-candidaturas.md)) |
| 🟢 | Política de divulgação responsável (security.txt) | Investigadores precisam de saber a quem reportar |
| 🟢 | Modelo de ameaça publicado | Dizer explicitamente contra o que a HidraNet protege **e contra o que não protege**. Honestidade técnica é a moeda desta comunidade. |

---

## H. Ordem de execução

| Prioridade | Fazer | Quando |
|---|---|---|
| **1** | Candidatura NGI Zero (não precisa de empresa) | **Já** |
| **2** | Consulta jurídica | Mês 1 |
| **3** | Bloco A completo | Mês 1–2 |
| **4** | Marca no INPI/EUIPO | Mês 2 |
| **5** | Blocos C e D | Antes do 1.º cliente |
| **6** | Bloco B | Com a contabilidade |
| **7** | Bloco G | T2–T3 |
| **8** | Bloco F | Antes da ronda |

**Orçamento estimado do primeiro ano (legal + registos + contabilidade):
3.500–7.000 €.** É a rubrica onde menos compensa poupar.
