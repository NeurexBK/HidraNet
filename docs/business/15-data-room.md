# 15 — Data Room (due diligence)

O que um investidor vai pedir depois de dizer "estamos interessados". Montar
**antes** de precisar: um data room pronto em 24 horas transmite competência;
três semanas a reunir documentos transmite o contrário e arrefece a ronda.

Estrutura sugerida em pastas numeradas, numa drive partilhada com controlo de
acesso.

---

## 01 — Sociedade
- [ ] Certidão permanente
- [ ] Pacto social (versão em vigor)
- [ ] Acordo parassocial entre fundadores
- [ ] **Cap table** atualizado, com vesting explícito
- [ ] Atas da gerência
- [ ] RCBE
- [ ] Registo de beneficiários efetivos

## 02 — Financeiro
- [ ] Contas dos exercícios encerrados
- [ ] Balancetes do exercício corrente
- [ ] Modelo financeiro com pressupostos editáveis ([07](07-projecoes-financeiras.md))
- [ ] Extratos bancários (12 meses)
- [ ] Situação fiscal e contributiva regularizada (certidões AT e SS)
- [ ] Mapa de dívida, se existir

## 03 — Comercial
- [ ] Lista de clientes (anonimizada se necessário)
- [ ] Contrato-tipo de cliente
- [ ] **Coorte de churn por mês de entrada** ← o que mais vão analisar
- [ ] CAC por canal
- [ ] MRR e evolução
- [ ] Pipeline

## 04 — Produto e tecnologia
- [ ] Acesso ao repositório (ou auditoria de código)
- [ ] Documentação de arquitetura
- [ ] **Inventário de licenças de código aberto**
- [ ] **Relatório de auditoria de segurança**
- [ ] Roadmap ([08](08-roadmap.md))
- [ ] Registo de incidentes (incluindo a janela de fuga de IP e a correção — ver nota abaixo)

## 05 — Propriedade intelectual
- [ ] **Acordo de cessão de PI dos fundadores** ← bloqueio absoluto se faltar
- [ ] Cessões de PI de colaboradores e freelancers
- [ ] Registo de marca (INPI / EUIPO)
- [ ] Domínios registados

## 06 — Jurídico e conformidade
- [ ] Termos e Condições
- [ ] Política de Privacidade
- [ ] Política de Conteúdo
- [ ] **Registo de atividades de tratamento (RGPD art. 30.º)**
- [ ] DPIA
- [ ] Contratos com subcontratantes
- [ ] Procedimento de violação de dados
- [ ] Apólices de seguro
- [ ] Parecer jurídico sobre risco regulatório ([10](10-risco-legal-regulatorio.md))

## 07 — Equipa
- [ ] Contratos de trabalho e de prestação de serviços
- [ ] Organograma
- [ ] Plano de ESOP, se existir
- [ ] Acordos de confidencialidade

## 08 — Financiamento anterior
- [ ] Contratos de subvenção (NGI Zero, etc.)
- [ ] Relatórios de execução entregues
- [ ] Quaisquer instrumentos convertíveis emitidos

---

## Nota sobre o registo de incidentes

Incluir a janela de fuga de IP descrita em
[03 §1.4](03-produto-e-tecnologia.md), com datas, análise e correção.

Parece contraintuitivo entregar a um investidor a lista das próprias falhas. Não
é. Numa empresa de privacidade, a pergunta não é *"já tiveram falhas?"* — é
*"como é que descobrem e corrigem falhas?"*. Um registo que mostra uma falha
encontrada internamente, compreendida e corrigida antes do lançamento público
responde a essa pergunta melhor do que qualquer afirmação.

Uma empresa de segurança sem registo de incidentes está a dizer que não procura.

---

## As cinco perguntas que vão fazer

Preparar as respostas por escrito, antes:

1. **"Mostrem-me a coorte de churn."** — Se não houver 3 meses de dados, é cedo
   demais para esta conversa.
2. **"Quem é dono do código?"** — Resposta certa: a empresa, por cessão escrita.
3. **"O que acontece se o Google lançar isto?"** — O fosso é a rede e a
   propriedade dos dados, não o NFC.
4. **"Qual é a vossa exposição ao Chat Control?"** — [10 §2](10-risco-legal-regulatorio.md).
5. **"Porque é que são duas empresas?"** — [04 §5](04-modelo-de-negocio.md) e
   slide 7.
