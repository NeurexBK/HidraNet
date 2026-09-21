# 10 — Risco Legal e Regulatório

> **Isto não é aconselhamento jurídico.** É o levantamento dos riscos para
> preparar a conversa com um advogado de direito digital — conversa que tem de
> acontecer **antes** da constituição, não depois. As decisões da secção 1 são
> estruturais: mudá-las mais tarde implica reestruturar a empresa.

---

## 1. A decisão que tem de ser tomada primeiro

**A empresa opera a rede, ou só faz o software?**

É a decisão mais consequente de todo este pacote. Tudo o resto depende dela.

### Opção A — A empresa opera nós de saída ❌ **Não recomendada**

Quem opera um nó de saída de uma rede de anonimato recebe o tráfego de
utilizadores anónimos a sair para a internet aberta, com o seu próprio IP. Isto
significa, na prática:

- Queixas de abuso dirigidas à empresa
- Pedidos de dados de autoridades policiais
- Risco de responsabilidade por conteúdo que a empresa não controla nem vê
- Bloqueio de IP por serviços terceiros
- Dificuldade em contratar banca e seguros

O Tor Project lida com isto desde o primeiro dia — e é uma organização sem fins
lucrativos com apoio jurídico especializado, não uma startup de dois fundadores.

**Uma empresa com dois fundadores não deve carregar responsabilidade de operador
de saída.**

### Opção B — A empresa faz software; a rede é de voluntários ✅ **Recomendada**

A empresa:
- Publica software de código aberto (MIT — já é o caso)
- Vende serviços (HidraReview SaaS, subscrições, domínios `.hidra`)
- **Não opera nós de saída**
- **Não aloja conteúdo de terceiros** (ou, se alojar, assume conscientemente o
  estatuto de prestador de alojamento ao abrigo do DSA — ver secção 3)

Os relays são corridos por voluntários, como no Tor. A empresa fornece o
software e, eventualmente, uma fundação apoia a rede.

**É o modelo Proton:** Proton AG (empresa, vende serviços) + Proton Foundation
(missão). É também, na prática, o modelo do Tor.

### Estrutura recomendada

```
   ┌──────────────────────────┐      ┌────────────────────────────┐
   │  HidraNet, Lda           │      │  Associação / Fundação     │
   │  (empresa comercial)     │      │  HidraNet  (opcional, T2+) │
   ├──────────────────────────┤      ├────────────────────────────┤
   │ • HidraReview SaaS       │      │ • Protocolo e especificação│
   │ • Subscrições HidraNet   │      │ • Comunidade de relays     │
   │ • Domínios .hidra        │      │ • Recebe subvenções        │
   │ • Licenciamento do motor │      │ • Não opera saídas         │
   │ • Emprega os fundadores  │      │                            │
   └──────────────────────────┘      └────────────────────────────┘
              │                                    │
              └────── licença MIT, ambos ──────────┘
                      contribuem para o código
```

**Nota de pragmatismo:** a fundação não é necessária no dia um e acrescenta
custo e complexidade. Constituir só a empresa; manter a separação **no
desenho técnico** desde já (a empresa nunca opera saídas) e criar a estrutura
jurídica separada quando houver subvenções ou relays de terceiros que o
justifiquem.

---

## 2. Chat Control / CSAR

**Estado atual (setembro 2026):** rejeitado a 26 de março de 2026 por um voto,
devolvido ao Conselho da UE. **Nem morto, nem em vigor.**

O que obrigaria: varrimento do lado do cliente (*client-side scanning*) de
mensagens antes da cifragem, contornando na prática a proteção do E2E.

**Exposição da HidraNet:** se for aprovado numa forma que abranja "serviços de
comunicação interpessoal independentes do número", o **HidraChat** e o
**HidraMail** podem cair no âmbito.

**Mitigações:**
1. **Arquitetura sem conhecimento do conteúdo.** O HidraChat já é E2E no cliente
   com relay. A empresa não deve estar em posição de aceder a conteúdo, mesmo
   que queira. Manter e documentar.
2. **Software, não serviço.** Se o chat é software que o utilizador corre e o
   relay é de terceiros, a posição jurídica é substancialmente diferente de
   operar um serviço de mensagens.
3. **Acompanhar ativamente.** Isto volta ao Conselho. Aderir à EDRi ou
   equivalente dá aviso antecipado e posiciona a empresa do lado certo do debate
   — o que é também marketing junto do público que queremos.

**Como apresentar a um investidor:** não esconder. Um VC que investe em
privacidade conhece o Chat Control melhor do que nós. Mostrar que está mapeado e
mitigado é sinal de maturidade; não o mencionar parece ingenuidade.

---

## 3. DSA — Digital Services Act

Aplica-se se a empresa **alojar conteúdo de terceiros**. Relevante para:
- Sites `.hidra` (SevenNine)
- Fórum
- Reviews do HidraReview ← **este é o que conta**

**O HidraReview aloja avaliações escritas por utilizadores sobre negócios
identificados.** É alojamento de conteúdo de terceiros, com risco de difamação.
Obrigações prováveis: mecanismo de notificação e ação, ponto de contacto,
termos claros, tratamento de reclamações.

> **Nota:** o problema de difamação em reviews não é teórico. É o litígio
> clássico deste mercado — um estabelecimento processa por uma avaliação falsa.
> O Trustpilot e o Google têm equipas jurídicas para isto. É preciso: política
> de conteúdo, processo de contestação pelo dono do estabelecimento (o painel do
> dono já existe — é a base), e seguro de responsabilidade civil.

Para sites `.hidra` e fórum, a posição é mais segura se a empresa **não alojar**:
se o conteúdo vive na máquina do utilizador ou em relays de voluntários, a
empresa é fornecedora de software, não de alojamento.

---

## 4. RGPD

Aplica-se, e é uma vantagem competitiva se for bem feito — mas é obrigação real.

| Obrigação | Aplicável | Notas |
|---|---|---|
| Base legal para o tratamento | ✅ | Contrato (SaaS), consentimento (marketing) |
| Registo de atividades de tratamento | ✅ | Art. 30.º — documento obrigatório |
| Política de privacidade | ✅ | Tem de refletir o que o software faz **mesmo** |
| Direitos do titular | ✅ | Acesso, retificação, apagamento, portabilidade |
| Encarregado de Proteção de Dados (DPO) | Provavelmente não | Não obrigatório à escala inicial; reavaliar |
| Avaliação de impacto (DPIA) | **Provavelmente sim** | Tecnologia de anonimato + dados de reviews |
| Notificação de violações (72h) | ✅ | Precisa de procedimento escrito, antes de precisar dele |
| Subcontratantes | ✅ | Contrato com cada fornecedor (alojamento, pagamentos, email) |

**Nota específica de anonimato:** a HidraNet, por desenho, **não recolhe** dados
de navegação. Isto simplifica enormemente o RGPD do lado do browser, e deve
estar documentado como decisão deliberada de arquitetura. Os dados que
existem estão todos do lado do HidraReview: contas de estabelecimento, emails,
faturação, conteúdo de avaliações.

---

## 5. Pagamentos e banca — o risco operacional subestimado

**Problema real:** processadores de pagamento e bancos restringem ou recusam
serviços associados a anonimato. Empresas de privacidade são recusadas por
bancos com regularidade.

**Mitigações:**
1. **Faturar o HidraReview como SaaS de reputação e marketing local** — que é o
   que é. Não como "serviço de anonimato". A descrição de atividade e o CAE/CNAE
   importam.
2. **Não misturar entidades** de faturação: o SaaS B2B é um negócio
   perfeitamente convencional aos olhos de um banco.
3. **Ter um processador alternativo preparado** antes de precisar dele.
4. **Não emitir token nem aceitar cripto no arranque.** Multiplica o escrutínio
   de compliance e limita ainda mais as opções de banca.

---

## 6. Outros riscos

| Risco | Exposição | Mitigação |
|---|---|---|
| Associação reputacional a mercados ilícitos | Média-alta | Posicionamento público em comércio local legítimo; termos de uso explícitos |
| Responsabilidade por conteúdo em sites `.hidra` | Média | A empresa não aloja |
| Difamação em reviews | **Alta** | Política, processo de contestação, seguro |
| Controlo de exportação de criptografia | Baixa | Código aberto e publicado geralmente beneficia de isenções; **confirmar com advogado** |
| Retenção de dados (variável por país) | Média | A empresa não opera rede, logo não tem o que reter |
| Propriedade intelectual dos fundadores | Média | Acordo de cessão de PI assinado por ambos, **antes** de qualquer ronda |

---

## 7. Ações concretas, por ordem

| # | Ação | Quando | Custo estimado |
|---|---|---|---|
| 1 | Consulta com advogado de direito digital (não generalista) | **Antes de constituir** | 300–800 € |
| 2 | Decidir Opção A vs B (recomendação: **B**) | Antes de constituir | — |
| 3 | Acordo de cessão de PI dos fundadores para a empresa | Na constituição | incluído |
| 4 | Termos de Serviço + Política de Privacidade + Política de Conteúdo | Antes do primeiro cliente | 500–1.500 € |
| 5 | Registo de atividades de tratamento (RGPD art. 30.º) | Antes do primeiro cliente | interno |
| 6 | DPIA | Antes do lançamento público | interno + revisão |
| 7 | Seguro de responsabilidade civil profissional | Antes de 100 clientes | 400–1.200 €/ano |
| 8 | Procedimento de notificação de violações | Antes do primeiro cliente | interno |

**Orçamento legal do primeiro ano: 2.000–5.000 €.** É dos melhores
investimentos disponíveis nesta fase, e é uma rubrica que um investidor
experiente espera ver no plano. A sua ausência é um sinal de alerta.
