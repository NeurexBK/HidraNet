# Guia de Governança — HidraNet

**Versão 1.0 · Setembro 2026**

---

## 1. Princípio estruturante: duas coisas separadas

A HidraNet tem duas naturezas que **não devem ser confundidas**:

```
┌────────────────────────────────┐   ┌────────────────────────────────┐
│  HidraNet, Lda                 │   │  O protocolo HidraNet          │
│  (empresa)                     │   │  (bem comum)                   │
├────────────────────────────────┤   ├────────────────────────────────┤
│ • Desenvolve software          │   │ • Licença MIT                  │
│ • Vende serviços (HidraReview) │   │ • Qualquer pessoa implementa   │
│ • Emprega pessoas              │   │ • Qualquer pessoa opera nós    │
│ • Decide por gerência          │   │ • Decide por consenso técnico  │
│                                │   │                                │
│ ❌ NÃO opera nós de saída      │   │ • Operado por voluntários      │
│ ❌ NÃO controla a rede         │   │ • Ninguém é dono               │
└────────────────────────────────┘   └────────────────────────────────┘
```

**Porque importa.** Quem opera nós de saída de uma rede de anonimato recebe
queixas de abuso e pedidos judiciais relativos a tráfego que não controla nem
consegue ver. Uma empresa jovem não deve carregar essa responsabilidade.

É o modelo do Tor e o do Proton: a entidade comercial faz software e vende
serviços; a rede é dos participantes.

**Esta separação é uma decisão de arquitetura, não de comunicação.** Está
refletida no desenho técnico: a empresa não corre nós de saída.

---

## 2. Governação da empresa

### 2.1 Órgãos

| Órgão | Composição | Competência |
|---|---|---|
| Assembleia de sócios | João Brandão, Leonardo Mello, investidores | Decisões estruturais |
| Gerência | João Brandão, Leonardo Mello | Gestão corrente |
| Conselho consultivo | A constituir após a ronda | Aconselhamento, sem poder vinculativo |

### 2.2 Papéis dos fundadores

**A atribuir formalmente antes da ronda.** Um investidor vai perguntar quem
decide o quê, e "decidimos os dois tudo" não é resposta.

| Função | Responsabilidade |
|---|---|
| **CEO** | Receita, investidores, candidaturas, jurídico, contratação. Representa a empresa. |
| **CTO** | Produto, engenharia, arquitetura, segurança, auditorias. |

**Critério útil para decidir quem é quem:** quem tem mais apetência para
conversas desconfortáveis — vendas, investidores, advogados — deve ser CEO. Não
é necessariamente quem domina melhor o produto.

**No primeiro ano, ambos falam com clientes.** Um CTO que nunca ouviu um cliente
constrói a coisa errada com grande competência técnica.

### 2.3 Matriz de decisão

| Decisão | Quem decide |
|---|---|
| Operações do dia a dia | Quem tem a função |
| Contratação até [nível] | CEO |
| Despesa até [1.000 €] | Qualquer fundador |
| Despesa acima de [1.000 €] | Ambos |
| Alterações de preço | Ambos |
| Arquitetura técnica | CTO, ouvido o CEO |
| **Decisões de segurança** | **CTO tem veto** — ver 2.4 |
| Contratação sénior | Ambos |
| Ronda de investimento | Assembleia |
| Alteração de estratégia | Ambos |
| Venda da empresa | Assembleia |

### 2.4 Veto em matéria de segurança

**O CTO pode vetar o lançamento de funcionalidade que comprometa a segurança ou
a privacidade dos utilizadores, mesmo com pressão comercial ou de prazo.**

Cláusula deliberada. Numa empresa de privacidade, a tentação de lançar antes de
estar seguro é permanente e as consequências são irreversíveis: uma falha
divulgada publicamente num browser de privacidade destrói a confiança que é o
único ativo real do produto.

O veto é registado por escrito, com fundamento, e pode ser superado por decisão
unânime da assembleia — que assim assume expressamente o risco.

### 2.5 Mecanismo de desempate

Com dois fundadores em 50/50, um desacordo bloqueia a empresa.

**Mecanismos a prever no acordo parassocial** (escolher um):

| Mecanismo | Como funciona |
|---|---|
| **Participação assimétrica** | 52/48 — quem tem mais decide. Ver doc. 02 §5. **Preferível.** |
| Voto de qualidade por área | CEO desempata em comercial; CTO em técnico |
| Terceiro independente | Consultor acordado por ambos decide em caso de bloqueio |
| Cláusula de saída (*shotgun*) | Um propõe preço, o outro escolhe comprar ou vender. Último recurso. |

**Decidir isto agora**, enquanto é uma conversa abstrata. Depois de haver
desacordo real, já não se negoceia mecanismo de desempate.

### 2.6 Ritmo de reuniões

| Reunião | Frequência | Participantes | Registo |
|---|---|---|---|
| Ponto de situação | Semanal, 30 min | Fundadores | Ata curta |
| Revisão de métricas | Mensal | Equipa | Painel partilhado |
| Revisão de estratégia | Trimestral | Fundadores + consultores | Documento |
| Assembleia | Anual + extraordinárias | Sócios | Ata formal |
| Relatório a investidores | Trimestral | — | Email escrito |

> **Comecem os relatórios trimestrais antes de terem investidores.** Cria o
> hábito, e quando chegar a primeira ronda já existe histórico — que impressiona
> mais do que qualquer apresentação.

---

## 3. Governação do projeto de código aberto

### 3.1 Modelo atual

**Liderança dos mantenedores** (*maintainer-led*). Adequado à fase: decisões
rápidas, responsabilidade clara.

| Papel | Quem | Poderes |
|---|---|---|
| Mantenedores | Fundadores | Decisão final; integração de alterações |
| Contribuidores | Comunidade | Propor alterações, discutir, reportar |
| Operadores de nós | Voluntários | Operam a sua infraestrutura de forma autónoma |

### 3.2 Como se decide uma alteração técnica

```
Proposta (issue ou RFC)
        ↓
Discussão pública — mínimo 7 dias para alterações estruturais
        ↓
Parecer dos mantenedores
        ↓
Implementação + revisão por pares
        ↓
Integração
```

**Alterações que exigem RFC escrita:**
- Alteração de protocolo que quebre compatibilidade
- Alteração de primitivas criptográficas
- Alteração que afete o modelo de ameaça
- Remoção de funcionalidade

**Princípio:** nenhuma alteração ao núcleo criptográfico é integrada sem revisão
por pelo menos duas pessoas, sendo uma delas o CTO.

### 3.3 Evolução prevista da governança

| Fase | Modelo |
|---|---|
| Hoje | Mantenedores (fundadores) |
| >10 contribuidores regulares | Comité técnico com membros externos |
| >50 nós independentes | Estrutura formal da comunidade |
| Maturidade | Fundação independente que detém o protocolo |

**Compromisso declarado:** à medida que a rede crescer, a governação do
protocolo abre-se. Uma rede descentralizada governada indefinidamente por duas
pessoas não é descentralizada — é centralizada com passos extra.

---

## 4. Transparência

### 4.1 O que publicamos

| Documento | Frequência |
|---|---|
| Relatório de Transparência (pedidos de autoridades, denúncias) | Semestral |
| Relatórios de auditoria de segurança | Quando concluídos |
| Registo de limitações e vulnerabilidades conhecidas | Contínuo |
| Alterações aos Termos e à Política de Privacidade | Com 30 dias de antecedência |
| Roteiro de desenvolvimento | Trimestral |

### 4.2 O que não publicamos

- Dados que identifiquem pessoas
- Vulnerabilidades ainda não corrigidas (divulgação coordenada: 90 dias ou até
  correção)
- Informação comercial sujeita a confidencialidade contratual

---

## 5. Conflitos de interesse

Os fundadores declaram, por escrito e anualmente:

- Participações noutras empresas do setor
- Relações com fornecedores, clientes ou concorrentes
- Funções em entidades que possam conflituar

Havendo conflito, a pessoa afetada não participa na decisão.

---

## 6. Relação com autoridades

**Política, definida com calma agora, antes de ser necessária:**

1. Respondemos a pedidos **legalmente válidos**, na jurisdição aplicável.
2. Fornecemos **apenas o que temos** — que é pouco, por desenho (ver Política de
   Privacidade §3).
3. **Notificamos a pessoa visada**, salvo proibição legal expressa.
4. **Contestamos pedidos que consideremos excessivos ou sem base legal.**
5. Registamos e publicamos os números no Relatório de Transparência.
6. **Não construímos capacidades de vigilância que não existam.** Um pedido para
   alterar o software de modo a permitir acesso a conteúdo é recusado e, se
   necessário, contestado judicialmente.

O ponto 6 é a razão pela qual a cifra é feita no cliente: não é uma política
revogável, é uma propriedade do sistema.

---

## 7. Revisão

Este guia é revisto **anualmente** ou sempre que ocorra alteração societária
relevante. Versão atual: 1.0. Próxima revisão: [data].
