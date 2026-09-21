# Manual de Onboarding — HidraNet

**Para novos membros da equipa** · Versão 1.0

---

## Bem-vindo

Este manual cobre a primeira semana. Se algo aqui estiver errado ou em falta,
**corrija-o** — é um documento da equipa, não um documento sobre a equipa.

---

## 1. O que fazemos, em dois minutos

A HidraNet constrói infraestrutura de comunicação privada: uma rede
descentralizada com criptografia pós-quântica, um browser e aplicações que
cifram no dispositivo do utilizador.

**Uma coisa a compreender antes de tudo o resto:**

> As pessoas que usam isto podem estar a depender disto.

Não sabemos quem são — por desenho, não podemos saber. Podem ser jornalistas,
podem ser pessoas comuns que simplesmente não querem ser observadas. Um erro
nosso não produz um relatório de incidente: pode produzir consequências reais
para alguém.

Isto não é para criar ansiedade. É para explicar por que razão somos
minuciosos em coisas que noutras empresas seriam detalhes.

---

## 2. Os nossos princípios

### 2.1 Não recolher é melhor do que proteger

Dados que não existem não podem ser roubados, vazados nem exigidos por ninguém.
Antes de acrescentar um campo, uma métrica ou um registo, a pergunta é:
**precisamos mesmo disto?** A resposta predefinida é não.

### 2.2 Subprometer, sempre

Nunca afirmamos garantias que não verificámos. "100% anónimo" não se escreve
aqui — nem em marketing, nem na interface, nem numa conversa.

Se alguém confiar numa promessa exagerada e sofrer consequências, a
responsabilidade é de quem exagerou.

### 2.3 Honestidade sobre limitações é funcionalidade

O browser diz ao utilizador quando **não** consegue confirmar o anonimato. É a
decisão de produto que melhor define esta empresa. Quando tiver de escolher
entre parecer competente e ser exato, escolha ser exato.

### 2.4 Comunicar erros cedo nunca é sancionado

Um incidente comunicado em 10 minutos é gerível. Um escondido durante uma semana
pode não ser.

**Se cometer um erro, diga imediatamente.** Nunca houve nem haverá consequência
disciplinar por comunicar um erro próprio. Há, sim, por esconder.

### 2.5 Neutralidade

Somos uma ferramenta técnica. Não entramos em confronto político nem nos
posicionamos contra governos. Defendemos a privacidade em termos técnicos e
jurídicos — é um direito reconhecido, e isso é suficiente.

---

## 3. Primeiro dia

### Checklist

- [ ] Contrato assinado, incluindo **cessão de propriedade intelectual**
- [ ] NDA assinado
- [ ] Gestor de palavras-passe instalado e configurado
- [ ] **Autenticação multifator ativada em tudo** — sem exceções
- [ ] Cifra de disco confirmada no equipamento
- [ ] Acessos atribuídos (princípio do privilégio mínimo)
- [ ] Ler: Código de Conduta, Política de Segurança da Informação
- [ ] Apresentação à equipa

### Leitura obrigatória da primeira semana

| Ordem | Documento | Porquê |
|---|---|---|
| 1 | Whitepaper Técnico, **especialmente a secção 5** | O modelo de ameaça é o que define o que é um erro |
| 2 | Política de Segurança da Informação | Regras de trabalho |
| 3 | Código de Conduta | Como nos tratamos |
| 4 | Guia de Contribuição, **secção 6** | As regras não negociáveis |
| 5 | Manual de Marca, **secção 7** | Como falamos do produto |
| 6 | Plano de Resposta a Incidentes | Antes de precisar |

> **Se só ler uma coisa:** Whitepaper §5.2 — aquilo contra o qual **não**
> protegemos. É o que distingue um profissional de privacidade de alguém que
> acha que criptografia resolve tudo.

---

## 4. Ambiente de desenvolvimento

```bash
git clone https://github.com/NeurexBK/HidraNet.git
cd HidraNet

# Motor (Rust ≥ 1.80)
cd hidra-node
cargo build && cargo test

# Browser (Node ≥ 20)
cd ../hidra-browser
npm install
npm run fetch-tor
npm start
```

**Primeira tarefa sugerida:** instale o browser, use-o durante um dia como
utilizador normal, e escreva o que o incomodou. Olhos novos veem o que nós
deixámos de ver. Essa lista é bem-vinda, não é atrevimento.

---

## 5. Como trabalhamos

### 5.1 Ritmo

| Quando | O quê |
|---|---|
| Segunda, 10h | Ponto de situação (30 min) |
| Diário | Atualização escrita e assíncrona |
| Mensal | Revisão de métricas |
| Trimestral | Revisão de estratégia |

**Assíncrono por omissão.** Reuniões são caras; convoque uma quando a discussão
escrita não resolve.

### 5.2 Código

- Ramos a partir de `main`
- *Conventional Commits* — ver Guia de Contribuição §5.3
- Revisão obrigatória antes de integrar
- **Criptografia e protocolo: duas revisões, incluindo o CTO**
- `cargo fmt`, `clippy` sem avisos e testes antes de submeter

### 5.3 As regras que não se quebram

| ❌ Nunca |
|---|
| Telemetria ou análise que identifique utilizadores |
| Dependências externas carregadas em tempo de execução em código criptográfico |
| Primitivas criptográficas implementadas de raiz |
| Registo de conteúdo de utilizador — **nem para depuração** |
| Segredos no repositório |
| Dados de clientes em equipamento pessoal |

Se uma tarefa parecer exigir uma destas, **pare e pergunte**. Não é bloqueio
burocrático: é provavelmente sinal de que o problema tem outra solução.

---

## 6. Quem é quem

| Função | Quem | Procure para |
|---|---|---|
| CEO | [nome] | Estratégia, clientes, investidores, jurídico |
| CTO | [nome] | Arquitetura, segurança, decisões técnicas |

**Regra útil:** pergunte cedo. Uma pergunta feita ao fim de 20 minutos custa 20
minutos. Feita ao fim de dois dias, custa dois dias.

---

## 7. Canais

| Canal | Uso |
|---|---|
| [Chat interno] | Conversa do dia a dia |
| GitHub Issues | Trabalho técnico |
| GitHub Discussions | Propostas e discussão aberta |
| security@hidranet.org | **Vulnerabilidades — sempre por aqui** |
| conduct@hidranet.org | Violações do Código de Conduta |

---

## 8. Primeiros 30 dias

### Semana 1 — Compreender
- [ ] Leituras obrigatórias
- [ ] Ambiente a funcionar
- [ ] Usar o produto como utilizador
- [ ] Primeira contribuição pequena integrada (documentação conta)

### Semana 2 — Contribuir
- [ ] Primeira tarefa real
- [ ] Rever código de outra pessoa
- [ ] Compreender a sua área a fundo

### Semanas 3–4 — Autonomia
- [ ] Tarefa com autonomia
- [ ] Propor uma melhoria própria
- [ ] Conversa de balanço com o responsável

### Ao fim de 30 dias

Conversa de duas direções. Perguntamos como correu e o que melhoraríamos no
acolhimento; queremos ouvir o que não fez sentido.

**Ao fim de 30 dias ainda tem a vantagem de ver a empresa de fora. Use-a antes
que passe.**

---

## 9. Condições

| | |
|---|---|
| Horário | Flexível; sobreposição de algumas horas para trabalho conjunto |
| Local | [Remoto / híbrido / Lisboa] |
| Férias | [dias] |
| Equipamento | Fornecido, com cifra de disco obrigatória |
| Formação | Orçamento anual — ver com o responsável |
| **Stock options** | Conforme elegibilidade — **peça o documento 16 e leia-o** |

> **Sobre as opções:** se lhe forem atribuídas, receberá por escrito o número, o
> preço de exercício, o calendário de aquisição e o total da empresa. Se algum
> destes elementos faltar, peça-o. Uma opção cujo detentor não sabe o que
> representa não vale nada como incentivo — e a culpa disso seria nossa, não sua.

---

## 10. Perguntas frequentes

**E se eu partir alguma coisa?**
Acontece. Diga imediatamente, corrija-se, e depois percebe-se o que no sistema
permitiu que acontecesse. Não procuramos culpados — procuramos a causa.

**Posso usar IA para escrever código?**
Sim, com duas condições: revê tudo o que submete, e **nunca cola código
criptográfico gerado sem revisão de duas pessoas**. A responsabilidade pelo
código é de quem o submete.

**Posso falar publicamente sobre o meu trabalho?**
Sobre o que é público (código MIT, documentação), sim. Sobre roteiro não
publicado, vulnerabilidades por corrigir ou informação comercial, não — ver NDA.
Em dúvida, pergunte.

**Posso contribuir para outros projetos de código aberto?**
Sim, e é incentivado. Confirme apenas que não há conflito de interesses.

**Discordo de uma decisão técnica.**
Diga. Por escrito, com o raciocínio. Discordância fundamentada é o que impede
decisões más de se consolidarem. Se a decisão se mantiver, avança-se — mas o
argumento fica registado.
