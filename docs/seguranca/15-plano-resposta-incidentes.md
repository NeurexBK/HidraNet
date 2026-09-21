# Plano de Resposta a Incidentes — HidraNet

**Versão 1.0 · Setembro 2026**
Responsável: CTO · Teste: semestral

---

## 1. Como usar este documento

Em incidente real, vá direto ao que precisa:

| Situação | Secção |
|---|---|
| Está a decorrer agora — o que faço já? | **§2 — Primeiros 15 minutos** |
| Qual é a gravidade? | §3 |
| Quem contactar? | §4 |
| Violação de dados pessoais — prazos legais | §6 |
| Vulnerabilidade reportada por investigador externo | §7 |
| O que comunicar publicamente | §8 |

**Imprima este documento.** Um plano de resposta a incidentes acessível apenas
no sistema que está comprometido não é um plano.

---

## 2. Primeiros 15 minutos

### Passo 1 — Não desligue nada ainda

**Isole, não destrua.** Desligar um sistema comprometido apaga memória volátil
que é a principal fonte de prova sobre o que aconteceu.

- Retire o sistema da rede (desligue o cabo, ou regra de firewall)
- **Não reinicie**
- **Não apague ficheiros**
- Não inicie sessão com credenciais privilegiadas no sistema afetado

### Passo 2 — Registe

Abra um ficheiro de registo (noutro equipamento) e anote, com hora:

```
[HH:MM] O que observei:
[HH:MM] O que fiz:
[HH:MM] O que vi como resultado:
```

Registe **enquanto age**. A reconstituição posterior é sempre incompleta, e é
precisamente o que a autoridade de proteção de dados vai pedir.

### Passo 3 — Avise a outra pessoa

Contacte imediatamente o outro fundador. **Nenhum incidente é tratado por uma
pessoa sozinha.** Quem está a responder perde perspetiva; quem chega de fora
faz as perguntas que faltam.

### Passo 4 — Classifique

Ver §3. A classificação determina os prazos.

---

## 3. Classificação de gravidade

| Nível | Critério | Resposta | Comunicação |
|---|---|---|---|
| **P0 — Crítico** | Chaves de assinatura comprometidas · Vulnerabilidade explorada ativamente que desanonimize utilizadores · Comprometimento da cadeia de distribuição | **Imediata, tudo o resto para** | Pública em 24h |
| **P1 — Alto** | Dados de clientes expostos · Vulnerabilidade crítica sem exploração conhecida · Acesso não autorizado a produção | 4 horas | Afetados em 72h |
| **P2 — Médio** | Vulnerabilidade sem impacto direto no utilizador · Indisponibilidade prolongada | 24 horas | Conforme relevância |
| **P3 — Baixo** | Vulnerabilidade teórica · Problema de configuração sem exposição | 7 dias | Notas de versão |

### Classificação em caso de dúvida

**Classifique acima.** Um P2 tratado como P1 custa algumas horas; um P1 tratado
como P2 pode custar o projeto. A reclassificação para baixo é sempre possível
depois de compreender melhor.

---

## 4. Funções

Com uma equipa pequena, uma pessoa acumula funções. O que não pode acontecer é
ninguém ter a função.

| Função | Quem | Responsabilidade |
|---|---|---|
| **Coordenador** | CTO (suplente: CEO) | Decide, coordena, mantém o registo |
| **Técnico** | CTO | Contenção, análise, correção |
| **Comunicação** | CEO | Utilizadores, clientes, imprensa |
| **Jurídico** | CEO + advogado externo | Autoridades, obrigações legais |

**Contactos de emergência** (manter atualizado e acessível offline):

| | Contacto |
|---|---|
| CTO | [telefone] |
| CEO | [telefone] |
| Advogado | [nome, telefone] |
| CNPD | www.cnpd.pt |
| Alojamento | [suporte 24h] |

---

## 5. Fases da resposta

### 5.1 Deteção

Origens possíveis: monitorização, relato de utilizador, investigador externo,
comunicação de autoridade, ou observação da equipa.

### 5.2 Contenção

**Imediata:**
- Isolar sistemas afetados
- Revogar credenciais comprometidas
- Bloquear acessos suspeitos
- Se houver risco ativo para utilizadores, **considerar retirar a versão
  afetada de distribuição**

**A prazo:**
- Corrigir a causa
- Repor a partir de cópia de segurança verificada
- Rodar todas as credenciais relacionadas

### 5.3 Erradicação e recuperação

1. Identificar a causa raiz — não apenas o sintoma
2. Corrigir e testar
3. Verificar que o acesso do atacante foi eliminado
4. Repor o serviço
5. Monitorizar de forma reforçada durante 30 dias

### 5.4 Análise posterior

**Obrigatória para P0 e P1, em 7 dias.** Documento com:

- Cronologia dos factos
- Causa raiz
- Impacto: o que foi afetado, quantas pessoas
- O que correu bem
- O que correu mal
- Ações corretivas, com responsável e prazo

**Sem atribuição de culpa individual.** Uma análise que procura culpados ensina
a equipa a esconder incidentes, o que garante que o próximo será pior. Procura-se
o que no sistema permitiu o erro.

---

## 6. Violação de dados pessoais

### 6.1 Prazos legais

```
      Conhecimento da violação
                │
                ├── Avaliar risco para os titulares ─── imediato
                │
                ├── Notificar a CNPD ────────────────── 72 HORAS
                │   (se houver risco para direitos e liberdades)
                │
                └── Notificar os titulares ──────────── sem demora
                    (se houver risco ELEVADO)
```

**O prazo de 72 horas conta do conhecimento, não da confirmação.** Se não tiver
todos os elementos, notifique com o que tem e complete depois — a notificação
faseada é expressamente admitida. Ultrapassar o prazo é infração autónoma.

### 6.2 Conteúdo da notificação à CNPD

1. Natureza da violação, categorias e número aproximado de titulares e registos
2. Contacto do responsável (ou do Encarregado, se designado)
3. Consequências prováveis
4. Medidas adotadas ou propostas, incluindo mitigação

### 6.3 Notificação aos titulares

Em linguagem clara e simples, indicando:
- O que aconteceu
- Que dados foram afetados
- O que fizemos
- **O que a pessoa deve fazer**
- Onde obter mais informação

### 6.4 Dispensa de notificação aos titulares

Quando os dados estavam cifrados de forma que os torne ininteligíveis. **É o
efeito prático da cifra no cliente:** o conteúdo que não detemos em claro não
constitui violação notificável, porque não é inteligível para quem o obtenha.

### 6.5 Brasil (LGPD)

Havendo titulares no Brasil, notificar a ANPD em prazo razoável, nos termos do
artigo 48.º da LGPD.

---

## 7. Vulnerabilidade reportada externamente

| Prazo | Ação |
|---|---|
| 48 horas | Acusar receção |
| 7 dias | Avaliar, classificar, informar o investigador |
| Conforme gravidade | Corrigir (P0: dias; P1: 30 dias; P2: 90 dias) |
| Na correção | Publicar, creditar o investigador |
| 90 dias | Divulgação, corrigida ou não, com justificação se não corrigida |

**Regra de conduta:** tratamos quem reporta como aliado, não como ameaça.
Ameaçar juridicamente um investigador de boa-fé é, além de errado, a forma mais
rápida de garantir que a próxima vulnerabilidade é publicada sem aviso.

---

## 8. Comunicação pública

### 8.1 Princípios

1. **Comunicar cedo**, mesmo sem ter todas as respostas
2. **Não minimizar.** Se os utilizadores estão em risco, dizê-lo claramente
3. **Dizer o que a pessoa deve fazer** — é a parte que lhe interessa
4. **Atualizar** à medida que se souber mais
5. **Nunca afirmar "nenhum dado foi afetado"** antes de o ter verificado

### 8.2 O que não fazer

| ❌ | Porquê |
|---|---|
| Esperar por ter a história completa | O silêncio é interpretado como encobrimento |
| Linguagem vaga ("um incidente de segurança") | Erode a confiança mais do que o próprio incidente |
| Culpar terceiros | A responsabilidade perante o utilizador é nossa |
| Prometer o que não se pode garantir | |

### 8.3 Modelo de comunicação inicial

```markdown
# Incidente de segurança — [data]

## O que aconteceu
[Descrição factual, sem tecnicismos desnecessários.]

## Quem é afetado
[Quem, quantos, que dados.]

## O que já fizemos
[Ações concretas, com horas.]

## O que deve fazer
[Instruções claras e acionáveis.]

## O que vamos fazer
[Próximos passos e quando atualizamos.]

## Contacto
security@hidranet.org

*Última atualização: [data e hora]*
```

---

## 9. Cenários específicos

### 9.1 Chave de assinatura comprometida — P0

1. **Revogar imediatamente** e comunicar publicamente
2. Retirar de distribuição todas as versões assinadas com essa chave
3. Gerar nova chave em módulo de hardware
4. Reassinar e republicar, com novas somas de verificação
5. **Avisar todos os utilizadores que verifiquem antes de atualizar**
6. Análise posterior pública

### 9.2 Vulnerabilidade que desanonimize utilizadores — P0

1. Avaliar exploração ativa
2. Se ativa: **avisar publicamente antes de haver correção** — as pessoas
   precisam de saber para poderem parar de usar
3. Corrigir e publicar
4. Nota clara nas notas de versão
5. Relatório detalhado após correção

> Este é o cenário mais difícil: avisar sem correção disponível dá informação ao
> atacante. **Mas o utilizador tem direito a saber que está em risco.** A decisão
> pende para o aviso.

### 9.3 Comprometimento da cadeia de distribuição — P0

1. Retirar imediatamente todos os pacotes
2. Aviso público destacado no site
3. Verificar integridade de todos os artefactos
4. Reconstruir a partir de fonte verificada, em ambiente limpo
5. Republicar com novas somas de verificação
6. Instruções explícitas de verificação

### 9.4 Pedido de autoridade

1. **Não responder de imediato.** Encaminhar para o CEO e o advogado
2. Verificar validade legal e jurisdição
3. Determinar o que efetivamente possuímos (ver Política de Privacidade §3 —
   normalmente muito pouco)
4. Contestar se excessivo ou sem base legal
5. Notificar o visado, salvo proibição legal
6. Registar para o Relatório de Transparência

**Nunca:** alterar o software para criar capacidade de acesso que não exista. Um
pedido nesse sentido é recusado e, se necessário, contestado judicialmente.

---

## 10. Testes

| Teste | Frequência |
|---|---|
| Simulação de mesa (*tabletop*) | Semestral |
| Teste de restauro de cópias | Trimestral |
| Verificação de contactos de emergência | Trimestral |
| Simulação de *phishing* | Anual |
| Revisão deste plano | Anual ou após cada P0/P1 |

**Um plano nunca testado é um documento, não um plano.** A primeira simulação
revela sempre que faltam contactos, que ninguém sabe onde estão as credenciais
de emergência, e que o coordenador está de férias.

---

## 11. Registo de incidentes

| Data | Gravidade | Descrição | Estado | Análise |
|---|---|---|---|---|
| | | | | |

*A manter atualizado. Incluir também incidentes menores — o padrão ao longo do
tempo é mais informativo do que qualquer incidente isolado.*
