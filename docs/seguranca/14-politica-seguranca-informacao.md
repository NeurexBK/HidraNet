# Política de Segurança da Informação — HidraNet

**Versão 1.0 · Setembro 2026 · Classificação: Pública**
Responsável: CTO · Revisão: anual

---

## 1. Âmbito e princípio

Esta política aplica-se a todos os colaboradores, prestadores de serviços e
sistemas da HidraNet, Lda.

**Princípio orientador: a melhor forma de proteger dados é não os ter.**

A arquitetura da HidraNet minimiza deliberadamente a recolha. Não é uma medida
de conformidade acrescentada no fim — é a decisão de desenho a partir da qual
tudo o resto decorre. Dados que não existem não podem ser roubados, vazados nem
exigidos.

---

## 2. Classificação da informação

| Nível | Definição | Exemplos | Regra |
|---|---|---|---|
| **Público** | Divulgação sem risco | Código-fonte MIT, whitepaper, políticas | Livre |
| **Interno** | Uso interno | Roteiros, atas, métricas | Só equipa |
| **Confidencial** | Dano se divulgado | Dados de clientes, contratos, cap table | Necessidade de conhecer |
| **Crítico** | Dano grave | Chaves de assinatura, credenciais, vulnerabilidades não corrigidas | Acesso nominal e registado |

---

## 3. O que não detemos

Declarado expressamente por ser o núcleo do modelo de segurança:

| | Porquê |
|---|---|
| ❌ Chaves privadas de utilizadores | Geradas e guardadas no dispositivo |
| ❌ Conteúdo de mensagens | Cifrado no cliente, antes de sair |
| ❌ Histórico de navegação | Não é recolhido |
| ❌ Consultas de pesquisa | Não são registadas |
| ❌ IP de utilizadores do browser | Não é registado |

**Consequência deliberada:** não conseguimos entregar o que nos for pedido sobre
estes itens, nem por ordem judicial, nem por comprometimento dos nossos sistemas,
nem por erro nosso.

---

## 4. Segurança do desenvolvimento

### 4.1 Código

| Controlo | Regra |
|---|---|
| Revisão por pares | Obrigatória antes de integração |
| Núcleo criptográfico | **Mínimo duas pessoas**, uma delas o CTO |
| Ramo principal | Protegido; sem escrita direta |
| Dependências | Fixadas por versão e verificadas por integridade |
| Análise automática | Executada em cada alteração |
| Segredos no repositório | **Proibidos**, com verificação automática |

### 4.2 Regras sobre dependências

Três regras, que existem porque a alternativa é entregar o produto a terceiros:

1. **Nenhuma dependência de execução carregada a partir de CDN externa em código
   que manipule material criptográfico ou conteúdo de utilizadores.** As
   bibliotecas são incluídas no pacote da aplicação.
2. Versões **fixadas exatamente**, nunca por intervalo.
3. Alteração de dependência exige revisão como qualquer outra alteração de
   código.

> **Estado:** esta regra está em implementação. As aplicações carregam
> atualmente bibliotecas de terceiros a partir de CDN pública sem verificação de
> integridade, o que é incompatível com esta política. Item prioritário do plano
> de robustecimento (§8).

### 4.3 Criptografia

| Regra | |
|---|---|
| Não implementar primitivas próprias | Usar bibliotecas estabelecidas e auditadas |
| Algoritmos aprovados | Kyber-1024, X25519, Ed25519, ChaCha20-Poly1305, AES-256-GCM, BLAKE3, SHA-256, Argon2id |
| Proibidos | MD5, SHA-1, DES, 3DES, RC4, AES-ECB |
| Aleatoriedade | Apenas geradores criptográficos (`getRandomValues`, `OsRng`) |
| Derivação de palavra-passe | **Argon2id** com sal único por utilizador ou contexto |
| Material de chave em memória | Apagado após uso (*zeroize*) |

---

## 5. Segurança operacional

### 5.1 Acesso

| Controlo | Regra |
|---|---|
| Autenticação multifator | **Obrigatória** em todos os sistemas |
| Gestor de palavras-passe | Obrigatório; sem partilha por canais de texto |
| Privilégio mínimo | Acesso apenas ao necessário para a função |
| Revisão de acessos | Trimestral |
| Revogação na saída | **No próprio dia** |
| Chaves de assinatura de versões | Em módulo de hardware ou equivalente |

### 5.2 Equipamentos

- Cifra de disco obrigatória
- Bloqueio automático em 5 minutos
- Atualizações de segurança em 7 dias
- Sem dados de clientes em equipamento pessoal
- Comunicação de perda ou furto **imediata**

### 5.3 Infraestrutura

| Controlo | |
|---|---|
| Cifra em trânsito | TLS 1.3, HSTS |
| Cifra em repouso | Em todos os sistemas com dados de clientes |
| Cópias de segurança | Diárias, cifradas, **com restauro testado trimestralmente** |
| Registo de acessos administrativos | Retido 12 meses |
| Correção de vulnerabilidades | Críticas em 7 dias; altas em 30 |
| Separação de ambientes | Produção separada de desenvolvimento |

> Uma cópia de segurança cujo restauro nunca foi testado não é uma cópia de
> segurança — é uma suposição.

---

## 6. Divulgação responsável de vulnerabilidades

### 6.1 Como reportar

**security@hidranet.org** · Chave PGP publicada em `/.well-known/security.txt`

Inclua: descrição, passos de reprodução, impacto e, se possível, sugestão de
correção.

### 6.2 O nosso compromisso

| Prazo | Ação |
|---|---|
| 48 horas | Acusamos receção |
| 7 dias | Avaliação inicial e classificação |
| 90 dias | Correção ou justificação escrita do atraso |
| Na correção | Crédito público, salvo pedido de anonimato |

**Comprometemo-nos a:**
- Não tomar medidas legais contra quem investigue de boa-fé e respeite estas
  regras
- Manter o investigador informado do progresso
- Publicar a vulnerabilidade após a correção

**Pedimos que:**
- Não aceda a dados de terceiros nem os altere
- Não degrade o serviço
- Dê-nos prazo razoável antes de divulgar

Decorridos 90 dias sem correção, a divulgação coordenada por parte do
investigador é legítima e não a contestaremos.

### 6.3 Âmbito

**Dentro:** hidranet.org, HidraNet Browser, hidra-node, aplicações, API.
**Fora:** serviços de terceiros, engenharia social sobre colaboradores,
ataques físicos, negação de serviço por volume.

---

## 7. Registo público de limitações conhecidas

**Mantemos um registo público de limitações de segurança conhecidas e do
respetivo estado de correção.**

É pouco habitual e é deliberado. Numa ferramenta de segurança, a pergunta
relevante não é "há vulnerabilidades?" — há sempre. É **"quem as procura e o que
acontece quando são encontradas?"**. Um projeto sem registo de limitações está a
dizer que não procura.

O registo distingue:
- **Limitações inerentes** — do modelo de ameaça, não corrigíveis (ex.: um
  adversário com observação global da rede derrota qualquer rede de baixa
  latência)
- **Limitações em correção** — com prazo
- **Corrigidas** — com data e versão

---

## 8. Plano de robustecimento

Público, porque a credibilidade mede-se pelo que se promete corrigir e cumpre.

| # | Item | Prioridade | Estado |
|---|---|---|---|
| 1 | Bloqueio de tráfego não-loopback até a camada de anonimato estar pronta | Crítica | Em curso |
| 2 | Bibliotecas de terceiros incluídas localmente, com integridade verificada | Crítica | Planeado |
| 3 | Cifra em repouso do material de chave no dispositivo | Crítica | Planeado |
| 4 | Autenticação do remetente no HidraMail | Alta | Planeado |
| 5 | Bloqueio de WebRTC ao nível da rede | Alta | Planeado |
| 6 | Infraestrutura própria de transporte de mensagens | Alta | Planeado |
| 7 | Injeção do perfil no arranque do documento, em todos os quadros | Alta | Planeado |
| 8 | Argon2id com sal por contexto no HidraChat | Média | Planeado |
| 9 | **Auditoria de segurança externa independente** | Alta | Planeado |

**O item 9 é condição para divulgação pública ampla do browser.** Não anunciamos
uma ferramenta de privacidade a um público alargado antes de alguém de fora a
ter tentado partir e termos publicado o resultado.

---

## 9. Formação

| Quando | Conteúdo |
|---|---|
| À entrada | Esta política, classificação, gestor de palavras-passe, MFA |
| Trimestral | Ameaças atuais, casos reais |
| Anual | Revisão completa e simulação de *phishing* |

---

## 10. Incumprimento

O incumprimento desta política é tratado como questão disciplinar, podendo
implicar cessação do vínculo e, havendo ilícito, comunicação às autoridades.

**Comunicar um erro próprio nunca é sancionado.** Um incidente comunicado em 10
minutos é gerível; um escondido durante uma semana pode não ser. Queremos que a
equipa comunique cedo, e isso exige que comunicar não tenha custo.

---

## 11. Documentos relacionados

- Plano de Resposta a Incidentes (documento 15)
- Política de Privacidade (documento 04)
- Whitepaper, secção 5 — modelo de ameaça
- `/.well-known/security.txt`

---

**security@hidranet.org** · Revisão anual · Aprovada por: CTO
