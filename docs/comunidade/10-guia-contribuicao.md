# Guia de Contribuição — HidraNet

*Contributing Guide — English version in section 10*

Obrigado pelo interesse. Este guia diz-lhe como contribuir de forma que o seu
trabalho seja integrado depressa.

---

## 1. Antes de começar

| Quero… | Comece por… |
|---|---|
| Reportar um erro | §3 |
| **Reportar uma vulnerabilidade** | **§2 — não abra um issue público** |
| Propor funcionalidade | §4 |
| Submeter código | §5 |
| Traduzir | §7 |
| Operar um nó | Guia de Instalação |
| Melhorar documentação | §5 — é das contribuições mais úteis |

---

## 2. ⚠️ Vulnerabilidades de segurança

**Nunca reporte uma vulnerabilidade num issue público.**

📧 **security@hidranet.org** · Chave PGP em `/.well-known/security.txt`

Inclua descrição, passos de reprodução, impacto e, se possível, sugestão de
correção.

**O nosso compromisso:** resposta em 48h, avaliação em 7 dias, correção ou
justificação em 90 dias, crédito público na correção, e **nenhuma ação legal
contra investigação de boa-fé**. Detalhe na Política de Segurança da Informação.

---

## 3. Reportar um erro

Verifique primeiro se já existe um issue aberto sobre o mesmo.

```markdown
**Descrição**
O que acontece.

**Reproduzir**
1. …
2. …

**Esperado / Observado**
O que devia acontecer / o que aconteceu.

**Ambiente**
- Sistema operativo:
- Versão do HidraNet:
- Componente: browser / node / HidraMail / HidraChat / …

**Registos**
Se aplicável. ⚠️ REMOVA dados pessoais, endereços @hidra e chaves.
```

> **Aviso importante.** Antes de colar registos, remova endereços, IP e qualquer
> material de chave. Um registo colado num issue público fica indexado para
> sempre.

---

## 4. Propor funcionalidade

Abra um issue com o rótulo `enhancement`, explicando **o problema** antes da
solução. Propostas que descrevem a solução sem o problema são difíceis de
avaliar.

### Propostas que exigem RFC

Alterações estruturais exigem documento escrito e **7 dias** de discussão
pública:

- Alteração de protocolo que quebre compatibilidade
- Alteração de primitivas criptográficas
- Alteração que afete o modelo de ameaça
- Remoção de funcionalidade

---

## 5. Contribuir com código

### 5.1 Preparar o ambiente

```bash
git clone https://github.com/NeurexBK/HidraNet.git
cd HidraNet

# Motor (Rust ≥ 1.80)
cd hidra-node && cargo build && cargo test

# Browser (Node ≥ 20)
cd ../hidra-browser && npm install && npm run fetch-tor && npm start
```

### 5.2 Fluxo

```bash
git checkout -b fix/descricao-curta
# … alterações …
cd hidra-node && cargo fmt && cargo clippy -- -D warnings && cargo test
git commit -m "fix(onion): corrige fuga de circuito ao fechar"
git push -u origin fix/descricao-curta
```

### 5.3 Mensagens de commit

Formato *Conventional Commits*:

```
<tipo>(<âmbito>): <descrição no imperativo>

<corpo: porquê, não o quê — o diff já mostra o quê>
```

Tipos: `feat`, `fix`, `docs`, `refactor`, `test`, `perf`, `chore`, `security`.
Âmbitos: `onion`, `dht`, `relay`, `proxy`, `crypto`, `browser`, `mail`, `chat`,
`search`, `review`, `sevennine`.

**Boa mensagem:**
```
fix(browser): bloqueia trafego ate o Tor estar pronto

No arranque o primeiro separador era criado enquanto o Tor ainda
fazia bootstrap, e durante 20-40s o trafego saia pelo IP real
enquanto o painel mostrava "a iniciar". Inverte o default: bloqueado
ate confirmacao.
```

**Má mensagem:** `update code`, `fix bug`, `changes`.

### 5.4 Estilo

**Rust:** `cargo fmt`, `clippy` sem avisos, sem `unwrap()` em código de
produção (use `?` ou trate o erro), documentação em itens públicos.

**JavaScript:** 2 espaços, aspas simples, ponto e vírgula, `const`/`let`,
`async`/`await`.

**Comentários.** Escreva **porquê**, não o quê. O código já diz o quê. Um bom
comentário explica a razão de uma decisão não óbvia — especialmente quando
documenta um erro já cometido.

### 5.5 Testes

| Alteração | Exigência |
|---|---|
| Correção de erro | Teste que falha antes e passa depois |
| Funcionalidade | Testes das situações principais e limites |
| **Criptografia** | **Vetores de teste conhecidos** + revisão por duas pessoas |
| Documentação | Sem testes |

### 5.6 Revisão

| Tipo | Revisores |
|---|---|
| Documentação | 1 |
| Correção ou funcionalidade | 1 |
| **Criptografia ou protocolo** | **2, incluindo o CTO** |

Prazo habitual: 3 dias úteis para primeira resposta. Se passar uma semana sem
resposta, comente no PR — não é desinteresse, é falta de disponibilidade.

---

## 6. Regras não negociáveis

| Regra | Porquê |
|---|---|
| **Nenhuma telemetria ou análise que identifique utilizadores** | Contradiz a razão de existir do projeto |
| **Nenhuma dependência externa carregada em tempo de execução em código criptográfico** | Entrega o produto a um terceiro |
| **Nenhuma primitiva criptográfica implementada de raiz** | Use bibliotecas estabelecidas |
| **Nenhum registo de conteúdo de utilizador** | Nem para depuração |
| Dependências fixadas por versão exata | Reprodutibilidade e cadeia de distribuição |

Contribuições que violem estas regras são recusadas, independentemente da
qualidade técnica.

---

## 7. Traduções

O projeto é lusófono na origem e internacional na vocação. Traduções são
bem-vindas — prioridade para **inglês** e **espanhol**.

Ficheiros em `locales/`. Mantenha os termos técnicos consistentes; havendo
dúvida, abra um issue em vez de decidir sozinho.

---

## 8. Licença

Ao contribuir, aceita que a sua contribuição seja licenciada sob **MIT**, a
mesma licença do projeto.

Contribuições substanciais podem exigir **acordo de cessão de direitos (CLA)**.
Não é para nos apropriarmos do seu trabalho — é para que o projeto possa, se
necessário, alterar de licença ou defender-se juridicamente sem ter de localizar
centenas de contribuidores.

---

## 9. Comunidade

Aplica-se o **Código de Conduta** (documento 11) a todos os espaços do projeto.

| Canal | Uso |
|---|---|
| GitHub Issues | Erros e funcionalidades |
| GitHub Discussions | Perguntas e ideias |
| security@hidranet.org | Vulnerabilidades |
| conduct@hidranet.org | Violações do Código de Conduta |

---

## 10. Contributing (EN)

**Security vulnerabilities:** do **not** open a public issue. Email
**security@hidranet.org** (PGP key at `/.well-known/security.txt`). We respond
within 48h, assess within 7 days, fix or explain within 90 days, credit you
publicly, and **will not pursue legal action against good-faith research**.

**Setup:**
```bash
git clone https://github.com/NeurexBK/HidraNet.git
cd HidraNet/hidra-node && cargo build && cargo test
cd ../hidra-browser && npm install && npm run fetch-tor && npm start
```

**Workflow:** branch from `main`, use Conventional Commits, run `cargo fmt`,
`cargo clippy -- -D warnings` and `cargo test` before pushing, open a PR.

**Review:** 1 reviewer for docs and ordinary changes; **2 including the CTO for
cryptography or protocol changes**.

**Non-negotiable rules:** no user-identifying telemetry · no runtime external
dependencies in cryptographic code · no hand-rolled cryptographic primitives ·
no logging of user content · exact-pinned dependencies.

**License:** contributions are licensed under **MIT**. Substantial contributions
may require a CLA.

Issues and pull requests in English are welcome.
