# 05 — Concorrência

## 1. Mercado A — Rede de anonimato e browser

| | Tor Browser | Brave | Mullvad Browser | Proton | **HidraNet** |
|---|---|---|---|---|---|
| Preço | Grátis | Grátis | Grátis | Freemium | Freemium |
| Base | Firefox ESR | Chromium | Firefox ESR | — | **Electron** |
| Utilizadores | 2–2,5 M/dia (rede) | **100 M MAU** | — | — | Pré-lançamento |
| Receita | Donativos/subvenções | **>100 M$ ARR** | Subscrição fixa | **97,5 M$ ARR** | 0 |
| Pós-quântico | Em transição | Não | Não | Parcial | **✅ Kyber1024** |
| Apps integradas | Não | Carteira, VPN | Não | Mail, VPN, Drive, Docs | **Chat, Mail, Pesquisa, Fórum, Reviews** |
| Fingerprint | Uniformização | Aleatorização | Uniformização | — | **Aleatorização por separador** |
| Anonimato verificado ao utilizador | Não | N/A | Não | N/A | **✅** |

### Onde realisticamente ganhamos

1. **Pós-quântico já em produção.** Kyber1024 no núcleo. Nenhum dos outros tem.
   Argumento forte para subvenções e para utilizadores técnicos.
2. **Anonimato verificado, não afirmado.** O browser confirma o IP de saída
   contra o verificador do Tor Project e, se não conseguir, diz-o. Nenhum
   concorrente faz isto. É honestidade como funcionalidade.
3. **Aplicações na rede.** O Tor Browser é um browser. Nós trazemos pesquisa,
   correio, chat, fórum e reviews.
4. **Português nativo, mercado lusófono.** O Tor Browser em PT é uma tradução;
   a HidraNet é construída aqui, com o HidraReview desenhado para o comércio
   local português e brasileiro. É um nicho defensável e é onde está a venda.

### Onde perdemos, e é preciso assumir

1. **Anos de auditoria de segurança.** O Tor Browser tem uma década de revisão
   por pares. Nós não. Numa área onde uma falha é catastrófica, isto é o maior
   fosso deles.
2. **Electron.** Desempenho e superfície de ataque piores que um fork do Firefox.
3. **A rede de anonimato é a do Tor.** Ver
   [03, secção 4](03-produto-e-tecnologia.md). Temos protocolo próprio, não temos
   voluntários. Dizer o contrário a um investidor é insustentável.
4. **Distribuição.** O Brave tem 100 M de utilizadores. Nós temos uma landing page.

> **Conclusão para o deck:** *não competimos de frente com o Tor Browser.*
> Quem quer anonimato máximo deve usar o Tor Browser e nós devemos dizê-lo. Nós
> competimos por quem quer privacidade **com serviços úteis em cima**, em
> português, e por quem nos chega através do HidraReview.

---

## 2. Mercado B — HidraReview (é aqui que a batalha importa)

| | Google Business Profile | Trustpilot | Cartões NFC genéricos | Birdeye / Podium | **HidraReview** |
|---|---|---|---|---|---|
| Preço | Grátis | ~50–250 €/mês | 15–30 € (sem software) | 200–400 €/mês | **0–49 €/mês** |
| Dono dos dados | Google | Trustpilot | — | Plataforma | **Estabelecimento** |
| NFC incluído | Não | Não | Só hardware | Add-on | **✅** |
| PT/BR nativo | Parcial | Parcial | — | Não | **✅** |
| Alvo | Todos | Médias/grandes | Micro | Médias | **Micro e pequenas** |

### A leitura honesta deste quadro

**O concorrente real é o Google Business Profile, e é gratuito.** Nenhum
estabelecimento vai substituir o Google por nós — as pessoas procuram no Google.

**Por isso a proposta não pode ser "substitui o Google".** Tem de ser:

> *"Ajudamos-te a ter mais avaliações — no Google e na tua própria página, que
> é tua e não do Google. O cartão NFC converte 60–80% contra 35–50% do QR code.
> E a tua página não desaparece se o Google mudar de ideias."*

Ou seja: **complementar ao Google no topo do funil, alternativa na propriedade
dos dados.** É uma posição vendável. "Alternativa ao Google" não é.

**Onde ganhamos ao Birdeye/Podium:** preço. Eles vendem a 200–400 €/mês a
cadeias médias. O café da esquina nunca foi cliente deles. É o nosso mercado.

**Onde ganhamos aos cartões NFC genéricos:** eles vendem plástico sem software.
Nós vendemos o painel, o aviso ao dono, a página e a recorrência.

**Onde estamos fracos:** somos dois fundadores sem força de vendas, a vender a
um cliente que exige venda presencial e tem churn alto. Ver
[06 — Go-to-Market](06-go-to-market.md).

---

## 3. Resposta às três objeções que um VC vai levantar

**"Porque é que o Tor Browser não faz isto amanhã?"**
Não faz. É uma organização sem fins lucrativos com mandato estreito e avessa a
âmbito comercial. Reviews de restaurantes está fora do que são. O risco real não
é o Tor — é um concorrente de reviews acrescentar privacidade, que é mais fácil
do que nós acrescentarmos escala.

**"Porque é que isto é uma empresa e não dois projetos?"**
Porque o HidraReview precisa de um diferenciador que o Birdeye não copie em três
meses, e a rede precisa de utilizadores reais. Cada um resolve o problema do
outro. A resposta completa está em [04, secção 5](04-modelo-de-negocio.md) — e
é preciso que o produto a torne verdadeira, não só o deck.

**"Dois fundadores, dois produtos, zero receita. Porquê agora?"**
Porque o contexto regulatório (Chat Control, ver [02](02-analise-mercado.md))
está a gerar procura por privacidade que o legislador não consegue travar, e
porque o dinheiro não-diluidor para a camada de protocolo está disponível agora
(NGI Zero, 21,6 M€ até 2027). O plano não pede a um VC que financie a rede —
pede que financie a distribuição do HidraReview, que já tem cliente que paga.
