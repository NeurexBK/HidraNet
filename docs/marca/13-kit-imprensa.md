# Kit de Imprensa — HidraNet

**Atualizado: Setembro 2026** · https://hidranet.org/imprensa
Contacto: **imprensa@hidranet.org**

---

## 1. Descrições — use a que couber

### Uma linha (90 caracteres)
> HidraNet: rede descentralizada de código aberto com criptografia pós-quântica.

### Curta (280 caracteres)
> A HidraNet é uma rede descentralizada de código aberto com criptografia
> pós-quântica. Browser, chat, correio, pesquisa e sites — privados por desenho.
> Se não conseguirmos confirmar que está anónimo, dizemos-lhe.

### Média (parágrafo)
> A HidraNet é uma rede sobreposta de código aberto que combina encaminhamento
> em cebola com criptografia resistente a computação quântica (CRYSTALS-Kyber-1024).
> Inclui um browser com isolamento por separador e proteção contra impressão
> digital, e aplicações de mensagens, correio, pesquisa, fórum e publicação de
> sites — todas cifradas no dispositivo do utilizador. Fundada em Lisboa por
> João Brandão e Leonardo Mello, é distribuída sob licença MIT.

### Longa (institucional)
> A HidraNet é um projeto de código aberto que constrói infraestrutura de
> comunicação privada. A rede combina encaminhamento em cebola — em que o
> tráfego atravessa vários nós e nenhum conhece simultaneamente a origem e o
> destino — com CRYSTALS-Kyber-1024, o algoritmo de encapsulamento de chaves
> padronizado pelo NIST para resistir a criptanálise por computador quântico.
>
> Sobre essa base correm aplicações que cifram no dispositivo do utilizador:
> HidraChat, HidraMail com endereços auto-certificáveis, um fórum, meta-pesquisa
> sem registo de consultas, e SevenNine, para publicar sites alcançáveis sem
> revelar onde estão alojados.
>
> O HidraNet Browser atribui a cada separador uma sessão isolada e um perfil de
> impressão digital próprio, e verifica o endereço de saída contra o verificador
> independente do Tor Project — informando o utilizador quando **não** consegue
> confirmar, em vez de afirmar um anonimato não verificado.
>
> O software é distribuído sob licença MIT. A empresa desenvolve software e
> presta serviços; a rede é operada por participantes independentes.
>
> Fundada em 2026 em Lisboa, Portugal, por João Brandão e Leonardo Mello.

---

## 2. Dados de referência

| | |
|---|---|
| Fundação | 2026 |
| Sede | Lisboa, Portugal |
| Fundadores | João Brandão, Leonardo Mello |
| Licença | MIT |
| Repositório | github.com/NeurexBK/HidraNet |
| Site | hidranet.org |
| Plataformas | Windows, macOS, Linux |
| Motor | Rust · ~17.000 linhas |
| Criptografia | Kyber-1024, X25519, Ed25519, ChaCha20-Poly1305, AES-256-GCM, BLAKE3, Argon2 |

---

## 3. O que torna a HidraNet noticiável

Três ângulos, com o enquadramento honesto de cada um.

### 3.1 Pós-quântico já implementado

A HidraNet usa **CRYSTALS-Kyber-1024** em produção. Responde ao ataque
*harvest now, decrypt later*: tráfego capturado hoje e guardado fica ilegível
quando existir um computador quântico criptograficamente relevante.

*Enquadramento:* a maioria das ferramentas de privacidade está ainda em
transição para pós-quântico.

### 3.2 Anonimato verificado, não afirmado

O browser consulta o verificador do Tor Project e, **quando não consegue
confirmar, di-lo ao utilizador**.

*Porque é invulgar:* o padrão da indústria é mostrar "ligado" e deixar o
utilizador presumir o resto. É uma decisão de produto que troca aparência por
honestidade.

### 3.3 Construído em Portugal, em português

Infraestrutura de privacidade desenvolvida em Lisboa, com produto pensado de
origem para o mercado lusófono — não uma tradução.

---

## 4. Factos que pedimos que verifique connosco

Para evitar imprecisões que depois circulam:

| Afirmação | Correção |
|---|---|
| "A HidraNet substitui o Tor" | **Não.** O browser usa o Tor como camada de saída. O protocolo HidraNet está implementado; a sua população de relays está em construção. |
| "Anonimato total" | Nenhuma ferramenta o oferece. O nosso modelo de ameaça indica expressamente contra o que **não** protege. |
| "Rede para a dark web" | A HidraNet é ferramenta de privacidade para uso comum. A Política de Uso Aceitável proíbe atividade ilícita. |
| "Impossível de intercetar" | Dificulta muito a interceção. Um adversário com observação global da rede derrota qualquer rede de baixa latência, incluindo o Tor. |

**Preferimos uma peça rigorosa a uma peça favorável.** Se precisar de
confirmação técnica antes de publicar, escreva-nos — respondemos depressa e sem
pedir aprovação prévia do texto.

---

## 5. Citações atribuíveis

**Sobre o propósito:**
> "A privacidade não devia exigir conhecimentos técnicos. Uma pessoa não precisa
> de perceber de criptografia para merecer que as suas conversas sejam só suas."
> — [Fundador], HidraNet

**Sobre pós-quântico:**
> "Quem captura tráfego hoje não precisa de o conseguir ler hoje. Basta guardá-lo.
> É por isso que a resistência quântica tem de existir antes de ser urgente, e
> não depois."
> — [Fundador], HidraNet

**Sobre verificação:**
> "Preferimos dizer a alguém que não conseguimos confirmar o anonimato a
> deixá-lo assumir que está protegido. Numa ferramenta de privacidade, uma
> afirmação não verificada é pior do que nenhuma afirmação."
> — [Fundador], HidraNet

**Sobre código aberto:**
> "Ninguém deve ter de confiar na nossa palavra. O código está publicado —
> leiam-no, e digam-nos onde erramos."
> — [Fundador], HidraNet

*Atribuir ao fundador correto conforme a área. Para entrevista, contactar
imprensa@hidranet.org.*

---

## 6. Recursos visuais

Descarregáveis em https://hidranet.org/imprensa

| Recurso | Formato |
|---|---|
| Logótipo principal | SVG, PNG (transparente) |
| Símbolo isolado | SVG, PNG |
| Capturas do browser | PNG, 2560×1600 |
| Capturas das aplicações | PNG |
| Fotografias dos fundadores | JPG, alta resolução |
| Diagrama de arquitetura | SVG, PNG |
| Paleta de cores | Ver Manual de Marca |

**Uso:** os logótipos podem ser usados para ilustrar conteúdo **sobre** a
HidraNet, sem autorização prévia. Não alterar cores nem proporções — ver Manual
de Marca, secção 5.4.

---

## 7. Perguntas frequentes de jornalistas

**Quantos utilizadores têm?**
Não conseguimos saber, e é intencional: não há telemetria. Podemos indicar
números de descargas.

**Como ganham dinheiro?**
Serviços para empresas (HidraReview), subscrições e subvenções para
desenvolvimento de código aberto. **Não vendemos dados.** Não faz parte do
modelo — é incompatível com a arquitetura.

**Como impedem o uso indevido?**
Com honestidade sobre os limites: não conseguimos ler conteúdo cifrado nem
remover conteúdo de nós que não operamos. Conseguimos suspender contas dos
serviços que operamos e cooperar com autoridades nos limites do que possuímos —
que é pouco, por desenho. É a contrapartida inevitável de qualquer ferramenta de
privacidade, e assumimo-la.

**Já foram auditados?**
Ainda não por entidade externa independente. Está planeada uma auditoria e o
relatório será publicado, qualquer que seja o resultado. Até lá, não afirmamos
garantias que não foram verificadas por terceiros.

**Recebem financiamento?**
[Atualizar conforme o estado.] Procuramos ativamente financiamento não-diluidor
para a camada de protocolo, por ser código aberto e bem comum.

**Posso falar com um fundador?**
Sim. **imprensa@hidranet.org** — respondemos em 48 horas.

---

## 8. Contactos

| Assunto | Endereço |
|---|---|
| Imprensa e entrevistas | imprensa@hidranet.org |
| Questões técnicas | tech@hidranet.org |
| Segurança | security@hidranet.org |
| Geral | contact@hidranet.org |

**Tempo de resposta:** 48 horas em dias úteis. Se tiver fecho de edição, indique
o prazo no assunto — damos prioridade.
