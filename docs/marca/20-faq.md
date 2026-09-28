# Perguntas Frequentes — HidraNet

---

## Sobre o produto

**O que é a HidraNet?**
Uma rede descentralizada de código aberto e um conjunto de aplicações privadas:
browser, chat, correio, pesquisa, fórum e publicação de sites. O tráfego é
encaminhado por vários nós e cifrado com criptografia resistente a computação
quântica.

**É gratuito?**
O software é gratuito e de código aberto (MIT), e continuará a ser. Existem
serviços pagos para empresas (HidraReview) e uma subscrição opcional com
funcionalidades adicionais.

**Que sistemas suporta?**
Windows 10+, macOS 11+ e Linux de 64 bits.

**Preciso de saber alguma coisa de técnica?**
Não para usar. Descarrega, abre, e o browser trata do resto. Para operar um nó,
o Guia de Instalação leva-o passo a passo.

---

## Sobre privacidade

**A HidraNet consegue ler as minhas mensagens?**
Não. A cifra acontece no seu dispositivo, antes de a mensagem sair. Não temos as
chaves.

Não é uma política que possamos alterar — é a arquitetura. Se fôssemos obrigados
a entregar o conteúdo, não teríamos o que entregar.

**Que dados guardam sobre mim?**
Do browser: nada. Sem histórico, sem IP, sem consultas de pesquisa, sem
telemetria. Se for cliente do HidraReview, guardamos o email, os dados de
faturação e o conteúdo que publicar. Detalhe na Política de Privacidade.

**Vendem dados?**
Não, e nunca venderemos. Além de contradizer a razão de existir do projeto, não
temos o que vender.

**Sou realmente anónimo?**
**Não absolutamente, e nenhuma ferramenta o consegue.**

A HidraNet esconde o seu IP dos sites, cifra o conteúdo e dificulta muito a
associação entre as suas atividades.

Não o protege se iniciar sessão numa conta pessoal, se o computador estiver
comprometido, ou contra um adversário com capacidade de observar a internet
inteira. O Whitepaper, secção 5.2, indica expressamente contra o que **não**
protegemos.

**Como sei que estou protegido?**
O painel indica o IP de saída **verificado** contra o verificador do Tor Project.
Se não conseguirmos confirmar, o browser di-lo em vez de assumir.

**Qual é o maior erro que posso cometer?**
Iniciar sessão numa conta que o identifica — email pessoal, rede social. Liga
essa sessão a si de forma permanente, e nenhuma troca de circuito desfaz essa
associação.

---

## Comparações

**É melhor que uma VPN?**
Diferente. Uma VPN encaminha o tráfego por **um** servidor, que sabe quem é e o
que visita — tem de confiar no fornecedor. A HidraNet encaminha por **vários**
nós, e nenhum conhece as duas pontas. Não tem de confiar em nós.

**Em contrapartida:** é mais lenta e alguns sites bloqueiam nós de saída
conhecidos.

**É melhor que o Tor Browser?**
**Não dizemos que sim.**

Para o máximo de anonimato contra adversários com muitos recursos, **use o Tor
Browser** — tem uma década de auditoria por pares que nós ainda não temos.

A HidraNet oferece privacidade com aplicações integradas (chat, correio,
pesquisa, sites, reviews) que o Tor Browser não tem, e criptografia
pós-quântica, que o Tor ainda está a adotar.

São ferramentas diferentes. Dizer o contrário seria mau serviço a quem confia na
resposta.

**Em que difere do Brave?**
O Brave é um browser rápido com bloqueio de anúncios e um modelo de publicidade
próprio. A HidraNet é uma rede de anonimato com aplicações. O Brave tem 100
milhões de utilizadores e nós estamos a começar — mas o Brave não encaminha o
tráfego por vários nós nem tem criptografia pós-quântica.

**Porque é mais lento?**
O tráfego atravessa vários saltos, em pontos diferentes do mundo. É o custo
intrínseco do anonimato, não uma falha de implementação.

---

## Aplicações

**Como funciona o HidraMail?**
Recebe um endereço `@hidra` que deriva matematicamente da sua chave pública —
ninguém pode reclamá-lo sem ter a sua chave. As mensagens são cifradas no seu
dispositivo para a chave do destinatário.

**Perdi o meu endereço HidraMail. Recuperam-no?**
Não. Não temos as suas chaves — vivem no seu dispositivo. É a mesma propriedade
que impede que alguém nos obrigue a entregá-las.

Faça cópia de segurança.

**Posso confiar no remetente de um HidraMail?**
**Ainda não.** Atualmente o campo "De" é uma afirmação não verificada. Sabe que a
mensagem foi cifrada para si, mas não pode provar quem a enviou. A autenticação
do remetente por assinatura está no plano de robustecimento.

Até lá, **não tome decisões importantes com base no remetente**.

**Como funcionam as salas do HidraChat?**
A chave de cifra deriva da palavra-passe da sala. Quem tiver a palavra-passe lê;
quem não tiver vê "mensagem cifrada". Escolha uma frase longa e partilhe-a por
um canal seguro — nunca na própria sala.

**O que é o SevenNine?**
O construtor de sites `.hidra`. Publica um site alcançável na rede sem revelar
onde está alojado. Guarde a chave: sem ela não pode atualizá-lo.

---

## Legalidade e uso

**É legal usar a HidraNet?**
Sim. Privacidade é um direito reconhecido no artigo 12.º da Declaração Universal
dos Direitos Humanos e no artigo 8.º da Convenção Europeia dos Direitos Humanos.
Usar ferramentas de privacidade é legal nas jurisdições onde operamos.

**O que é proibido na rede?**
A Política de Uso Aceitável proíbe, entre outros: exploração de menores, ataques
a sistemas, distribuição de malware, fraude, spam e avaliações falsas.

**Como impedem o uso indevido?**
Com honestidade sobre os limites. **Não conseguimos** ler conteúdo cifrado nem
remover conteúdo de nós que não operamos. **Conseguimos** suspender contas dos
nossos serviços, remover conteúdo dos nossos servidores e cooperar com
autoridades nos limites do que possuímos.

É a contrapartida inevitável de qualquer ferramenta de privacidade: o que
protege o jornalista protege também quem abusa. Assumimo-lo em vez de o esconder.

**Como denuncio abuso?**
**abuse@hidranet.org**. Casos de abuso de menores: denuncie também à Polícia
Judiciária ou à INHOPE — não espere por nós.

---

## Projeto e empresa

**Quem está por trás?**
João Brandão e Leonardo Mello, em Lisboa, Portugal. A HidraNet, Lda desenvolve
software e presta serviços. **A empresa não opera nós de saída** — a rede é de
voluntários.

**Como ganham dinheiro?**
Serviços para empresas (HidraReview), subscrições opcionais, domínios `.hidra` e
subvenções para desenvolvimento de código aberto. Não vendemos dados.

**O código é mesmo aberto?**
Sim, licença MIT, em github.com/NeurexBK/HidraNet. Pode ler, auditar, modificar
e bifurcar.

**Já foram auditados?**
Ainda não por entidade externa independente. Está planeado, e o relatório será
publicado — qualquer que seja o resultado. Até lá, não afirmamos garantias
verificadas por terceiros.

**Como posso ajudar?**
Operar um nó (Guia de Instalação) · Contribuir código ou documentação (Guia de
Contribuição) · Traduzir · Divulgar (Programa de Embaixadores) · Reportar
problemas.

**Encontrei uma vulnerabilidade.**
**security@hidranet.org** — não abra um issue público. Respondemos em 48 horas,
creditamo-lo na correção, e **não tomamos medidas legais contra investigação de
boa-fé**.

---

## Problemas comuns

**O Tor não passa dos 0%.**
A sua rede pode estar a bloquear o Tor. Configure uma *bridge* nas definições.

**"A porta 8090 está ocupada."**
Há outra cópia do browser aberta. Feche-a e reinicie.

**Um site bloqueia-me.**
Alguns sites bloqueiam nós de saída conhecidos. Experimente **Trocar circuito**.

**O macOS diz que a aplicação está danificada.**
O download está bem. A app não é assinada pela Apple e, no Apple Silicon, o
macOS recusa código sem assinatura válida e chama-lhe "danificado". No Terminal,
na pasta extraída:

```bash
xattr -cr HidraNet.app
codesign --force --deep --sign - HidraNet.app
open HidraNet.app
```

A segunda ordem é a que resolve. O ZIP inclui `Start HidraNet.command`, que faz
isto por si.

**O macOS continua a bloquear.**
Em macOS 15 (Sequoia) e posterior, clique direito → Abrir já não funciona.
Vá a **Ajustes do Sistema → Privacidade e Segurança**, desça, e clique em
**Abrir Mesmo Assim**.

**Perdi tudo ao limpar os dados.**
Os endereços e mensagens vivem no seu dispositivo. Sem cópia de segurança, não
há recuperação — não temos as suas chaves.

---

## Contactos

| Assunto | Endereço |
|---|---|
| Geral | contact@hidranet.org |
| Segurança | security@hidranet.org |
| Privacidade | privacidade@hidranet.org |
| Abuso | abuse@hidranet.org |
| Imprensa | imprensa@hidranet.org |
| Embaixadores | embaixadores@hidranet.org |
