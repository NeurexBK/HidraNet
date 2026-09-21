# Guia do Utilizador — HidraNet

---

## 1. Antes de começar: o que esta ferramenta faz e não faz

Ler isto poupa-lhe problemas.

**Faz:**
- Esconde o seu endereço IP dos sites que visita
- Cifra as suas mensagens e correio de modo que nem nós os conseguimos ler
- Impede que separadores diferentes sejam associados entre si
- Dificulta a identificação do seu equipamento por impressão digital

**Não faz:**
- Não o protege se iniciar sessão numa conta que o identifica
- Não o protege se o seu computador estiver comprometido
- Não o protege de um adversário que observe a internet inteira
- Não torna ilegal legal

**A regra que importa:** o anonimato quebra-se por aquilo que a pessoa faz, não
por falha da ferramenta. Iniciar sessão no seu email pessoal dentro do HidraNet
liga essa sessão a si — de forma permanente e irreversível.

---

## 2. Navegação

### O painel de estado

Ao abrir, o separador inicial mostra:

| Indicador | Significado |
|---|---|
| **A iniciar o Tor — N%** | A construir circuito. Aguarde. |
| **Conectado — a sair por `<IP>`** | Anónimo, IP de saída **verificado** |
| **Conectado, mas a verificação não confirmou** | Ligado, mas sem confirmação independente — não assuma anonimato |
| **Desconectado** | A navegação sai pelo seu próprio IP |

Esta distinção é deliberada. Preferimos dizer-lhe que não confirmámos a
dizer-lhe que está anónimo sem o ter verificado.

### Nova identidade

O botão **Trocar circuito** pede à rede um caminho novo, com outro nó de saída.
Use quando quiser separar uma atividade da anterior.

Notas honestas:
- A rede pode devolver o mesmo nó de saída. Quando isso acontece, o browser
  di-lo em vez de fingir que mudou.
- Pode demorar alguns segundos (a rede limita a frequência destes pedidos).
- **Não apaga o que já revelou.** Se iniciou sessão numa conta, trocar de
  circuito não desfaz essa associação.

### Separadores isolados

Cada separador é, para os sites, um visitante diferente: cookies, armazenamento
e impressão digital separados, apagados ao fechar.

**Consequência prática:** a sua sessão num site não passa de um separador para
outro. É intencional.

### Atalhos

| Atalho | Ação |
|---|---|
| `Ctrl/Cmd + T` | Novo separador |
| `Ctrl/Cmd + W` | Fechar separador |
| `Ctrl/Cmd + L` | Focar a barra de endereço |
| `Ctrl/Cmd + R` / `F5` | Recarregar |

---

## 3. HidraMail

Correio com endereços `@hidra`, cifrado ponta a ponta. Nem nós nem qualquer
intermediário conseguem ler o conteúdo.

### Criar endereço

Abra o HidraMail. É gerado automaticamente um endereço como:

```
k3mz7qp2vx@hidra
```

O endereço **deriva matematicamente da sua chave pública**. Ninguém pode
reclamar o seu endereço sem ter a sua chave.

### Vários endereços

Botão **⚙ → Gerar novo endereço anónimo**. Use endereços diferentes para
contextos diferentes — é a forma mais simples de os manter não associados.

Todos recebem em simultâneo; escolhe qual usa para enviar.

### Enviar

1. **Escrever**
2. Destinatário: `endereco@hidra`
3. Assunto e corpo
4. **Enviar 🔒**

Antes de enviar, o cliente verifica que a chave pública obtida corresponde ao
endereço de destino. Se não corresponder, recusa. Isto protege-o contra
substituição de chave.

> **O destinatário tem de ter aberto o HidraMail pelo menos uma vez**, para que
> a sua chave pública esteja publicada na rede. Caso contrário verá
> "endereço não encontrado".

### Limitações que deve conhecer

| Limitação | O que significa |
|---|---|
| **O remetente não é autenticado** | O campo "De" é uma afirmação não verificada. Pode receber correio que diz vir de um endereço e não vir. **Não confie no remetente para decisões importantes.** Correção prevista. |
| Deixe o HidraMail aberto para receber | As mensagens chegam enquanto a aplicação está aberta |
| Guardado neste dispositivo | Sem sincronização entre equipamentos |
| Máximo ~500 KB por mensagem | Sem anexos grandes |

### Cópia de segurança

O seu endereço e o correio vivem **neste dispositivo**. Se limpar os dados da
aplicação ou perder o computador, perde o endereço e o histórico. Não há
recuperação — não temos as suas chaves, por desenho.

---

## 4. HidraChat

Salas de conversa cifradas ponta a ponta.

### Entrar numa sala

1. Escolha um nome (não use o seu nome real)
2. Nome da sala
3. **Palavra-passe da sala** — é o que gera a chave de cifra

Todos os que entram com a mesma palavra-passe leem as mensagens. Quem não a
tiver vê apenas "mensagem cifrada".

### A palavra-passe é a segurança

- Escolha uma **frase longa e imprevisível** — não `123456`, não o nome da sala
- **Partilhe-a por um canal seguro**, nunca na própria sala
- Quem obtiver a palavra-passe lê tudo o que for enviado depois

O identificador técnico da sala também deriva da palavra-passe, por isso o
transporte não revela o nome da sala.

---

## 5. SevenNine — publicar um site `.hidra`

Publica um site alcançável na rede sem revelar onde está alojado.

1. No browser, abra o SevenNine
2. Crie as páginas no editor
3. **Publicar**
4. Recebe um endereço:

```
7k2mx9qpvz3nd8fw4h6j.hidra
```

O endereço deriva da chave do site. Guarde a chave: **sem ela não pode
atualizar nem recuperar o site.**

Para visitar, escreva o endereço `.hidra` na barra de endereço.

---

## 6. HidraSearch

Meta-pesquisa que consulta vários motores e devolve resultados sem registar as
suas consultas. Os pedidos saem pela rede, não pelo seu IP.

Pode fixar o idioma dos resultados nas preferências.

---

## 7. Boas práticas

### Faça

- ✅ Verifique o IP de saída antes de algo sensível
- ✅ Use endereços HidraMail diferentes para contextos diferentes
- ✅ Frases longas nas salas do HidraChat
- ✅ Mantenha o browser atualizado
- ✅ Guarde cópia das chaves dos sites que publicar

### Não faça

- ❌ **Não inicie sessão em contas pessoais** — é o erro que anula tudo o resto
- ❌ Não descarregue e abra ficheiros fora do browser (um PDF ou .doc pode
  contactar a internet diretamente, fora da rede, e revelar o seu IP)
- ❌ Não maximize a janela se se preocupa com a impressão digital (o tamanho da
  janela é um sinal)
- ❌ Não reutilize nomes de utilizador que já usa noutro lado
- ❌ Não assuma anonimato quando o painel diz que não confirmou

---

## 8. Perguntas frequentes

**A HidraNet consegue ler as minhas mensagens?**
Não. A cifra acontece no seu dispositivo, antes de a mensagem sair. Não temos as
chaves. Isto não é uma política que possamos mudar — é a arquitetura.

**É legal?**
Sim, nas jurisdições onde a HidraNet opera. Privacidade é um direito. A
Política de Uso Aceitável define o que não é permitido na rede.

**Porque é que é mais lento?**
O tráfego atravessa vários saltos, em pontos diferentes do mundo. É o custo do
anonimato, e é intrínseco.

**Perdi o meu endereço HidraMail. Recuperam-no?**
Não. Não temos as suas chaves. É a mesma propriedade que impede que alguém nos
obrigue a entregá-las.

**Substitui o Tor Browser?**
Não, e não dizemos que sim. Para o máximo de anonimato contra adversários com
muitos recursos, o Tor Browser tem uma década de auditoria que nós ainda não
temos. A HidraNet oferece privacidade com aplicações integradas — chat, correio,
pesquisa, sites — que o Tor Browser não tem.

**Posso ajudar?**
Sim: opere um nó (Guia de Instalação), contribua código (Guia de Contribuição)
ou divulgue (Programa de Embaixadores).
