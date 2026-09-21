# Manual de Marca — HidraNet

**Versão 1.0 · Setembro 2026**

---

## 1. ⚠️ Problema a resolver primeiro

**A HidraNet tem hoje duas identidades visuais diferentes.**

| Superfície | Cor principal | |
|---|---|---|
| Site institucional | `#00ff88` verde neon + `#00ccff` ciano | Fundo `#070809` |
| Browser e aplicações | `#00d4aa` teal | Fundo `#06070d` |

São marcas distintas. Quem chega pelo site e instala a aplicação vê dois
produtos.

### Decisão

**Adotar `#00d4aa` (teal) como cor principal da marca.**

Fundamento:
1. É usada de forma consistente nas **oito interfaces** do produto — mudar o
   site é alterar uma página; mudar o produto é alterar oito.
2. O teal distingue-se melhor: verde neon sobre preto é a convenção visual de
   "hacker" usada por dezenas de projetos.
3. Verificada em acessibilidade (secção 3.3).

**Ação:** alinhar o site institucional com a paleta do produto.

---

## 2. A marca

### 2.1 Nome

**HidraNet** — uma palavra, H e N maiúsculos. Nunca "Hidra Net", "HIDRANET" ou
"hidranet" em texto corrido (o domínio em minúsculas é aceitável).

Produtos: **HidraNet Browser**, **HidraChat**, **HidraMail**, **HidraSearch**,
**HidraReview**, **SevenNine**.

### 2.2 Origem

Da Hidra: corte uma cabeça, nascem duas. É o comportamento de uma rede
descentralizada — remover um nó não a interrompe; a rede reencaminha e continua.

### 2.3 Posicionamento

> Privacidade que se verifica.

---

## 3. Cores

### 3.1 Principais

| Cor | Hex | RGB | Uso |
|---|---|---|---|
| **Hidra Teal** | `#00d4aa` | 0, 212, 170 | Cor da marca, ações principais, destaques |
| **Teal Escuro** | `#00a888` | 0, 168, 136 | Estados de interação, gradientes |
| **Fundo** | `#06070d` | 6, 7, 13 | Fundo principal |
| **Fundo 2** | `#0b0d16` | 11, 13, 22 | Fundo elevado |

### 3.2 Secundárias

| Cor | Hex | Uso |
|---|---|---|
| Cartão | `#10131f` | Superfícies |
| Cartão 2 | `#161a2b` | Superfícies elevadas |
| Contorno | `#1c2133` | Separadores |
| Texto principal | `#e9ecf5` | Corpo de texto |
| Texto secundário | `#9aa3bd` | Texto de apoio |
| Texto terciário | `#5b6480` | Ver aviso em 3.3 |
| Azul | `#4f8cff` | Ligações, informação |
| Aviso | `#f5a623` | Alertas |
| Perigo | `#ff5c6c` | Erros, ações destrutivas |

### 3.3 Acessibilidade — valores verificados

Rácios de contraste WCAG 2.1, calculados:

| Combinação | Rácio | Nível |
|---|---|---|
| Teal `#00d4aa` sobre fundo `#06070d` | **10,53:1** | ✅ AAA |
| Texto principal `#e9ecf5` sobre fundo | **17,03:1** | ✅ AAA |
| Texto secundário `#9aa3bd` sobre fundo | **8,00:1** | ✅ AAA |
| Texto terciário `#5b6480` sobre fundo | **3,43:1** | ⚠️ apenas AA-grande |
| **Teal `#00d4aa` sobre branco** | **1,91:1** | ❌ **FALHA** |

**Duas regras que decorrem destes números:**

1. **O texto terciário `#5b6480` só pode ser usado a 18px ou mais** (ou 14px a
   negrito). Abaixo disso não cumpre o mínimo de 4,5:1 e é ilegível para uma
   parte dos utilizadores. Para texto pequeno de apoio, use `#9aa3bd`.

2. **Nunca use teal sobre branco.** Falha com larga margem. Em fundos claros —
   impressão, documentos, apresentações — use **`#00695c`** (teal escurecido,
   ~7:1 sobre branco) ou o fundo escuro da marca.

---

## 4. Tipografia

### 4.1 Famílias

| Uso | Fonte | Alternativa |
|---|---|---|
| Títulos e interface | **Inter** | -apple-system, Segoe UI, Roboto, sans-serif |
| Monoespaçada | **JetBrains Mono** | SF Mono, Consolas, monospace |

Ambas são livres e podem ser incorporadas nos produtos.

### 4.2 Escala

| Nível | Tamanho | Peso | Entrelinha |
|---|---|---|---|
| H1 | 40 px | 800 | 1,15 |
| H2 | 30 px | 700 | 1,2 |
| H3 | 22 px | 700 | 1,3 |
| H4 | 18 px | 600 | 1,4 |
| Corpo | 16 px | 400 | 1,6 |
| Pequeno | 14 px | 400 | 1,5 |
| Legenda | 12 px | 500 | 1,4 |

### 4.3 Uso da monoespaçada

Reservada para: endereços `.hidra` e `@hidra`, chaves, somas de verificação,
comandos e código. **Nunca para texto corrido.**

---

## 5. Logótipo

### 5.1 Variantes

| Variante | Uso |
|---|---|
| Principal | Fundo escuro — uso preferencial |
| Monocromática clara | Fundo escuro com restrições |
| Monocromática escura | Fundo claro, impressão |
| Símbolo isolado | Ícone de aplicação, avatar, favicon |

### 5.2 Área de proteção

Margem mínima em torno do logótipo igual à **altura do "H"**. Nada — texto,
imagem ou contorno — entra nessa área.

### 5.3 Dimensão mínima

| Meio | Mínimo |
|---|---|
| Ecrã, logótipo completo | 120 px de largura |
| Ecrã, símbolo | 24 × 24 px |
| Impressão, logótipo | 25 mm |

### 5.4 Usos proibidos

| ❌ |
|---|
| Alterar as cores |
| Distorcer, esticar ou comprimir |
| Rodar |
| Aplicar sombras, contornos ou efeitos |
| Colocar sobre fundo de contraste insuficiente |
| Colocar sobre fotografia sem área de proteção |
| Recriar com outra fonte |
| Alterar as proporções entre símbolo e texto |

---

## 6. Uso da marca por terceiros

**Importante:** o software é MIT; **as marcas não são**.

### 6.1 Permitido, sem autorização

- Referir a HidraNet em artigos, análises e conteúdos
- Indicar que um projeto é compatível com a HidraNet
- Usar os logótipos para ilustrar conteúdo **sobre** a HidraNet
- Embaixadores: usar os materiais fornecidos, nos termos do programa

### 6.2 Requer autorização escrita

- Usar "Hidra" ou "HidraNet" no nome de um produto ou empresa
- Registar domínios com a marca
- Merchandise para venda
- Sugerir patrocínio, parceria ou aprovação inexistentes

### 6.3 Proibido

- Usar a marca numa **bifurcação modificada** do software, de forma que possa
  confundir os utilizadores quanto à origem

> **Regra sobre bifurcações, e a razão de ser.** Bifurcar o código é um direito
> conferido pela licença MIT, e não só o respeitamos como o incentivamos. Mas
> uma versão modificada que se apresente como "HidraNet" pode enganar alguém
> quanto às garantias de segurança que está a obter. Numa ferramenta de
> privacidade, isso tem consequências reais para quem confia no nome.
>
> Bifurque à vontade — dê-lhe outro nome.

Pedidos: **marca@hidranet.org**

---

## 7. Tom de voz

### 7.1 Princípios

| Somos | Não somos |
|---|---|
| Diretos | Sensacionalistas |
| Técnicos quando é preciso | Obscuros |
| Honestos sobre limitações | Alarmistas |
| Sóbrios | Solenes |
| Úteis | Condescendentes |

### 7.2 A regra principal: nunca prometer mais do que se entrega

É a característica que define a comunicação da HidraNet.

| ❌ Não escrever | ✅ Escrever |
|---|---|
| "100% anónimo" | "Esconde o seu IP dos sites que visita" |
| "Impossível de rastrear" | "Dificulta muito o rastreio — veja o modelo de ameaça" |
| "Segurança militar" | "Kyber-1024, resistente a computação quântica" |
| "Ninguém o pode parar" | "A rede é descentralizada: não há um ponto único de falha" |
| "Melhor que o Tor" | "Diferente do Tor: traz aplicações integradas" |

**Porquê.** Se alguém confiar numa promessa exagerada e sofrer consequências
reais, a responsabilidade é de quem exagerou. Numa ferramenta de privacidade, o
marketing excessivo pode ter custo humano. **Subprometer é política, não
modéstia.**

### 7.3 Neutralidade

A HidraNet é uma ferramenta técnica. A comunicação **não** entra em confronto
político nem se posiciona contra governos ou instituições.

Defendemos a privacidade em termos **técnicos e jurídicos** — é um direito
reconhecido no artigo 12.º da Declaração Universal dos Direitos Humanos. Não
precisamos de mais do que isso.

| ❌ | ✅ |
|---|---|
| "Contra a vigilância dos governos" | "Privacidade é um direito reconhecido" |
| "Escape ao controlo do Estado" | "As suas comunicações são só suas" |
| "Eles estão a observá-lo" | "Menos gente a observar do que imagina" |

### 7.4 Exemplos

**Descrição curta (280 caracteres):**
> A HidraNet é uma rede descentralizada de código aberto com criptografia
> pós-quântica. Browser, chat, correio, pesquisa e sites — privados por desenho.
> Se não conseguirmos confirmar que está anónimo, dizemos-lhe.

**Aviso de erro:**
> Não foi possível confirmar o seu IP de saída. A ligação está ativa, mas a
> verificação independente falhou. Não trate esta sessão como anónima até
> confirmar.

*(Diz o que aconteceu, o que significa, e o que fazer. Sem culpar o utilizador,
sem minimizar.)*

---

## 8. Ficheiros

| Recurso | Local |
|---|---|
| Logótipos (SVG, PNG) | `/brand/logo/` |
| Fontes | Inter e JetBrains Mono — Google Fonts |
| Paleta (CSS, Figma) | `/brand/colors/` |
| Kit de imprensa | https://hidranet.org/imprensa |

### Variáveis CSS

```css
:root {
  --hidra-teal:      #00d4aa;
  --hidra-teal-dark: #00a888;
  --hidra-teal-print:#00695c; /* fundos claros — ver §3.3 */

  --bg:        #06070d;
  --bg-2:      #0b0d16;
  --card:      #10131f;
  --card-2:    #161a2b;
  --border:    #1c2133;

  --text:      #e9ecf5;
  --text-2:    #9aa3bd;
  --text-3:    #5b6480; /* mínimo 18px — ver §3.3 */

  --blue:      #4f8cff;
  --warning:   #f5a623;
  --danger:    #ff5c6c;
}
```

---

📧 **marca@hidranet.org**
