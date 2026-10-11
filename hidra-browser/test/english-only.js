// The product ships in English. All of it.
//
// This has now regressed twice. The first pass translated the pages a reader
// opens and stopped there, so the SevenNine site builder, the analytics
// dashboard and every MQTT connection status stayed Portuguese — and because
// those strings live inside Rust string literals in hidra-node, a grep of the
// browser's HTML found nothing and the sweep looked finished. The second pass
// found them, and also found two things a reader skimming for accented
// characters slides straight past: strings translated word by word into
// neither language ("Text do button", "URL da image", "Title da secao", "Add
// blocks from the panel a esquerda"), and dates formatted with a 'pt-BR'
// locale under labels that had already been translated.
//
// So this is a lint rather than a running check, and it is deliberately a
// guard and not a proof. It cannot know English. It knows the accents, the
// Portuguese joining words a half-finished translation leaves behind, and the
// vocabulary that was actually in this codebase — which is enough to catch the
// next string being added, and that is the only thing a test can do here.

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..');

// Where user-visible text lives. hidra-node is in here because the engine
// serves the HidraMail, HidraChat, SevenNine and analytics pages itself, as
// HTML inside Rust string literals — the reason the first sweep missed them.
const TREES = [
  ['hidra-browser/src', /\.(html|js)$/],
  ['hidra-node/src', /\.rs$/],
  ['hidra-node/assets', /\.(html|js|css)$/],
  ['landing', /\.(html|js)$/],
];
const EXCLUDE = /node_modules|[/\\]vendor[/\\]|\.min\.(js|css)$/;

// ── What counts as Portuguese ─────────────────────────────────────────────

// Accented Latin letters, skipping U+00D7 and U+00F7: those are the
// multiplication and division signs, and the first is this codebase's close
// button.
const ACCENT = /[À-ÖØ-öø-ÿĀ-ſ]/;

// Joining words English never uses. `do` and `com` are left out on purpose —
// "do not" is English and ".com" is a hostname.
const JOINERS =
  /\b(?:em|da|dos|das|ao|aos|pelo|pela|uma|nas|nos|que|para|por|sem|mais|muito|todos|cada|isso|nao|seu|sua|este|esta|esse|essa|quando|onde|qual|quais|sobre|entre|ate)\b/i;

// An English noun joined to the next word by a Portuguese preposition, or the
// other way round. This is what word-by-word translation leaves behind, and
// `do` is exactly the preposition the rule above cannot look for on its own:
// "Text do button" and "Link de compra" read as neither language, and neither
// one has an accent or an obviously Portuguese word in it.
const NOUNS =
  'button|image|images|site|sites|page|pages|section|product|products|order|' +
  'user|users|plan|plans|item|items|link|links|text|title|name|price|card|' +
  'block|blocks|email|phone|address|date|summary|author|period|label|icon|' +
  'color|size|url|video|file|files|shop|post|posts|review|reviews';
const MIXED = new RegExp(
  `\\b(?:${NOUNS})\\s+(?:do|da|de|dos|das)\\b|` +
    `\\b(?:do|da|de|dos|das)\\s+(?:${NOUNS})\\b`,
  'i'
);

// The vocabulary this sweep actually found, in the app and in the engine. The
// closing boundary matters: without it `pagina` matches `pagination` and
// `tema` matches `template`.
const WORDS = new RegExp(
  '\\b(?:' +
    [
      'abaixo', 'acesse', 'acima', 'adicionar', 'alternar', 'apelido',
      'aparelho', 'baixe', 'cebola', 'consigo', 'consultar', 'carregue',
      'estabelecimento\\w*', 'funciona', 'instalad\\w*', 'levar',
      'roteamento',
      'cole', 'criador', 'anonim\\w*', 'aparencia', 'aguarde', 'arquivos?',
      'arredondada', 'ativos?', 'ativas?', 'avaliacoes', 'bloco', 'busc\\w*', 'carreg\\w*', 'carteira', 'categoria', 'celular', 'circuitos',
      'concluid\\w*', 'conect\\w*', 'confirmar',
      'configuracoes', 'conteudo', 'continuar', 'comprar', 'criando',
      'criptograf\\w*', 'desconect\\w*', 'descricao', 'descriptograf\\w*',
      'desativado', 'destacar', 'digitando', 'direita', 'divisor', 'elegante',
      'enviad\\w*', 'enviar', 'escolher', 'esquerda', 'excluir', 'falha',
      'fechar', 'fonte', 'formulario', 'galeria', 'habilitado', 'icone',
      'inativo', 'incluso', 'iniciando', 'inesperadamente', 'mensagens?',
      'encontrad\\w*', 'minhamarca', 'moderna', 'moeda', 'mundo', 'nada',
      'nativas', 'subindo', 'visita',
      'navegacao', 'nenhum\\w*', 'nivel',
      'laociano', 'oculto', 'oculta', 'ocupada', 'pachto', 'pagina',
      'usbeque', 'pesquisar', 'privacidade', 'prontos?',
      'publicament\\w*', 'publicand\\w*', 'publicar', 'receb\\w*',
      'reconectand\\w*', 'recursos?', 'relatorio', 'remover', 'rodape',
      'salvar', 'secao', 'seguranca', 'senha', 'servicos', 'subtitulo',
      'procura', 'tecnica', 'telefone', 'tema', 'titulo', 'trafego', 'usuarios?',
      'visitantes', 'visitas', 'voltar',
    ].join('|') +
    ')\\b',
  'i'
);

// A Portuguese locale formats dates and numbers in Portuguese however the text
// around them reads, so it is the same bug wearing a different hat.
const LOCALE = /\bpt[-_]BR\b|\bpt[-_]PT\b/;

// ── What is allowed, and why ──────────────────────────────────────────────

const ALLOW_LINE = [
  // Keys for data stored before the translation. The Portuguese is the old
  // value being migrated away from, not a label.
  /TYPE_LEGACY|CAT_LEGACY/,
  // A continuation line of such a map, which carries the pairs but not the
  // name.
  /^\s*(?:'[^']+':\s*'[A-Za-z][A-Za-z ]*',?\s*)+\}?;?\s*$/,
  // A table of locale-to-region codes, where 'dk-da' is Danish in Denmark
  // rather than a Portuguese word.
  /^\s*(?:'?[\w-]+'?:\s*'[a-z]{2}-[a-z]{2,3}',?\s*)+$/,
];

const ALLOW_WORD = [
  // \b does not fire after an accented letter, so this cannot use one.
  /caf[eé]s?/i,
  // The two roles in a Noise handshake are the initiator and the responder.
  /(?:from|the|a|as) responder/i,
];

// A locale code is not Portuguese text. Offering Portuguese as a search
// language, mapping a locale to a search engine's own region code, and listing
// one in a fingerprinting decoy profile are all things the product should do.
const ALLOW_LOCALE = [
  /<option value="pt-[A-Z]{2}"/,
  /'pt-[A-Z]{2}':\s*'/,
  /languages:\s*\[/,
];

// ── Pulling the displayed text out of a line ──────────────────────────────

// Quoted strings, and text between tags, with quotes paired by walking the
// line. A regex cannot do this part: one literal of a single character or of
// none ('✦', '') shifts every pair after it on the line, which silently
// hides the rest of the line from the scan. That is not hypothetical — it is
// how the first version of this scanner missed the SevenNine block defaults.
function displayed(line) {
  const out = [];
  let i = 0;
  while (i < line.length) {
    const c = line[i];
    if (c === "'" || c === '"' || c === '`') {
      let j = i + 1;
      while (j < line.length) {
        if (line[j] === '\\') {
          j += 2;
          continue;
        }
        if (line[j] === c) break;
        j++;
      }
      out.push(line.slice(i + 1, j));
      i = j + 1;
    } else if (c === '>') {
      const j = line.indexOf('<', i + 1);
      if (j === -1) break;
      out.push(line.slice(i + 1, j));
      i = j;
    } else {
      i++;
    }
  }
  return out;
}

// A comment is not shown to anyone, and one of them quotes a Portuguese string
// the product used to display, on purpose, to explain why it no longer does.
const isComment = (line) => /^(\/\/|\/\*|\*(?!\/))/.test(line.trim());

function sources() {
  const found = [];
  const walk = (dir, ext) => {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (EXCLUDE.test(full)) continue;
      if (e.isDirectory()) walk(full, ext);
      else if (ext.test(e.name)) found.push(full);
    }
  };
  for (const [rel, ext] of TREES) walk(path.join(ROOT, rel), ext);
  return found;
}

const files = sources();
if (files.length === 0) {
  console.log('FAIL  found no sources to scan');
  process.exit(1);
}

const offences = [];
for (const file of files) {
  const rel = path.relative(ROOT, file);
  fs.readFileSync(file, 'utf8')
    .split('\n')
    .forEach((line, n) => {
      if (ALLOW_LINE.some((rx) => rx.test(line))) return;
      if (isComment(line)) return;
      if (LOCALE.test(line) && !ALLOW_LOCALE.some((rx) => rx.test(line))) {
        offences.push(
          `${rel}:${n + 1}  a Portuguese locale: ${line.trim().slice(0, 90)}`
        );
        return;
      }
      for (const raw of displayed(line)) {
        const s = raw.trim();
        if (s.length < 3) continue;
        if (/^https?:|^\/\/|^#|^var\(/.test(s)) continue;
        let probe = s;
        for (const ok of ALLOW_WORD) probe = probe.replace(ok, ' ');
        if (
          ACCENT.test(probe) ||
          JOINERS.test(probe) ||
          MIXED.test(probe) ||
          WORDS.test(probe)
        ) {
          offences.push(`${rel}:${n + 1}  ${s.slice(0, 90)}`);
        }
      }
    });
}

console.log(`scanned ${files.length} files for text that is not English`);

if (offences.length) {
  const unique = [...new Set(offences)];
  console.log(`\nFAIL  ${unique.length} string(s) a user would see in Portuguese:\n`);
  for (const o of unique) console.log('  ' + o);
  console.log(
    '\nTranslate them. If one has to stay as it is — a key for data already ' +
      'stored in Portuguese, say — add it to the allow list in this test with ' +
      'the reason.'
  );
  process.exit(1);
}

console.log('every string a user sees is in English');
