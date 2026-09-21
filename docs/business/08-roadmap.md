# 08 — Roadmap (24 meses)

Organizado por **desbloqueios**, não por funcionalidades. Cada trimestre existe
para remover um bloqueio específico ao trimestre seguinte.

---

## T1 — Tornar vendável e candidatável

| # | Trabalho | Desbloqueia |
|---|---|---|
| 1 | **Kill switch de rede** no browser ([03 §1.4](03-produto-e-tecnologia.md)) | Poder afirmar privacidade sem ressalvas |
| 2 | Corrigir fuga de WebRTC ao nível da rede (`setWebRTCIPHandlingPolicy`) | Idem — hoje só há uma proteção em JavaScript, contornável |
| 3 | Injetar o fingerprint no arranque do documento, não em `dom-ready` | Scripts no `<head>` leem hoje os valores reais |
| 4 | **Candidatura ao NGI Zero** | 5–50 k€ não-diluidores + auditoria |
| 5 | **HidraReview faturável**: multi-tenant, registo, pagamento | Poder cobrar |
| 6 | Separar `main.rs` (9.600 linhas) nos módulos já existentes | Due diligence técnica |
| 7 | Consulta jurídica + constituição da Lda | Tudo o resto |

**Fim do T1:** produto cobrável, candidatura submetida, empresa constituída.

---

## T2 — Provar que alguém paga

| # | Trabalho | Desbloqueia |
|---|---|---|
| 1 | 10 pilotos presenciais, gratuitos | **Medir churn e CAC reais** |
| 2 | Painel do dono: métricas que justifiquem a fatura | Retenção |
| 3 | Produção dos cartões NFC | Venda |
| 4 | Primeiros 30 pagantes | Prova de mercado |
| 5 | Auditoria de segurança (via NGI Zero, se aprovado) | Lançamento público do browser |
| 6 | Registo de domínios `.hidra` | 2.ª linha de receita |

**Fim do T2:** 30 pagantes, churn medido, auditoria em curso.
**Porta de decisão:** se o churn for >8%, **parar de vender e corrigir o
produto**. Não escalar um funil que não retém.

---

## T3 — Repetir o canal

| # | Trabalho |
|---|---|
| 1 | 100 clientes pagantes |
| 2 | Canal de revendedores (agências locais, contabilistas) |
| 3 | Lançamento público do browser — só depois da auditoria |
| 4 | Apps móveis do HidraReview (o cliente final está no telemóvel) |
| 5 | Programa de relays de voluntários — **torna a rede real** |

**Fim do T3:** canal repetível, browser lançado com auditoria feita.

---

## T4 — Preparar a ronda

| # | Trabalho |
|---|---|
| 1 | 200+ clientes pagantes, 6 meses de histórico de churn |
| 2 | Data room completo ([15](15-data-room.md)) |
| 3 | Abordar VC de pre-seed |
| 4 | 2.ª candidatura ao NGI Zero (fase seguinte) |
| 5 | HidraNet Pro (B2C) — só se houver base de utilizadores que o justifique |

---

## Ano 2 — Escala

| Trimestre | Foco |
|---|---|
| T5 | Fecho do pre-seed · 1.º comercial contratado |
| T6 | 2.ª e 3.ª cidades · 600 clientes |
| T7 | Estrutura para o Brasil · começar entrada no mercado |
| T8 | 1.000+ clientes · preparar seed |

---

## O que **não** está no roadmap, e porquê

| Ideia | Porque não |
|---|---|
| Fork do Firefox em vez de Electron | Tecnicamente correto, custa 12 meses. Reavaliar no ano 2 com equipa financiada. |
| Token / cripto | Ver [04 §3](04-modelo-de-negocio.md) — MiCA, banca, credibilidade |
| Rede própria de saída operada pela empresa | Ver [10 §1](10-risco-legal-regulatorio.md) — risco estrutural |
| Expansão internacional (não lusófona) | Antes de repetir o canal numa cidade, é dispersão |
| HidraNet Pro no T1 | Sem base de utilizadores, converte ~0 |
