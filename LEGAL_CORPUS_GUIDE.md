# Legal Reference Corpus: Collection Guide

**Owner:** RAG teammate · **Time budget:** about 2.5 hours · **Related spec:** `RAG_CASE_INTELLIGENCE.md`

## Goal
Give the Case Assistant a second knowledge layer of **real, public Indian law** next to the (synthetic, encrypted) case files. Then it can answer questions like:
- "Which BNS section covers chain snatching, and what are its elements?"
- "Is the CCTV footage admissible? What certificate is needed?"
- "What does the law say about filing the charge sheet?"

Each answer cites both the **case file** (facts) and the **law** (e.g. `BNS §304`), side by side.

## Ground rules
1. **Official sources only.** Download from India Code (Government of India) and the Supreme Court's own portals. No random blogs or PDFs from Scribd.
2. **Download manually.** Do not write scrapers or bulk-download from any site.
3. **Never edit legal text.** Clean formatting (headers, page numbers) only; the words of the law stay exactly as published.
4. **Record provenance** for every file: source URL, download date, SHA-256 hash (fits our tamper-evidence story).
5. **Verify section numbers and titles against the downloaded PDF.** Section numbers in this guide are a starting point; the PDF is the authority.
6. Legal corpus is public and **readable by every role**. It is never mixed into the case tables.

---

## Step 1: Folder structure (create in the repo)
```
data/legal/
  raw/                  # original PDFs exactly as downloaded
  processed/            # one .jsonl file per source (one JSON object per line)
  manifest.json         # provenance for every source
  law_mapping.csv       # old law -> new law section mapping (hand-built)
scripts/legal/
  extract-acts.ts       # PDF -> per-section JSONL
  extract-judgments.ts  # PDF -> per-paragraph-group JSONL
  ingest-legal.ts       # JSONL -> embeddings -> legal_chunks table
```

---

## Step 2: Download list

### Priority 1: The three new criminal laws (must have)
| Save as | Act | India Code page | Direct PDF |
|---|---|---|---|
| `raw/bns_2023.pdf` | Bharatiya Nyaya Sanhita, 2023 (Act 45 of 2023), offences | https://www.indiacode.nic.in/handle/123456789/20062 | https://www.indiacode.nic.in/bitstream/123456789/20062/1/a202345.pdf |
| `raw/bnss_2023.pdf` | Bharatiya Nagarik Suraksha Sanhita, 2023 (Act 46 of 2023), procedure | https://indiacode.nic.in/handle/123456789/20099 | https://indiacode.nic.in/bitstream/123456789/20099/3/A2023-46.pdf |
| `raw/bsa_2023.pdf` | Bharatiya Sakshya Adhiniyam, 2023 (Act 47 of 2023), evidence | https://indiacode.nic.in/handle/123456789/20063 | https://www.indiacode.nic.in/bitstream/123456789/20063/1/aa202347.pdf |

If a direct PDF link fails, open the India Code page and use its download option. Use the **English** version.

### Priority 2: Supreme Court judgments (4 files)
Where: the Supreme Court's free **e-SCR / Digital SCR** portal (search by party name), or the judgments section of the Supreme Court of India website. Download the official PDF. Indian Kanoon is fine for **reading**, but take the file from the official portal and do not scrape any site.

| Save as | Case | Why it matters for our demo |
|---|---|---|
| `raw/sc_lalita_kumari_2013.pdf` | Lalita Kumari v. Government of Uttar Pradesh (Constitution Bench, decided Nov 2013) | Registration of an FIR is mandatory for cognizable offences |
| `raw/sc_youth_bar_2016.pdf` | Youth Bar Association of India v. Union of India (2016) | FIRs to be uploaded online (with exceptions for sensitive cases) |
| `raw/sc_anvar_basheer_2014.pdf` | Anvar P.V. v. P.K. Basheer (2014) | Electronic records need a certificate to be admissible |
| `raw/sc_arjun_khotkar_2020.pdf` | Arjun Panditrao Khotkar v. Kailash Kushanrao Gorantyal (2020) | Certificate for electronic evidence is mandatory (old Evidence Act s.65B, now BSA s.63); this is the CCTV question in our demo |

Judgments are public court records; real names in them are fine. They never go into the case tables.

### Priority 3 (only if time): Cyber law for Case B
- `raw/it_act_2000.pdf`: Information Technology Act, 2000. Search "Information Technology Act" on indiacode.nic.in. Relevant: s.66C (identity theft), s.66D (cheating by personation using a computer resource).

### Skip
Forensic SOP manuals: we could not find an official, free Indian government PDF quickly. The Acts already contain the key forensic and chain-of-custody provisions (see the curated list below), so use those. Only add an SOP if you find an **official government PDF** in under 15 minutes.

---

## Step 3: Manifest
After downloading, hash every file:
```bash
sha256sum data/legal/raw/*.pdf
```
Fill `data/legal/manifest.json`:
```json
[
  {
    "source_id": "bns_2023",
    "type": "ACT",
    "title": "The Bharatiya Nyaya Sanhita, 2023",
    "short": "BNS",
    "citation": "Act No. 45 of 2023",
    "file": "raw/bns_2023.pdf",
    "source_url": "https://www.indiacode.nic.in/bitstream/123456789/20062/1/a202345.pdf",
    "landing_url": "https://www.indiacode.nic.in/handle/123456789/20062",
    "downloaded_at": "2026-10-09T13:30:00+05:30",
    "sha256": "<from sha256sum>",
    "language": "en"
  }
]
```
In the UI, legal citations get a small badge: "Official source · hash verified".

---

## Step 4: Extract and split

### 4A. Minimum viable: curated sections (do this first)
Don't try to perfectly parse all ~1,000 sections first. Start with the ~35 sections our demo needs. Open each Act's India Code page (it lists sections individually), confirm number + title, and extract just these.

**BNS (offences)**
| Section | Expected title / topic | Demo use |
|---|---|---|
| 2 | Definitions | General |
| 3(5) | Acts done by several persons in furtherance of common intention | Two riders on the scooter |
| 115 | Voluntarily causing hurt | Victim pushed |
| 303 | Theft | Base offence |
| 304 | Snatching | Core charge for Case A |
| 309 | Robbery | Contrast with snatching |
| 317 | Stolen property | Recovery of chain |
| 318 | Cheating | Case B |
| 319 | Cheating by personation | Case B |

**BNSS (procedure)**
| Section | Expected title / topic | Demo use |
|---|---|---|
| 105 | Recording of search and seizure through audio-video electronic means | Chain of custody |
| 173 | Information in cognizable cases (FIR) | FIR |
| 176 | Procedure for investigation (incl. forensic expert visit for serious offences) | Forensic |
| 180 | Examination of witnesses by police | Witness statements |
| 183 | Recording of confessions and statements | Statements before Magistrate |
| 187 | Procedure when investigation cannot be completed in twenty-four hours | Custody / timelines |
| 193 | Report of police officer on completion of investigation | Charge sheet |
| 230 | Supply to accused of copy of police report and other documents | Disclosure |

**BSA (evidence)**
| Section | Expected title / topic | Demo use |
|---|---|---|
| 2 | Definitions (document, evidence, electronic records) | General |
| 57 | Primary evidence (incl. explanations on electronic records) | CCTV / digital |
| 61 | Electronic or digital record (admissibility) | CCTV |
| 62 | Special provisions as to evidence relating to electronic record | CCTV |
| 63 | Admissibility of electronic records | CCTV certificate |
| Schedule | Certificate format under s.63 (Part A / Part B) | CCTV certificate |

If a number or title in these tables doesn't match the PDF, trust the PDF and fix the table.

### 4B. Output format: Acts (`processed/bns_2023.jsonl`, one line per section)
```json
{"id":"BNS-304","source_id":"bns_2023","type":"ACT","short_ref":"BNS §304","act":"Bharatiya Nyaya Sanhita, 2023","chapter":"<from PDF>","chapter_title":"<from PDF>","section":"304","section_title":"Snatching","text":"<full section text incl. sub-sections, explanations, illustrations>","page":0,"source_url":"https://www.indiacode.nic.in/bitstream/123456789/20062/1/a202345.pdf"}
```
- One record per section, keeping sub-sections, explanations and illustrations together.
- If a section is very long (over ~800 tokens), split into `BNS-xxx-p1`, `BNS-xxx-p2` with the same `short_ref`.

### 4C. Output format: judgments (`processed/sc_arjun_khotkar_2020.jsonl`)
Split by numbered paragraphs, grouping consecutive paragraphs into ~500–800 token chunks.
```json
{"id":"SC-KHOTKAR-2020-p61-63","source_id":"sc_arjun_khotkar_2020","type":"JUDGMENT","short_ref":"Arjun Panditrao Khotkar (2020), paras 61–63","case_name":"Arjun Panditrao Khotkar v. Kailash Kushanrao Gorantyal","court":"Supreme Court of India","decided_on":"<from PDF>","para_start":61,"para_end":63,"text":"<verbatim paragraphs>","source_url":"<official URL>"}
```
Also add **one** `headnote` record per judgment, written by you in 2–3 plain sentences, marked clearly:
```json
{"id":"SC-KHOTKAR-2020-headnote","type":"HEADNOTE","team_written":true,"short_ref":"Arjun Panditrao Khotkar (2020), team summary","text":"..."}
```
The UI must label headnotes "Team summary, not the judgment text".

### 4D. Extraction script hints (`scripts/legal/extract-acts.ts`)
```ts
import { readFile, writeFile } from "node:fs/promises";
import { extractText, getDocumentProxy } from "unpdf";

const pdf = await getDocumentProxy(new Uint8Array(await readFile("data/legal/raw/bns_2023.pdf")));
const { text } = await extractText(pdf, { mergePages: false }); // string[] (one per page)

// 1. Remove junk lines: page numbers, running headers, gazette headers, footnote markers.
// 2. Join pages, keep a page index for each character offset (to fill "page").
// 3. Split on section starts, e.g. lines beginning with "304. " (number + dot + space).
//    Marginal headings (section titles) may come out of the PDF before or after the
//    section text, so confirm titles against the India Code section list.
// 4. Keep only sections in the curated list first (4A); add the rest later if time permits.
// 5. Write one JSON object per line to data/legal/processed/bns_2023.jsonl
```
If PDF parsing gets messy, the fallback for the curated sections is to copy each section's text from its India Code section view into the JSONL by hand. About 35 sections is fine to do manually.

### 4E. `law_mapping.csv` (hand-built, helps old-law questions)
Judges, police and lawyers still think in IPC/CrPC numbers. Verify every row against the new Act text before committing.
```csv
old_law,old_section,new_law,new_section,topic,verified
IPC,379,BNS,303(2),Theft (punishment),no
IPC,323,BNS,115(2),Voluntarily causing hurt (punishment),no
IPC,34,BNS,3(5),Common intention,no
CrPC,154,BNSS,173,FIR,no
CrPC,161,BNSS,180,Police examination of witnesses,no
CrPC,164,BNSS,183,Recording of confessions and statements,no
CrPC,167,BNSS,187,Custody when investigation not complete in 24 hours,no
CrPC,173,BNSS,193,Charge sheet,no
CrPC,207,BNSS,230,Supply of documents to accused,no
Evidence Act,65B,BSA,63,Admissibility of electronic records,no
-,-,BNS,304,Snatching (new standalone offence; earlier charged under IPC theft/robbery provisions),no
```
Set `verified` to `yes` only after checking the row yourself.

---

## Step 5: QA checklist (before ingestion)
- [ ] Every curated section exists in the JSONL with a matching number and title.
- [ ] Spot-check 10 records word-for-word against the PDF.
- [ ] No gazette headers, page numbers, or "THE GAZETTE OF INDIA EXTRAORDINARY" lines inside `text`.
- [ ] No empty `text` fields; no duplicated `id`s.
- [ ] `manifest.json` has a SHA-256 for every raw file, and `sha256sum` still matches.
- [ ] Judgments: paragraph numbers in `para_start`/`para_end` match the PDF.
- [ ] Headnotes are marked `team_written: true`.

---

## Step 6: Ingestion (`scripts/legal/ingest-legal.ts`)

### Table
The legal corpus is public, so no encryption or blind index is needed. Normal Postgres full-text search is fine here.
```sql
create table legal_chunks (
  id            text primary key,          -- e.g. BNS-304, SC-KHOTKAR-2020-p61-63
  source_id     text not null,
  type          text not null,             -- ACT | JUDGMENT | HEADNOTE | MAPPING
  short_ref     text not null,             -- "BNS §304"
  title         text,
  text          text not null,
  tsv           tsvector generated always as (to_tsvector('simple', coalesce(short_ref,'') || ' ' || coalesce(title,'') || ' ' || text)) stored,
  embedding     vector(768) not null,
  source_url    text not null,
  source_sha256 text not null,
  meta          jsonb default '{}'
);
create index on legal_chunks using hnsw (embedding vector_cosine_ops);
create index on legal_chunks using gin (tsv);
alter table legal_chunks enable row level security;
create policy "legal corpus readable by all signed-in users"
  on legal_chunks for select to authenticated using (true);
```

### Embedding
Same model and format as the case corpus (`gemini-embedding-2`, 768 dims):
```
title: BNS §304 Snatching | text: <section text>
```
Batch in groups of 8 with retry/backoff (see `RAG_CASE_INTELLIGENCE.md` §4.4). The whole curated corpus is small, so ingest once at seed time.

### Retrieval change (for whoever owns `/api/ai/ask`)
- Search **both** `doc_chunks` (case, access-controlled) and `legal_chunks` (law, public); take top 4 case + top 3 law.
- Mark law blocks in the prompt: `<context id="L1" source="LAW" ref="BNS §304" url="...">`.
- Add to the system prompt:
  > Blocks with source="LAW" state the law; other blocks state case facts. You may say which provisions are relevant and which facts relate to their elements, but never conclude that an offence is proved or that a provision is satisfied.
- UI: law citations render as a different chip style (e.g. "⚖ BNS §304") linking to the India Code page.
- Every AI answer that uses the legal corpus shows a footer: "Legal references are for information only and are not legal advice."

---

## Step 7: Demo questions to test
| Question (as Prosecutor) | Should cite |
|---|---|
| Which BNS section covers chain snatching, and what are its elements? | BNS §304 + FIR / WS-1 facts |
| Two men were on the scooter. Can both be charged? | BNS §3(5) + FIR / FR-1 |
| Is the CCTV footage admissible? What certificate is needed? | BSA §63 (+ Schedule) + Khotkar 2020 + FR-1 |
| What does the law say about filing the charge sheet? | BNSS §193 (+ §187) |
| What was IPC 379 replaced with? | `law_mapping.csv` → BNS §303(2) |
| (Forensic Lab) What did the witnesses say? | Still "Not found in accessible records." for case facts; law answers remain available |

---

## Step 8: Timeline
| Duration | Task |
|---|---|
| 30 min | Download Priority 1 + 2, hash files, write `manifest.json` |
| 60 min | Curated sections + judgment chunks into JSONL (script or manual) |
| 20 min | `law_mapping.csv`, verify rows |
| 20 min | QA checklist |
| 30 min | `legal_chunks` table + ingestion script, run it |
| Later, if time | Full Acts parsing, IT Act, Hindi versions |

## Definition of done
- `data/legal/raw/` has the 3 Acts + 4 judgments, matching `manifest.json` hashes.
- `data/legal/processed/` has JSONL for each, passing the QA checklist.
- `legal_chunks` is populated and the Step 7 questions return correct citations.
- Everything committed and pushed.
