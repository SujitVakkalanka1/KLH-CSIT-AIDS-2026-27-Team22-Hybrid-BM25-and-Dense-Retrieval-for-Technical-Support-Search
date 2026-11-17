# Hybrid BM25 + Dense Retrieval Search Engine Prototype

> **About (GitHub Repository Description)**
> Hybrid BM25 + Dense Retrieval search engine prototype for technical support with 1-indexed Reciprocal Rank Fusion (RRF) and an automated Recall@5 / MRR@5 evaluation harness across 250 KB articles and 42 benchmark queries.

**Suggested GitHub Topics:**
`hybrid-search` · `bm25` · `dense-retrieval` · `reciprocal-rank-fusion` · `rrf` · `sentence-transformers` · `information-retrieval` · `search-evaluation` · `fastapi` · `python`

---

## 1. About the Project (Why Hybrid Search?)

In technical support retrieval, relying on a single search paradigm introduces systematic blind spots:

1. **BM25 (Sparse Keyword Search)** matches exact character tokens in an inverted index (`rank_bm25` / `BM25Okapi`). It excels at finding specific error codes (`E_AUTH_501`), firmware point releases (`Router-X1 v2.4.1`), and CLI flags, but fails when a user describes a problem in everyday language (*"wipe my office router back to default out-of-the-box settings"* vs. the manual's *"Executing Non-Volatile NVRAM Factory Initialization"*).
2. **Dense Retrieval (Semantic Vector Search)** encodes text into normalized 384-dimensional meaning vectors using a neural bi-encoder (`sentence-transformers/all-MiniLM-L6-v2`). It bridges vocabulary gaps (*"notebook sat unused in a closet for months and now it is totally dead"* $\rightarrow$ *"Lithium-Ion Pack Under-Voltage Lockout (UVLO) Pre-Charge Trickle Wake Procedure"*), but compresses exact strings into dense concepts—frequently confusing sibling error codes (`E_AUTH_501` vs. `E_AUTH_503` vs. `E_AUTH_509`) or adjacent firmware builds (`v2.4.1` vs. `v2.4.4` vs. `v2.4.9`).
3. **Hybrid Search + 1-Indexed Reciprocal Rank Fusion (RRF):** Both BM25 and Dense Retrieval run in parallel on every query, and their Top 50 candidate lists are merged using **Reciprocal Rank Fusion (`k = 60`)**. Because BM25 produces unbounded statistical scores and Dense Retrieval produces cosine similarity (`-1.0` to `1.0`), raw scores cannot be summed directly. RRF scores documents strictly by their 1-indexed rank position across both engines.

---

## 2. System Architecture

```text
┌────────────────────────────────────────────────────────────────────────────────┐
│              Hybrid Search Prototype & Evaluation Workbench (UI)               │
├─────────────────────────┬──────────────────────────┬───────────────────────────┤
│   Scorecard Banner      │  3-Column Search Grid    │  Diagnostic Workbenches   │
│ • Overall (40 queries)  │ • BM25 / Dense / Hybrid  │ • 42-Query Eval Debugger  │
│ • Per-Category Metrics  │ • 5 Preset Trap Buttons  │   (Click-to-Run + Ranks)  │
│ • 2 Unanswerable Report │ • Provenance Readouts    │ • Trap & 250-KB Browser   │
└────────────┬────────────┴────────────┬─────────────┴─────────────┬─────────────┘
             │ GET /api/metrics        │ POST /api/search          │ GET /api/corpus
             ▼                         ▼                           ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│                 Port 3000 Gateway & FastAPI Retrieval Lifespan                 │
├─────────────────────────────────────┬──────────────────────────────────────────┤
│      Sparse Engine (BM25Okapi)      │     Dense Engine (all-MiniLM-L6-v2)      │
│  • Compound + Sub-Part Tokenizer    │  • Normalized 384-d Embeddings           │
│  • Drops candidates with score <= 0 │  • Disk Cache + SHA-256 Corpus Checksum  │
│  • Top 50 with 1-indexed ranks      │  • Dot-Product Top 50 (1-indexed ranks)  │
└───────────────────┬─────────────────┴────────────────────┬─────────────────────┘
                    │                                      │
                    ▼                                      ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│            1-Indexed Reciprocal Rank Fusion (k = 60, Configurable)             │
│  • Formula: (1/(60 + rank_bm25) if in_bm25) + (1/(60 + rank_dense) if in_dense)│
│  • Tie-Break: rrf_score ↓  →  min(rank_bm25, rank_dense) ↑  →  article_id ↑    │
└─────────────────────────────────────┬──────────────────────────────────────────┘
                                      │
                                      ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│           250-Article Technical Corpus & 42-Query Evaluation Dataset           │
│  • 30 Hand-Written Sibling/Firmware/Vocab Trap Articles (8 Trap Clusters)      │
│  • 220 Varied Multi-Pattern Domain Articles across 5 Technical Domains         │
│  • 42 Independent Queries: 14 exact_code, 14 symptom, 12 mixed, 2 unanswerable │
└────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Core Algorithms & Worked Examples

### A. Compound + Sub-Part Regex Tokenizer (`tech_tokenize`)
A naive tokenizer either splits `E_AUTH_501.` into `['e', 'auth', '501']` (losing exact compound specificity) or keeps `['e_auth_501.']` (failing when a user searches `"auth 501"` or when trailing punctuation is attached).
- **Rule**: Lowercase input, strip leading/trailing punctuation (`501.` $\rightarrow$ `501`), emit the intact compound token **AND** its split alphanumeric sub-parts on `_`, `-`, and `.`:
  - **Input**: `"Error E_AUTH_501 on v2.4."`
  - **Output Tokens**: `["error", "e_auth_501", "e", "auth", "501", "on", "v2.4", "v2", "4"]`

### B. 1-Indexed Reciprocal Rank Fusion (RRF) Math
For a query, each engine retrieves up to its Top 50 candidates with 1-indexed ranks (`1, 2, ..., 50`). Any BM25 candidate with `score <= 0.0` is dropped immediately so zero-score documents never receive arbitrary ranks.

$$\text{RRF\_Score}(d) = \begin{cases} \frac{1}{k + \text{rank}_{\text{bm25}}(d)} & \text{if } d \in \text{BM25 Top 50} \\ 0.0 & \text{otherwise} \end{cases} + \begin{cases} \frac{1}{k + \text{rank}_{\text{dense}}(d)} & \text{if } d \in \text{Dense Top 50} \\ 0.0 & \text{otherwise} \end{cases}$$

With smoothing constant $k = 60$:
- Suppose **Article KB-001** ranks `#2` in BM25 and `#4` in Dense:
  $$\text{RRF\_Score}(\text{KB-001}) = \frac{1}{60 + 2} + \frac{1}{60 + 4} = 0.01613 + 0.01563 = 0.03175$$
- Suppose **Article KB-002** ranks `#1` in Dense (sibling error code `E_AUTH_503`) and is absent from BM25's Top 50:
  $$\text{RRF\_Score}(\text{KB-002}) = 0.0 + \frac{1}{60 + 1} = 0.01639$$
- **Result**: **KB-001** wins Rank `#1` in Hybrid (`0.03175 > 0.01639`), resolving Dense Retrieval's sibling-code confusion.
- **Deterministic Tie-Breaking**: Sort by `rrf_score` descending $\rightarrow$ `min(rank_bm25, rank_dense)` ascending $\rightarrow$ `article_id` ascending.

### C. Evaluation Metrics (`Recall@5` & `MRR@5`)
Evaluated across **40 answerable queries** (where each query has a single ground-truth `expected_id`) plus **2 separately reported unanswerable queries** (`expected_id: null`):
- **Recall@5**: `1.0` if `expected_id` appears anywhere in the top 5 results, else `0.0` (averaged across the 40 answerable queries overall and per category: `exact_code`, `symptom`, `mixed`).
- **MRR@5 (Mean Reciprocal Rank @ 5)**: `1 / rank` if `expected_id` is in the top 5 (Rank `#1` = `1.0`, Rank `#2` = `0.5`, Rank `#4` = `0.25`), else `0.0`.
- **Unanswerable Queries (Reported Separately)**: Tests in-domain queries referencing unreleased firmware builds (`Router-X1 v3.9.0-beta2`) or nonexistent error codes (`NET_QKD_999`, `E_BIO_999`) without distorting the 40-query Recall@5 and MRR@5 denominator.

---

## 4. Corpus & Benchmark Dataset (`dataset.json` & `eval_queries.json`)

- **250 KB Articles (`KB-001` to `KB-250`)** balanced evenly across 5 domains (`50` articles each):
  - `Auth/IAM` · `Network/Routers` · `Database/Storage` · `Cloud/CLI` · `Display/Hardware`
- **30 Hand-Written Trap Articles (`KB-001` to `KB-030`)** across 8 trap clusters:
  1. `TRAP-AUTH-50X`: Sibling OAuth/OIDC handshake codes (`E_AUTH_501`, `E_AUTH_503`, `E_AUTH_509`, `E_AUTH_512`).
  2. `TRAP-SSL-10X`: Sibling TLS inspection & mTLS codes (`ERR_SSL_102`, `ERR_SSL_108`, `ERR_SSL_109`).
  3. `TRAP-ROUTER-FW`: Point-release regressions (`Router-X1 v2.4.1`, `v2.4.4`, `v2.4.9`).
  4. `TRAP-SWITCH-FW`: Point-release switch traps (`OmniSwitch-48P v5.1.2` vs. `v5.1.8`).
  5. `TRAP-DB-LOCK`: Sibling database lock codes (`DB_LOCK_801`, `DB_LOCK_804`, `DB_LOCK_809`).
  6. `TRAP-CLI-90X`: Sibling cloud CLI codes (`CLI_ERR_901`, `CLI_ERR_902`, `CLI_ERR_907`).
  7. `TRAP-DISPLAY-HW`: Sibling docking station display codes (`DISP_EDID_301`, `DISP_EDID_305`, `DISP_PWR_309`).
  8. `TRAP-VOCAB-SYMPTOM`: 9 formal engineering articles (`KB-022` to `KB-030`) paired with colloquial symptom queries that have zero technical keyword overlap.
- **42 Independently Authored Queries (`eval_queries.json`)**:
  - `14 exact_code` (`Q-01`–`Q-14`)
  - `14 symptom` (`Q-15`–`Q-28`)
  - `12 mixed` (`Q-29`–`Q-40`, combining plain-English symptoms with partial codes like `auth 501`, `ssl 102`, `v2.4.4`, `lock 801`)
  - `2 unanswerable` (`Q-41`–`Q-42`, `expected_id: null`)
  - Verified via automated leak check (`0 / 40` answerable queries share 4 or more contiguous words with any article in the corpus).

---

## 5. Tech Stack

- **Backend**: Python 3.10+, FastAPI, Uvicorn, Pydantic
- **Sparse Retrieval**: `rank_bm25` (`BM25Okapi`) + custom compound/sub-part regex tokenizer
- **Dense Retrieval**: `sentence-transformers` (`all-MiniLM-L6-v2`) + `numpy` (normalized embeddings cached to `embeddings.npy` with SHA-256 dataset checksum verification)
- **Frontend Workbench**: Dark-mode 3-Column Comparison UI with Per-Query Evaluation Debugger (click-to-run) and 250-Article / Trap Cluster Corpus Browser
