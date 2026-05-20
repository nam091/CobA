# Chương 2 — Cơ sở lý thuyết

## 2.1. Lỗ hổng an toàn mã nguồn

### 2.1.1. Định nghĩa

Theo NIST SP 800-160, một *vulnerability* là "khiếm khuyết trong yêu cầu,
thiết kế, hoặc cài đặt của một hệ thống mà attacker có thể khai thác để
gây hại". Trong ngữ cảnh **source code**, lỗ hổng thường biểu hiện dưới
dạng các mẫu (pattern) lập trình sai hoặc thiếu kiểm tra (vd. SQL injection,
buffer overflow, broken access control).

### 2.1.2. Phân loại theo CWE và OWASP

- **CWE (Common Weakness Enumeration)** [@mitre_cwe] là danh mục các *loại*
  điểm yếu phần mềm do MITRE quản lý — ~ 1400 entries. CWE Top 25 năm 2024
  liệt kê những điểm yếu nguy hiểm nhất [@mitre_topcwe].
- **CVE (Common Vulnerabilities and Exposures)** là *thể hiện cụ thể* của
  lỗ hổng — mỗi CVE id (vd. CVE-2017-5638) gắn với một sản phẩm, phiên bản,
  và mô tả.
- **OWASP Top 10** [@owasp_top10] là danh sách 10 hạng mục lỗ hổng web phổ
  biến nhất — chu kỳ cập nhật 3–4 năm.

Hai phân loại trên *bổ sung* nhau: CWE chi tiết hơn, OWASP gần với ngôn
ngữ developer.

### 2.1.3. Các họ lỗ hổng quan tâm trong CobA

- **Injection family** — CWE-79/89/78/94/611/918.
- **Memory safety** — CWE-787/125/416/476 (chủ yếu C/C++).
- **Crypto family** — CWE-327/328/330/798.
- **Access control** — CWE-862/863/285/352/434/639.

### 2.1.4. Mô hình tấn công cơ bản — Taint analysis

Một lỗ hổng injection có thể được mô hình hoá thành chuỗi *source → sink*:

- **Source**: nơi dữ liệu không tin cậy đi vào (input từ user, network, file).
- **Sink**: hàm nguy hiểm nếu nhận dữ liệu không hợp lệ (`exec`, `eval`,
  `db.query`).
- **Sanitizer**: hàm khử nguy hiểm cho dữ liệu (escape, validate,
  parameterize).

Lỗ hổng tồn tại khi có **đường đi (path)** trong chương trình từ source
tới sink mà không qua sanitizer phù hợp.

## 2.2. Phân tích chương trình tĩnh

### 2.2.1. AST — Abstract Syntax Tree

Cây cú pháp trừu tượng (AST) là biểu diễn cấu trúc của mã nguồn sau khi
loại bỏ thông tin trình bày (whitespace, dấu ngoặc dư). Mỗi node ứng với
một construct: function, class, statement, expression, …

```
Python source:                AST:
def add(a, b):                FunctionDef
    return a + b              ├── identifier "add"
                              ├── Parameters [a, b]
                              └── Return
                                  └── BinOp(Add)
                                      ├── Name(a)
                                      └── Name(b)
```

Thư viện AST đa ngôn ngữ hàng đầu hiện nay là **Tree-sitter** — incremental
parser sinh AST cho 100+ ngôn ngữ với cùng API, được GitHub Code Search
dùng làm backbone.

### 2.2.2. CFG — Control Flow Graph

Đồ thị luồng điều khiển biểu diễn các nhánh thực thi của một function:
mỗi node là một *basic block*; mỗi edge là một bước thực thi tuần tự, một
nhánh `if`, một vòng lặp, hoặc một lời gọi hàm.

### 2.2.3. PDG — Program Dependence Graph

Đồ thị phụ thuộc gồm hai loại cạnh:
- *Data dependence*: biến được gán ở node A, dùng ở node B.
- *Control dependence*: thực thi B phụ thuộc giá trị tại A.

PDG là nền tảng cho taint analysis: nếu source và sink có đường đi qua
data-dependence trong PDG thì có khả năng tồn tại data flow.

### 2.2.4. CPG — Code Property Graph

Code Property Graph (CPG) [@joern] hợp nhất AST + CFG + PDG vào một *đồ thị
thuộc tính* duy nhất, cho phép viết query Datalog/Scala duyệt cấu trúc và
luồng dữ liệu cùng lúc. Joern là engine mã nguồn mở phổ biến nhất hiện nay,
hỗ trợ C/C++/Java/Python/JavaScript với cùng schema CPG.

Ví dụ một query Joern tìm "user input chảy tới `exec`":
```scala
cpg.call.name("request.args.get").reachableByFlows(cpg.call.name("exec")).p
```

### 2.2.5. SAST — Static Application Security Testing

SAST là phương pháp tự động phát hiện lỗ hổng bằng cách *phân tích tĩnh*
mã nguồn (không thực thi). SAST có 3 cách tiếp cận chính:

1. **Pattern matching** (Semgrep, Bandit) — viết rules YAML/Datalog so khớp
   AST/text. Ưu: nhanh, dễ mở rộng. Nhược: không hiểu ngữ cảnh.
2. **Data-flow analysis** (Joern, CodeQL, Infer) — taint, thread-safety,
   null-deref. Ưu: chính xác hơn. Nhược: chậm, đôi khi tốn 4 GB RAM cho
   repo lớn.
3. **Symbolic execution** (KLEE) — duyệt mọi đường đi với constraint
   solver. Ưu: tìm corner case. Nhược: state explosion, ít scale.

CobA sử dụng kết hợp **pattern matching** (Semgrep, Bandit, Gitleaks) +
**data-flow** (Joern) như "first pass".

## 2.3. Mô hình ngôn ngữ lớn (LLM)

### 2.3.1. Transformer & Decoder-only

Hầu hết LLM hiện đại sử dụng kiến trúc *Transformer* [Vaswani 2017] dạng
*decoder-only* (auto-regressive): mô hình dự đoán token tiếp theo dựa trên
toàn bộ token đã sinh. Các thành phần:

- **Multi-head Self-Attention**: cho mỗi token, đánh trọng số liên hệ với
  tất cả token trước đó.
- **Feed-Forward Network**: biến đổi nonlinear sau attention.
- **Layer Normalization & Residual connection**: ổn định gradient.

Kích thước mô hình tăng nhanh: từ GPT-2 (1.5B) → GPT-3 (175B) → GPT-4
(ước lượng ~ 1.7T sparse). Mô hình mã nguồn mở phổ biến cho code:
DeepSeek-Coder V2 [@guo2024deepseekcoder], Qwen2.5-Coder
[@hui2024qwen25coder].

### 2.3.2. Tokenization

Văn bản → chuỗi *token* (đơn vị BPE/SentencePiece) → embedding vector.
Code Python `def f(x):` ≈ 4 token. Số lượng token quyết định chi phí
API và bộ nhớ.

### 2.3.3. Cửa sổ ngữ cảnh

*Context window* là số token tối đa LLM xử lý một lượt:
- GPT-4o: 128K.
- Claude 3.5 Sonnet: 200K.
- Gemini 1.5 Pro: 2M.
- Qwen2.5-Coder 7B: 32K.

Vẫn chưa đủ để feed một repo 100K LOC ⇒ cần chunking thông minh
(xem § 2.5).

### 2.3.4. Inference parameters

- **Temperature** ∈ [0, 2]: 0 = deterministic; cao = đa dạng.
- **Top-p (nucleus sampling)**: chọn từ tập xác suất tích luỹ ≤ p.
- **Stop tokens**: chuỗi khiến mô hình dừng.
- **max_tokens**: trần độ dài output.

CobA dùng `temperature=0` cho cả Detector và Verifier nhằm tăng khả năng
tái lập.

### 2.3.5. Prompt engineering

Một số kỹ thuật chính:

- **Zero-shot**: chỉ mô tả task.
- **Few-shot**: kèm 2–5 ví dụ trong prompt.
- **Chain-of-Thought (CoT)**: yêu cầu LLM "suy luận từng bước".
- **ReAct**: kết hợp suy luận + gọi tool.
- **Structured output (JSON mode / function calling)**: ép format đầu ra
  để parse được tự động — quan trọng với pipeline tự động.

### 2.3.6. Khả năng & hạn chế của LLM

| Khả năng | Hạn chế |
|---|---|
| Hiểu ngữ nghĩa rộng | Hallucination (bịa fact) |
| Suy luận đa bước | Phụ thuộc context, dễ bị input dài làm "loãng" |
| Nhiều ngôn ngữ tự nhiên + code | Sai về số học, ngày tháng |
| Sinh giải thích dễ đọc | Không đảm bảo deterministic |
| Học từ in-context | Cutoff date — không biết update gần đây |
| Function calling, JSON mode | Có thể bị prompt injection từ input |

## 2.4. Retrieval-Augmented Generation (RAG)

### 2.4.1. Định nghĩa

RAG là kỹ thuật bổ sung tri thức ngoài cho LLM bằng cách:
1. Lưu KB ở dạng embedding vector.
2. Khi nhận query, *retrieve* top-k snippet liên quan nhất.
3. *Inject* các snippet vào prompt cùng query → LLM trả lời.

Mục đích: giảm hallucination, cập nhật fact mới mà không cần re-train.

### 2.4.2. Embedding

Embedding biến text → vector cố định (vd. 384 hoặc 1024 chiều). Cosine
similarity giữa hai vector ≈ độ liên quan ngữ nghĩa. Mô hình embedding
phổ biến: `sentence-transformers/all-MiniLM-L6-v2` (80 MB),
`BAAI/bge-large-en-v1.5` (1.3 GB) [@reimers2019sbert].

### 2.4.3. Vector database

Các DB phổ biến: ChromaDB (in-process), Qdrant (server), pgvector (Postgres),
Pinecone (SaaS). CobA chọn ChromaDB [@chromadb] vì nhẹ, persistent, không
cần server riêng.

### 2.4.4. RAG cho phát hiện lỗ hổng

Vul-RAG [@du2024vulrag] và IRIS [@lin2024iris] cho thấy:
- **CWE retrieval** giúp LLM cite CWE id đúng > 90 %.
- **Past CVE similarity** giúp LLM nhận biết các pattern lỗi đã thấy.
- Có thể kết hợp **negative examples** (code đã fix) để LLM phân biệt
  vuln vs safe.

CobA sử dụng 3 ChromaDB collection: `cwe_kb` (250 CWE), `cve_corpus`
(5000 CVE), `primevul_examples` (3000 cặp vuln/fixed).

## 2.5. Code chunking & multi-file reasoning

### 2.5.1. Vì sao cần chunking

Repo lớn vượt cửa sổ ngữ cảnh; nếu cố nén toàn bộ file → mất chi tiết
quan trọng. Đồng thời, LLM xử lý chunk dài → attention bị "loãng".

### 2.5.2. Chiến lược chunking

| Chiến lược | Mô tả | Ưu | Nhược |
|---|---|---|---|
| Line-based | Mỗi N dòng | Đơn giản | Cắt giữa hàm |
| Token-based | Mỗi M token | Cân bằng cost | Mất syntax |
| File-based | Mỗi file 1 chunk | Giữ nguyên context | Vượt window |
| **Function-based** | Mỗi function 1 chunk | Đơn vị ngữ nghĩa | Cần parser |
| CPG-aware | Function + caller/callee | Inter-procedural | Cần Joern |

CobA chọn *Function-based + CPG-aware* (xem `docs/05_CODE_UNDERSTANDING.md`).

### 2.5.3. Cross-file reasoning

Lỗ hổng thường vượt qua biên file (taint source ở file A, sink ở file B).
Giải pháp: build CPG cho cả repo → expand caller/callee 2 cấp khi cần.

## 2.6. Đánh giá hiệu năng

### 2.6.1. Confusion matrix

|         | Predicted POS | Predicted NEG |
|---|---|---|
| **Actual POS** | TP | FN |
| **Actual NEG** | FP | TN |

### 2.6.2. Các metric

- **Precision** = TP / (TP + FP) — tỉ lệ cảnh báo đúng.
- **Recall** = TP / (TP + FN) — tỉ lệ vuln được phát hiện.
- **F1** = 2·P·R / (P + R) — trung bình điều hoà.
- **MCC** = (TP·TN − FP·FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN)) — robust
  với class imbalance.
- **FP rate** = FP / (FP + TN) — quan trọng khi dataset imbalanced.

### 2.6.3. Significance test

- **McNemar's test** cho so sánh hai classifier trên cùng test set
  (paired binary outcome).
- **Bootstrap** 1000 resample để estimate CI 95 %.

## 2.7. Anti-hallucination cho LLM

### 2.7.1. Tổng quan biện pháp

1. **Strict output schema** (JSON mode) — reject nếu không parse được.
2. **Grounding constraint** — yêu cầu LLM cite line range tồn tại.
3. **RAG context** — đưa fact đáng tin vào prompt.
4. **Critique by another LLM (Verifier)** — model thứ hai phê bình.
5. **Self-consistency** — sample N lần, majority vote.
6. **Tool-augmented reasoning** — LLM gọi tool để verify (vd. eval Python
   AST query trên CPG).

CobA chọn 1 + 2 + 3 + 4 — không dùng 5 (đắt) và 6 (phức tạp giai đoạn v0).

### 2.7.2. Confirmation bias trong Verifier

Nếu Detector và Verifier cùng model, có xu hướng đồng ý với chính nó.
Vì vậy CobA mặc định:

- Detector = GPT-4o-mini (OpenAI).
- Verifier = Claude 3.5 Sonnet (Anthropic).
- Khác *provider*, khác *training data* → giảm bias.

## 2.8. Tóm tắt nền tảng

Bốn nền tảng được tổng hợp trong CobA:

1. **Phân tích chương trình tĩnh** (AST, CFG, CPG, taint).
2. **LLM** (Transformer, prompt engineering, JSON mode).
3. **RAG** (embedding, vector DB, retrieval).
4. **Đánh giá thực nghiệm** (confusion matrix, F1, MCC, significance test).

Mỗi nền tảng có công cụ chuẩn (Joern, OpenAI/Anthropic/Ollama, ChromaDB,
PrimeVul/OWASP Benchmark) và được tích hợp trong kiến trúc Chương 4.

---

> **TODO** trước khi nộp:
> - Thêm hình kiến trúc Transformer (sơ đồ Vaswani 2017).
> - Vẽ minh hoạ CPG đơn giản (3 node, 6 edge).
> - Bổ sung bảng so sánh thông số 3 mô hình embedding.
> - Tham khảo thêm bài [Khare et al. 2024] [@khare2024understanding].
