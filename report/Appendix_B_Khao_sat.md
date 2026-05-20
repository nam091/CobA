# Phụ lục B — Khảo sát công trình liên quan

> Phần này nguyên là Chương 3 trong bản 7-chương; được đưa xuống phụ lục theo định dạng khoá luận 3 chương.

## B.1. Phân nhóm tổng quan

Các công trình hiện có phát hiện lỗ hổng có thể chia thành 4 nhóm:

1. **SAST cổ điển** — rule-based, không dùng ML/LLM.
2. **Deep-learning vulnerability detection** — model nhỏ (CodeBERT, Devign,
   LineVul) train trên dataset gán nhãn.
3. **LLM zero/few-shot prompting** — sử dụng GPT-4, Claude với prompt
   engineering.
4. **LLM-augmented agent / hybrid** — kết hợp LLM với tool (SAST, taint).

CobA thuộc nhóm 4 — sẽ phân tích kỹ § 3.4.

## B.2. SAST cổ điển

### B.2.1. Semgrep [@semgrep]

- Mã nguồn mở (LGPL-2.1), > 2000 rules sẵn.
- Pattern matching trên AST (DSL gần với code, không phải regex).
- Hỗ trợ multi-language (30+ ngôn ngữ).
- Hiệu năng tốt (~ 30 s cho 50K LOC).
- **Hạn chế**: rule-based không hiểu data flow phức tạp.

### B.2.2. Bandit [@bandit]

- Maintained by PyCQA, chuyên Python.
- Phù hợp cho rule Python (`exec`, `eval`, `pickle.load`, hash MD5/SHA1, …).
- **Hạn chế**: chỉ Python.

### B.2.3. CodeQL

- Phát triển bởi Semmle/GitHub, dùng QL/Datalog.
- Phân tích sâu, hỗ trợ taint inter-procedural.
- **Hạn chế**: license cho commercial use bị hạn chế (Academic license
  riêng); learning curve cao.

### B.2.4. Joern [@joern]

- Apache-2.0, CPG cho C/C++/Java/Python/JS.
- Cho phép viết Scala/CPGQL queries.
- **Hạn chế**: chậm với repo lớn (~ 5 phút cho 50K LOC), tốn RAM.

### B.2.5. Infer, SpotBugs, Cppcheck, SonarQube

- Specialized cho từng ngôn ngữ.
- Tốt cho memory safety (Infer).
- **Hạn chế**: tỉ lệ FP cao, không có khả năng "giải thích".

### B.2.6. Gitleaks [@gitleaks]

- MIT, detect secret hard-coded (CWE-798).
- Pattern dựa trên regex/entropy.

## B.3. Deep-learning vulnerability detection

### B.3.1. Devign [@zhou2019devign]

- Sử dụng Graph Neural Network trên đồ thị code (AST+CFG+DFG+NCS).
- Train trên 4 dự án C lớn.
- F1 ≈ 0.63 trên dataset của mình.
- **Hạn chế**: chỉ binary classification (vuln/not vuln), không chỉ ra line.

### B.3.2. LineVul, IVDetect, ReGVD

- Transformer-based classifier ở mức line.
- Train trên BigVul.
- F1 line-level cao hơn Devign, nhưng dataset có vấn đề noise [PrimeVul].

### B.3.3. PrimeVul [@ding2024primevul]

- Dataset 6800 cặp vuln/fixed sau khi verify thủ công.
- Chứng minh dataset cũ (BigVul, Devign) có > 20 % noise.
- Trên PrimeVul, F1 của các model SOTA tụt xuống còn ~ 0.3–0.4 → cho thấy
  bài toán *khó hơn* nhiều khi dataset sạch.

### B.3.4. DiverseVul [@chen2023diversevul]

- Dataset C/C++ ~ 18K vuln; bổ sung diversity (nhiều repo).
- Cho thấy model train trên 1 repo không generalize tốt sang repo khác.

## B.4. LLM-based vulnerability detection

### B.4.1. Khảo sát baseline — Khare et al. 2024 [@khare2024understanding]

- Đánh giá GPT-3.5/4, Llama 2, Code-Llama, Vicuna trên hai dataset C/C++.
- Kết luận: LLM zero-shot kém hơn SOTA model train chuyên dụng, nhưng
  few-shot + CoT cải thiện ~ 10 % F1.

### B.4.2. GPTScan [@sun2024gptscan]

- Phát hiện *logic vulnerability* trong Solidity smart contract.
- Kết hợp GPT + static analysis: GPT chia loại lỗ hổng → static tool verify.
- F1 ≈ 0.74 trên benchmark smart contract.
- **CobA học**: phối hợp LLM + static analysis có thể vượt từng tool đơn
  thuần — ngay cả khi static tool khá đơn giản.

### B.4.3. Vul-RAG [@du2024vulrag]

- Sử dụng RAG đưa CWE knowledge vào prompt LLM.
- Improvement ~ 12 pp F1 so với LLM zero-shot trên dataset C.
- **CobA học**: RAG ngữ cảnh CWE là một mảnh ghép thiết yếu để LLM cite
  CWE đúng. CobA thừa hưởng ý tưởng này — mở rộng cho 4 ngôn ngữ.

### B.4.4. LATTE [@liu2024latte]

- LLM-powered binary taint analysis.
- Tách function thành slice → LLM phân tích từng slice.
- Phát hiện 37 zero-day trong firmware thật.
- **CobA học**: slicing per function quan trọng — phù hợp với chiến lược
  chunking của CobA.

### B.4.5. IRIS [@lin2024iris]

- LLM-assisted static analysis: LLM sinh taint rules cho CodeQL.
- Đánh giá trên Java, kết quả cải thiện so với CodeQL gốc.
- **CobA học**: LLM có thể *bổ sung* tool, không chỉ thay thế.

### B.4.6. SeCoRA, VulnDetect, GPTLens [@li2023gptlens]

- Các công trình khác cùng nhóm: LLM + một số dạng grounding.
- GPTLens (smart contract): LLM "auditor" + "critic" (gần với Verifier
  của CobA, nhưng cùng model).

### B.4.7. Tổng kết khoảng trống (research gap)

| Khía cạnh | SAST | DL | LLM zero-shot | LLM + RAG | LLM + Critic | **CobA** |
|---|---|---|---|---|---|---|
| Multi-language | ✓ | × | ✓ | partial | partial | **✓** |
| Inter-procedural | partial | × | × | × | × | **✓ (Joern)** |
| CWE grounding | × | × | × | ✓ | × | **✓** |
| Verifier *khác provider* | × | × | × | × | × | **✓** |
| Offline (local LLM) | ✓ | partial | × | × | × | **✓** |
| Cost-aware routing | × | × | × | × | × | **✓** |
| Open source MIT | partial | partial | × | partial | partial | **✓** |

Cột "CobA" chính là **chỗ đứng** của khoá luận — tổng hợp các ý tưởng đã có
+ bổ sung 3 điểm mới: (1) Verifier khác provider, (2) hybrid cloud + local
router, (3) anti-hallucination 3-layer pipeline.

## B.5. Bộ dữ liệu & benchmark hiện có

| Dataset | Ngôn ngữ | Loại | Ghi chú |
|---|---|---|---|
| PrimeVul | C/C++ | Real CVE, verified | High quality (CobA dùng) |
| OWASP Benchmark v1.2 | Java | Synthetic | Đo FP rate (CobA dùng) |
| Juliet/SARD | C/C++/Java | Synthetic CWE | Public domain |
| BigVul | C/C++ | Real CVE | Noisy theo PrimeVul paper |
| DiverseVul | C/C++ | Real | Bổ sung diversity |
| Devign | C | Real | 4 projects |
| CVEfixes | Multi | Patch commits | RAG corpus tốt |
| Vul4J | Java | Reproducible | 79 mẫu |
| D2A | C/C++ | Infer-based | Noise cao |

Chi tiết license và trust score xem `docs/04_DATA_SOURCES.md`.

## B.6. Công cụ thương mại liên quan

| Tool | Hỗ trợ AI/LLM | Open source | Ghi chú |
|---|---|---|---|
| GitHub Copilot Autofix | Có | × | Hỗ trợ fix, không chuyên phát hiện |
| Snyk Code | Có (DeepCode AI) | × | Cloud only |
| Veracode | Có (AI-assisted triage) | × | Enterprise |
| SonarQube + LLM extensions | Plugin | partial | Tự host |
| CodeQL + Copilot | LLM giải thích | partial | GHES integration |
| Checkmarx | Có | × | Commercial |
| Snyk + Cursor | LLM trong IDE | × | IDE-focused |

CobA *bổ sung* — không cạnh tranh trực tiếp với commercial offerings — bằng
việc:
- Mã nguồn mở (MIT) → research-friendly.
- Đa nhà cung cấp LLM → không vendor-lock.
- Có chế độ offline → phù hợp môi trường nhạy cảm.

## B.7. Định vị CobA so với công trình liên quan

```
                  ┌──────────────┐
                  │  CobA        │ ← Multi-lang + hybrid + Verifier other-provider
                  │  (đề xuất)   │
                  └──────┬───────┘
                         │
        ┌────────────────┼─────────────────┐
        ▼                ▼                 ▼
  ┌──────────┐    ┌──────────┐      ┌──────────┐
  │ Vul-RAG  │    │ GPTScan  │      │ LATTE    │ ← RAG / LLM+SA / LLM+slice
  └──────────┘    └──────────┘      └──────────┘
        │                │                 │
        └────────────────┴─────────────────┘
                         │
                  ┌──────▼──────┐
                  │ LLM baseline│ ← Khare 2024 et al.
                  └─────────────┘
                         │
                  ┌──────▼──────┐
                  │   Devign,   │ ← DL model
                  │  LineVul    │
                  └─────────────┘
                         │
                  ┌──────▼──────┐
                  │  Semgrep,   │ ← SAST cổ điển
                  │  Joern, …   │
                  └─────────────┘
```

## B.8. Khoảng trống mà CobA giải quyết

1. **Verifier khác provider** — chống confirmation bias, chưa được công trình
   trước nghiên cứu hệ thống.
2. **Hybrid cloud + local routing** với fallback offline (Qwen2.5-Coder) —
   chưa có công trình LLM-detection nào tích hợp.
3. **Bao phủ 4 ngôn ngữ phổ biến** trong cùng pipeline thống nhất, không
   phải 1 tool/1 ngôn ngữ.
4. **Đánh giá Pareto cost-vs-accuracy** — chưa có công trình hệ thống đánh
   giá nhiều cấu hình LLM trên cùng pipeline để so sánh.

## B.9. Tóm tắt chương

Chương 3 đã khảo sát 4 nhóm chính (SAST cổ điển, DL, LLM zero-shot,
LLM-agent hybrid) với ~ 20 công trình. Vị trí của CobA là điểm giao của
nhóm 4, bổ sung 4 đóng góp mới so với hiện trạng. Chương 4 sẽ trình bày
kiến trúc chi tiết của CobA.

---

> **TODO** trước khi nộp:
> - Mở rộng phần GPTScan, Vul-RAG, LATTE — mỗi cái 1 hình.
> - Bổ sung kết quả số (F1) của các baseline tại bảng so sánh.
> - Bổ sung 2–3 hình minh hoạ kiến trúc các công trình tiêu biểu.
> - Cập nhật bảng commercial tool với version 2024.
