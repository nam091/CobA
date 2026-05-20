# Tóm tắt

Phát hiện lỗ hổng an toàn trong mã nguồn là bài toán kinh điển nhưng vẫn còn
nhiều thách thức: công cụ phân tích tĩnh truyền thống (SAST) có độ phủ rộng
nhưng tỉ lệ báo động giả (false positive) cao; ngược lại, các giải pháp dựa
trên Mô hình ngôn ngữ lớn (Large Language Model — LLM) hiện đạt khả năng suy
luận tốt nhưng dễ "bịa" (hallucination), thiếu căn cứ trên cấu trúc chương
trình và tốn kém về chi phí lẫn quyền riêng tư khi gọi API đám mây.

Khoá luận này đề xuất **CobA** (Code-base Audit) — một *tác tử lai*
(hybrid agent) kết hợp công cụ SAST sẵn có (Semgrep, Bandit, Gitleaks, Joern)
với LLM nhằm phát hiện lỗ hổng đa ngôn ngữ (Python, Java, C/C++, JavaScript).
CobA sử dụng (1) chiến lược cắt khúc mã *function-level* dựa trên AST/CPG,
(2) cơ chế *Retrieval-Augmented Generation* (RAG) lấy ngữ cảnh CWE/CVE,
(3) bộ định tuyến mô hình lai (cloud + local) với dự phòng ngoại tuyến bằng
Qwen2.5-Coder, và (4) bước *Verifier* phê bình bằng một LLM khác để giảm
false positive.

Hệ thống được đánh giá trên hai bộ dữ liệu chuẩn — *PrimeVul*-1K (1000 cặp
mã có/không lỗ hổng) và *OWASP Benchmark v1.2* (2740 mẫu Java). Kết quả kỳ
vọng: F1 ≥ 0.55 trên PrimeVul, FP rate ≤ 25 % trên OWASP, thời gian < 10
phút cho 50K LOC, chi phí < 0.5 USD/repo.

Đóng góp chính: (i) kiến trúc agent lai SAST + LLM với 3 lớp chống ảo giác;
(ii) thư viện mã nguồn mở Python có CLI/REST API; (iii) bộ chuẩn so sánh
8 cấu hình LLM (GPT-4o-mini, Claude 3.5 Sonnet/Haiku, Gemini 1.5 Flash,
Qwen2.5-Coder 7B/32B…) trên cùng pipeline; (iv) tài liệu hoá đầy đủ (12 file
thiết kế, BibTeX) để tái lập.

**Từ khoá**: lỗ hổng mã nguồn, LLM, RAG, CWE, SAST, Code Property Graph,
agent, phân tích an toàn.

---

# Abstract

Detecting vulnerabilities in source code remains a long-standing challenge:
Static Application Security Testing (SAST) tools have broad coverage but
suffer high false-positive rates, while LLM-based approaches reason well
about semantics but frequently hallucinate, lack program-structural grounding,
and raise privacy/cost concerns when calling cloud APIs.

This thesis proposes **CobA** (Code-base Audit), a *hybrid agent* that
combines existing SAST tools (Semgrep, Bandit, Gitleaks, Joern) with LLMs to
detect vulnerabilities across multiple languages (Python, Java, C/C++,
JavaScript). CobA introduces (1) a function-level code chunking strategy
based on AST/CPG, (2) a Retrieval-Augmented Generation pipeline grounded in
CWE/CVE, (3) a hybrid model router (cloud + local) with offline fallback via
Qwen2.5-Coder, and (4) a Verifier critique step using a second LLM to reduce
false positives.

We evaluate on two standard benchmarks — PrimeVul-1K and OWASP Benchmark
v1.2. Expected outcomes: F1 ≥ 0.55 on PrimeVul, FP rate ≤ 25 % on OWASP,
< 10 min for 50K LOC, and < 0.5 USD per repository.

**Keywords**: source code vulnerability, LLM, RAG, CWE, SAST,
Code Property Graph, agent, security analysis.
