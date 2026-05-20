# 10 — GLOSSARY: Từ điển thuật ngữ EN ⇄ VN

| English | Tiếng Việt | Định nghĩa ngắn |
|---|---|---|
| Source code vulnerability | Lỗ hổng mã nguồn | Lỗi/khiếm khuyết trong code có thể bị khai thác |
| Static Application Security Testing (SAST) | Kiểm thử an toàn ứng dụng tĩnh | Phân tích code không thực thi |
| Dynamic Application Security Testing (DAST) | Kiểm thử an toàn ứng dụng động | Phân tích ứng dụng đang chạy |
| Interactive AST (IAST) | Kiểm thử tương tác | Lai SAST + DAST |
| Software Composition Analysis (SCA) | Phân tích thành phần phần mềm | Quét dependency lỗ hổng |
| Common Weakness Enumeration (CWE) | Danh mục các điểm yếu phổ biến | MITRE — phân loại loại lỗ hổng |
| Common Vulnerabilities and Exposures (CVE) | Định danh lỗ hổng | Mỗi CVE là một lỗ hổng cụ thể |
| Common Vulnerability Scoring System (CVSS) | Hệ thang chấm độ nghiêm trọng | 0.0–10.0 |
| Abstract Syntax Tree (AST) | Cây cú pháp trừu tượng | Biểu diễn cấu trúc code |
| Control Flow Graph (CFG) | Đồ thị luồng điều khiển | Các nhánh thực thi của chương trình |
| Data Flow Graph (DFG) | Đồ thị luồng dữ liệu | Các biến chảy giữa câu lệnh |
| Program Dependence Graph (PDG) | Đồ thị phụ thuộc chương trình | Kết hợp DFG + control dependency |
| Code Property Graph (CPG) | Đồ thị thuộc tính mã | AST + CFG + PDG hợp nhất (Joern) |
| Taint analysis | Phân tích vết bẩn | Theo dõi dữ liệu từ source tới sink |
| Source | Nguồn (đầu vào không tin) | E.g. user input, network, file |
| Sink | Điểm chìm (hàm nguy hiểm) | E.g. `eval`, `system`, `db.execute` |
| Sanitizer | Bộ làm sạch | Hàm khử nguy hiểm cho dữ liệu (escape, validate) |
| Large Language Model (LLM) | Mô hình ngôn ngữ lớn | E.g. GPT-4, Claude |
| Prompt | Lời nhắc | Văn bản đầu vào cho LLM |
| Token | Token | Đơn vị xử lý nhỏ nhất của LLM |
| Context window | Cửa sổ ngữ cảnh | Số token tối đa LLM xử lý mỗi lần |
| Few-shot learning | Học vài ví dụ | Inject 2–5 ví dụ vào prompt để LLM bắt chước |
| Chain-of-Thought (CoT) | Chuỗi suy luận | LLM suy luận từng bước trước khi trả lời |
| Retrieval-Augmented Generation (RAG) | Sinh có truy hồi | Lấy snippet từ KB → đưa vào prompt |
| Embedding | Nhúng vector | Biểu diễn text dưới dạng vector cố định |
| Vector database | Cơ sở dữ liệu vector | Lưu embedding + tìm kiếm tương đồng |
| Hallucination | Sự bịa đặt | LLM tạo thông tin không có thật |
| Grounding | Neo (vào ground truth) | Ràng buộc LLM phải cite/match fact |
| Hybrid model | Mô hình lai | Kết hợp nhiều thành phần (LLM + SAST) |
| False positive (FP) | Báo động giả | Báo có vuln nhưng không có |
| False negative (FN) | Bỏ sót | Có vuln nhưng không báo |
| True positive (TP) | Đúng | Báo có vuln, thực sự có |
| True negative (TN) | Đúng âm | Không báo, thực sự không có |
| Precision | Độ chính xác | TP / (TP + FP) |
| Recall | Độ nhạy | TP / (TP + FN) |
| F1 score | Trung bình điều hoà P và R | 2PR/(P+R) |
| Matthews Correlation Coefficient (MCC) | Hệ số tương quan Matthews | Robust với imbalance |
| Ablation study | Nghiên cứu loại bỏ | Tắt 1 thành phần để đo đóng góp |
| Confusion matrix | Ma trận nhầm lẫn | Bảng TP/FP/TN/FN |
| Baseline | Mốc so sánh | Hệ thống cơ sở để so |
| Agent | Tác tử | Hệ thống tự ra quyết định + dùng tool |
| Tool calling / Function calling | Gọi công cụ | LLM gọi function với arg JSON |
| Critique / Verifier | Phê bình / Kiểm chứng | Bước review của LLM khác trên output LLM trước |
| Pipeline | Đường ống | Chuỗi xử lý nối tiếp |
| Orchestrator | Bộ điều phối | Component điều phối các bước |
| Planner | Bộ hoạch định | Component chia task |
| Chunking | Cắt khúc | Chia code/text thành phần nhỏ |
| Quantization | Lượng tử hoá | Giảm độ chính xác trọng số LLM (FP16→INT4) |
| Inference | Suy luận | Chạy model (không train) |
| Fine-tuning | Tinh chỉnh | Train tiếp model trên data riêng |
| In-context learning | Học trong ngữ cảnh | LLM "học" từ few-shot trong prompt |
| Latency | Độ trễ | Thời gian từ request tới response |
| Throughput | Thông lượng | Số request/s |
| Rate limit | Giới hạn tốc độ | Số request/phút API cho phép |
| Container | Container | Đơn vị chạy độc lập (Docker) |
| OWASP Top 10 | Top 10 OWASP | 10 hạng mục lỗ hổng web phổ biến |
| Zero-day | Lỗ hổng chưa được biết | Chưa có patch / chưa public |
| Patch | Vá lỗi | Commit / cập nhật sửa lỗ hổng |
| Reproducibility | Khả năng tái lập | Chạy lại cho cùng kết quả |
| Benchmark | Phép thử so sánh | Dataset chuẩn để đo |
| Pre-commit hook | Hook trước commit | Script chạy trước khi git commit |
| Continuous Integration (CI) | Tích hợp liên tục | Tự động test mỗi push/PR |
