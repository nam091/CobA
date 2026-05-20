# `examples/` — smoke test corpora

Small, deliberately-vulnerable code samples used by the smoke tests and demos.

| File | Languages | CWE demonstrated |
|---|---|---|
| `vulnerable_python.py` | Python | CWE-89, 78, 94, 502, 22, 327, 798, 330, 918, 732 |
| `safe_python.py` | Python | (none — negative control) |
| `vulnerable_java/SqlInjection.java` | Java | CWE-89, 78 |
| `vulnerable_c/strcpy_overflow.c` | C | CWE-787 |
| `vulnerable_js/xss_express.js` | JavaScript | CWE-79, 918, 94 |

**Do not run** any of these files — they are illustrative only.

Demo:
```bash
coba scan examples/vulnerable_python.py -o /tmp/report.json
```
