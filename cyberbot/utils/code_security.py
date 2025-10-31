import re
import difflib
from ..services.llm_service import analyze_code_with_ai


def analyze_and_fix_code(source_code: str, language: str = "auto", use_ai: bool = True) -> dict:
    """
    Analyze a code snippet for common security issues and propose fixes.
    Combines rule-based analysis with AI-powered deep analysis.

    Args:
        source_code: The code to analyze
        language: Programming language (e.g., 'python', 'javascript', 'auto')
        use_ai: Whether to use AI analysis (default: True)

    Returns:
        dict with keys: issues (combined), fixed_code, diff, summary, ai_analysis, best_practices
    """
    if not isinstance(source_code, str) or not source_code.strip():
        return {
            "issues": [],
            "fixed_code": source_code or "",
            "diff": "",
            "summary": "No code provided",
            "ai_analysis": {},
            "best_practices": []
        }

    lang = detect_language(source_code) if language == "auto" else language.lower()

    # Step 1: Rule-based analysis (fast, deterministic)
    issues, fixed = [], source_code

    if lang in ("python", "py"):
        issues, fixed = analyze_python(source_code)
    elif lang in ("javascript", "js", "node"):
        issues, fixed = analyze_javascript(source_code)
    else:
        # Fallback generic checks
        generic_issues, generic_fixed = analyze_generic(source_code)
        issues.extend(generic_issues)
        fixed = generic_fixed

    # Step 2: AI-powered analysis (deep insights, best practices)
    ai_analysis = {}
    best_practices = []
    ai_fixed_code = fixed
    
    if use_ai:
        try:
            ai_analysis = analyze_code_with_ai(source_code, lang, issues)
            best_practices = ai_analysis.get("best_practices", [])
            ai_fixed_code = ai_analysis.get("ai_fixes", fixed)
            
            # Merge AI issues with rule-based issues (avoid duplicates)
            ai_issues = ai_analysis.get("ai_issues", [])
            existing_lines = {iss.get("line") for iss in issues}
            
            for ai_issue in ai_issues:
                ai_line = ai_issue.get("line")
                # Add AI issue if it's on a different line or provides new insights
                if ai_line not in existing_lines or ai_issue.get("vulnerability") not in [iss.get("id", "") for iss in issues]:
                    issues.append({
                        "id": f"ai_{ai_issue.get('vulnerability', 'unknown')}",
                        "line": ai_line,
                        "severity": ai_issue.get("severity", "medium"),
                        "message": ai_issue.get("description", ""),
                        "explanation": ai_issue.get("explanation", ""),
                        "fix_suggestion": ai_issue.get("fix_suggestion", ""),
                        "vulnerability": ai_issue.get("vulnerability", ""),
                        "source": "ai"
                    })
        except Exception as e:
            print(f"[WARNING] AI analysis failed: {str(e)}")
            ai_analysis = {"error": str(e)}

    # Use AI-fixed code if available and different, otherwise use rule-based fixed code
    final_fixed_code = ai_fixed_code if ai_fixed_code != source_code and ai_fixed_code != fixed else fixed

    diff = "\n".join(difflib.unified_diff(
        source_code.splitlines(),
        final_fixed_code.splitlines(),
        fromfile="original",
        tofile="fixed",
        lineterm=""
    ))

    # Enhanced summary
    rule_count = len([i for i in issues if i.get("source") != "ai"])
    ai_count = len([i for i in issues if i.get("source") == "ai"])
    
    summary = summarize_issues(issues)
    if ai_analysis.get("summary"):
        summary = f"{ai_analysis.get('summary')}\n\nRule-based: {rule_count} issue(s) | AI-detected: {ai_count} issue(s)"

    return {
        "language": lang,
        "issues": issues,
        "fixed_code": final_fixed_code,
        "diff": diff,
        "summary": summary,
        "ai_analysis": ai_analysis,
        "best_practices": best_practices,
        "rule_based_count": rule_count,
        "ai_count": ai_count
    }


def detect_language(code: str) -> str:
    # Heuristics
    if re.search(r"^\s*import\s+|def\s+|print\(|from\s+\w+\s+import", code, re.MULTILINE):
        return "python"
    if re.search(r"function\s+\w+\(|=>|console\.log|document\.", code):
        return "javascript"
    return "generic"


def summarize_issues(issues: list) -> str:
    if not issues:
        return "No obvious security issues detected by static rules."
    severities = {i.get("severity", "low") for i in issues}
    return f"Detected {len(issues)} issue(s). Severities: {', '.join(sorted(severities))}."


def analyze_generic(code: str):
    issues = []
    fixed = code

    # Hardcoded secrets
    secret_patterns = [
        r"(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{12,})['\"]",
    ]
    for pat in secret_patterns:
        for m in re.finditer(pat, code):
            issues.append({
                "id": "hardcoded_secret",
                "message": "Hardcoded secret detected. Use environment variables or secret manager.",
                "severity": "high",
                "line": get_line_number(code, m.start())
            })
            fixed = re.sub(pat, r"\1 = os.getenv('REDACTED_ENV_VAR')", fixed)

    return issues, fixed


def analyze_python(code: str):
    issues = []
    fixed = code

    # Ensure os import if we replace secrets
    needs_os_import = False

    checks = [
        (r"\beval\(", "Avoid eval(); use safe parsing/whitelisting instead.", "high"),
        (r"\bexec\(", "Avoid exec(); refactor to explicit logic.", "high"),
        (r"subprocess\.[Pp]open\(.*shell\s*=\s*True", "subprocess with shell=True is dangerous. Set shell=False and pass args list.", "high"),
        (r"os\.system\(", "os.system can be unsafe with user input. Use subprocess.run with args list.", "medium"),
        (r"pickle\.loads\(", "Untrusted pickle deserialization is unsafe. Use safer formats (JSON) or restrict sources.", "high"),
        (r"yaml\.load\(.*\)", "Use yaml.safe_load instead of yaml.load.", "high"),
        (r"hashlib\.(md5|sha1)\(", "Weak hash algorithm. Prefer SHA-256/512 or a KDF like bcrypt/Argon2.", "medium"),
        (r"requests\.[a-z]+\(.*verify\s*=\s*False", "TLS verification disabled. Remove verify=False.", "high"),
        (r"Flask\(.*\)\s*.*debug\s*=\s*True|app\.run\(.*debug\s*=\s*True", "Flask debug=True leaks internals. Disable in production.", "medium"),
    ]

    for pattern, message, severity in checks:
        for m in re.finditer(pattern, code, re.DOTALL):
            issues.append({
                "id": f"py_{pattern}",
                "message": message,
                "severity": severity,
                "line": get_line_number(code, m.start())
            })

    # Fixes (simple, conservative replacements)
    fixed = re.sub(r"yaml\.load\(", "yaml.safe_load(", fixed)
    fixed = re.sub(r"requests\.(get|post|put|patch|delete)\(([^)]*?)verify\s*=\s*False(,)?\s*", r"requests.\1(\2", fixed)

    # Hardcoded secrets replacement
    secret_pat = r"(?i)(\b(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD)\b\s*[:=]\s*)['\"]([A-Za-z0-9_\-]{8,})['\"]"
    if re.search(secret_pat, fixed):
        needs_os_import = True
        fixed = re.sub(secret_pat, r"\1os.getenv('REDACTED_ENV_VAR')", fixed)

    if needs_os_import and not re.search(r"^\s*import\s+os\b", fixed, re.MULTILINE):
        fixed = "import os\n" + fixed

    return issues, fixed


def analyze_javascript(code: str):
    issues = []
    fixed = code

    checks = [
        (r"\beval\(", "Avoid eval(); use JSON.parse or explicit logic.", "high"),
        (r"document\.write\(", "document.write can be abused for XSS. Avoid it.", "medium"),
        (r"innerHTML\s*=", "Assigning to innerHTML can cause XSS. Use textContent or safe templating.", "high"),
        (r"localStorage\.(setItem|\[)", "Storing sensitive data in localStorage is unsafe.", "medium"),
        (r"http://", "Insecure HTTP detected. Use HTTPS for sensitive operations.", "medium"),
    ]

    for pattern, message, severity in checks:
        for m in re.finditer(pattern, code):
            issues.append({
                "id": f"js_{pattern}",
                "message": message,
                "severity": severity,
                "line": get_line_number(code, m.start())
            })

    # Simple fix: innerHTML -> textContent when assigning plain variables
    fixed = re.sub(r"\.innerHTML\s*=", ".textContent =", fixed)

    return issues, fixed


def get_line_number(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1