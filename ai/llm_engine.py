# ai/llm_engine.py
import os
import json
import re
import time
import ast
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

class LLMEngine:
    """
    Robust wrapper around Gemini calls.
    - Uses GEMINI_API_KEY from .env (GEMINI_API_KEY).
    - Caches results per key in-memory for the run.
    - Provides a static fallback payload list if LLM fails or is rate-limited.
    - Defensive parsing of LLM output to produce a Python list of strings.
    """

    STATIC_SQLI_PAYLOADS = [
        "' OR 1=1 --",
        "' OR '1'='1' --",
        "\" OR \"\"=\"\"",
        "admin' --",
        "' OR 'a'='a",
        "' UNION SELECT NULL --",
        "' UNION SELECT 1, database(), user() --",
        "' AND SLEEP(5) --",
        "'; SELECT SLEEP(5) --",
        "'; DROP TABLE users; --",
        "1' OR '1'='1",
        "' OR 'x'='x"
    ]

    STATIC_XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'\"><img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert(1)>",
        "javascript:alert(1)",
        "<img src=x onerror=alert(document.domain)>",
        "<svg><script>alert(1)</script></svg>",
        "'\"><svg/onload=alert(String.fromCharCode(88,83,83))>"
    ]

    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY (or GOOGLE_API_KEY) missing in .env")
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel("gemini-2.5-flash")
        self.cache = {}  # simple in-memory cache for payloads
        # debug file
        self.debug_path = os.path.join("data", "llm_raw_responses.log")
        os.makedirs(os.path.dirname(self.debug_path), exist_ok=True)

    def _write_debug(self, tag, content):
        try:
            with open(self.debug_path, "a", encoding="utf-8") as fh:
                fh.write(f"--- {tag} ---\n")
                fh.write(content + "\n\n")
        except Exception:
            pass

    def _strip_backticks(self, text):
        if not isinstance(text, str):
            return ""
        t = text.strip()
        t = re.sub(r"^```(?:json)?\s*", "", t, flags=re.IGNORECASE)
        t = re.sub(r"\s*```$", "", t, flags=re.IGNORECASE)
        return t.strip()

    def _extract_text_from_response(self, response):
        """
        Try to extract a textual body from the Gemini response object.
        Return string (possibly empty).
        """
        try:
            if hasattr(response, "text") and isinstance(response.text, str):
                return response.text
        except Exception:
            pass

        try:
            candidates = getattr(response, "candidates", None)
            if candidates:
                first = candidates[0]
                if isinstance(first, str):
                    return first
                # common nested places
                for attr in ("content", "text", "message", "output"):
                    val = getattr(first, attr, None)
                    if isinstance(val, str):
                        return val
                # check for parts structure
                content = getattr(first, "content", None)
                if content:
                    parts = getattr(content, "parts", None) or getattr(content, "text", None)
                    if isinstance(parts, list) and parts:
                        texts = []
                        for p in parts:
                            if isinstance(p, str):
                                texts.append(p)
                            elif isinstance(p, dict):
                                t = p.get("text") or p.get("content") or ""
                                if isinstance(t, str):
                                    texts.append(t)
                        if texts:
                            return "\n".join(texts)
                    if isinstance(parts, str):
                        return parts
        except Exception:
            pass

        try:
            return str(response)
        except Exception:
            return ""

    def _extract_list_candidate(self, text):
        if not text:
            return None
        match = re.search(r"\[.*\]", text, flags=re.DOTALL)
        if match:
            return match.group(0)
        return None

    def generate_sql_payloads(self, url, field_name, max_payloads=12):
        """
        Returns a list of SQLi payload strings.
        Defensive: never raises on network/LLM parsing errors.
        Caches results per key to avoid repeated LLM calls.
        """
        key = f"sqli::{field_name}"  # coarse-grained cache key (per field)
        if key in self.cache:
            return self.cache[key]

        prompt = f"""
Return ONLY a JSON array (no explanation, no backticks, no extra text).
Each element must be a SQL injection payload string.

Example:
["' OR 1=1 --", "' OR 'a'='a", "admin' --"]

Target:
URL: {url}
Field: {field_name}

Return at most {max_payloads} payloads.
"""
        raw_text = ""
        try:
            # protective loop with small backoff for transient rate limits
            for attempt in range(1, 4):
                try:
                    response = self.model.generate_content(prompt)
                    raw_text = self._extract_text_from_response(response)
                    break
                except Exception as e:
                    # if ratelimit contains 'quota' or similar, backoff a bit
                    err = str(e).lower()
                    if "quota" in err or "rate limit" in err:
                        wait = 2 ** attempt
                        time.sleep(wait)
                        continue
                    # other errors -> break and fallback
                    raw_text = f"EXCEPTION:{str(e)}"
                    break

            if not raw_text or raw_text.strip() == "":
                # LLM returned nothing -> fallback
                self._write_debug("RAW_EMPTY", raw_text or "<empty>")
                payloads = list(self.STATIC_SQLI_PAYLOADS)[:max_payloads]
                self.cache[key] = payloads
                return payloads

            self._write_debug("RAW_RESPONSE", raw_text)

            cleaned = self._strip_backticks(raw_text)

            # Try JSON load first
            try:
                payloads = json.loads(cleaned)
                if isinstance(payloads, list):
                    out = [str(p) for p in payloads][:max_payloads]
                    self.cache[key] = out
                    return out
            except Exception:
                pass

            # try to find bracketed list substring
            candidate = self._extract_list_candidate(cleaned)
            if candidate:
                try:
                    payloads = json.loads(candidate)
                    if isinstance(payloads, list):
                        out = [str(p) for p in payloads][:max_payloads]
                        self.cache[key] = out
                        return out
                except Exception:
                    # fallback to ast literal eval after normalizing quotes
                    try:
                        safe = candidate.replace("\u2018", "'").replace("\u2019", "'")
                        payloads = ast.literal_eval(safe)
                        if isinstance(payloads, list):
                            out = [str(p) for p in payloads][:max_payloads]
                            self.cache[key] = out
                            return out
                    except Exception:
                        pass

            # final fallback: extract quoted strings
            pairs = re.findall(r'"([^"]+)"|\'([^\']+)\'', cleaned)
            flat = []
            for a, b in pairs:
                flat.append(a if a else b)
            if flat:
                seen = set()
                out = []
                for s in flat:
                    if s not in seen:
                        seen.add(s)
                        out.append(s)
                        if len(out) >= max_payloads:
                            break
                self.cache[key] = out
                return out

            # if everything fails, fall back to static list
            self._write_debug("PARSE_FAILED", cleaned)
            payloads = list(self.STATIC_SQLI_PAYLOADS)[:max_payloads]
            self.cache[key] = payloads
            return payloads

        except Exception as e:
            self._write_debug("EXCEPTION", f"{str(e)}\nRAW:\n{raw_text}")
            # last-resort fallback
            payloads = list(self.STATIC_SQLI_PAYLOADS)[:max_payloads]
            self.cache[key] = payloads
            return payloads

    def get_xss_payloads(self, max_payloads=10):
        """
        Returns a list of XSS payload strings.
        Defensive: never raises on network/LLM parsing errors.
        Caches results to avoid repeated LLM calls.
        """
        key = "xss::payloads"
        if key in self.cache:
            return self.cache[key]

        prompt = f"""
Return ONLY a JSON array of XSS payloads (no explanation, no backticks, no extra text).
Each element must be a cross-site scripting payload string.

Example:
["<script>alert(1)</script>", "'\"><img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"]

Return at most {max_payloads} creative and effective XSS payloads.
"""
        raw_text = ""
        try:
            # protective loop with small backoff for transient rate limits
            for attempt in range(1, 4):
                try:
                    response = self.model.generate_content(prompt)
                    raw_text = self._extract_text_from_response(response)
                    break
                except Exception as e:
                    err = str(e).lower()
                    if "quota" in err or "rate limit" in err:
                        wait = 2 ** attempt
                        time.sleep(wait)
                        continue
                    raw_text = f"EXCEPTION:{str(e)}"
                    break

            if not raw_text or raw_text.strip() == "":
                self._write_debug("XSS_RAW_EMPTY", raw_text or "<empty>")
                payloads = list(self.STATIC_XSS_PAYLOADS)[:max_payloads]
                self.cache[key] = payloads
                return payloads

            self._write_debug("XSS_RAW_RESPONSE", raw_text)

            cleaned = self._strip_backticks(raw_text)

            # Try JSON load first
            try:
                payloads = json.loads(cleaned)
                if isinstance(payloads, list):
                    out = [str(p) for p in payloads][:max_payloads]
                    self.cache[key] = out
                    return out
            except Exception:
                pass

            # try to find bracketed list substring
            candidate = self._extract_list_candidate(cleaned)
            if candidate:
                try:
                    payloads = json.loads(candidate)
                    if isinstance(payloads, list):
                        out = [str(p) for p in payloads][:max_payloads]
                        self.cache[key] = out
                        return out
                except Exception:
                    try:
                        safe = candidate.replace("\u2018", "'").replace("\u2019", "'")
                        payloads = ast.literal_eval(safe)
                        if isinstance(payloads, list):
                            out = [str(p) for p in payloads][:max_payloads]
                            self.cache[key] = out
                            return out
                    except Exception:
                        pass

            # final fallback: extract quoted strings
            pairs = re.findall(r'"([^"]+)"|\'([^\']+)\'', cleaned)
            flat = []
            for a, b in pairs:
                flat.append(a if a else b)
            if flat:
                seen = set()
                out = []
                for s in flat:
                    if s not in seen:
                        seen.add(s)
                        out.append(s)
                        if len(out) >= max_payloads:
                            break
                self.cache[key] = out
                return out

            # if everything fails, fall back to static list
            self._write_debug("XSS_PARSE_FAILED", cleaned)
            payloads = list(self.STATIC_XSS_PAYLOADS)[:max_payloads]
            self.cache[key] = payloads
            return payloads

        except Exception as e:
            self._write_debug("XSS_EXCEPTION", f"{str(e)}\nRAW:\n{raw_text}")
            payloads = list(self.STATIC_XSS_PAYLOADS)[:max_payloads]
            self.cache[key] = payloads
            return payloads