# ai/llm_engine.py
import os
import json
import re
import ast
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

class LLMEngine:
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY missing in .env")
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel("gemini-2.5-flash")

        # debug log for raw responses to help diagnose parsing issues
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
        # Remove surrounding triple-backtick blocks and optional "```json" header
        t = re.sub(r"^```(?:json)?\s*", "", t, flags=re.IGNORECASE)
        t = re.sub(r"\s*```$", "", t, flags=re.IGNORECASE)
        return t.strip()

    def _extract_text_from_response(self, response):
        """
        Try multiple ways to extract a textual reply from the genai response object.
        Returns a string (possibly empty).
        """
        # 1) try response.text (works if the client created a text accessor)
        try:
            if hasattr(response, "text") and isinstance(response.text, str):
                return response.text
        except Exception:
            pass

        # 2) try response.candidates (common in many LLM client libs)
        try:
            candidates = getattr(response, "candidates", None)
            if candidates:
                # candidate can be a simple string or an object
                first = candidates[0]
                # try common nested fields
                if isinstance(first, str):
                    return first
                # candidate might be an object with .content or .text
                # attempt several likely attribute names
                for attr in ("content", "text", "message", "output"):
                    val = getattr(first, attr, None)
                    if isinstance(val, str):
                        return val
                    # sometimes content is an object with 'parts' or 'text'
                    if hasattr(first, "content"):
                        content = getattr(first, "content")
                        # content may have .parts which is a list of dicts
                        parts = getattr(content, "parts", None) or getattr(content, "text", None)
                        if isinstance(parts, list) and parts:
                            # try to join textual parts
                            texts = []
                            for p in parts:
                                if isinstance(p, str):
                                    texts.append(p)
                                elif isinstance(p, dict):
                                    # dict may have 'text' or 'content' keys
                                    t = p.get("text") or p.get("content") or ""
                                    if isinstance(t, str):
                                        texts.append(t)
                            if texts:
                                return "\n".join(texts)
                        if isinstance(parts, str):
                            return parts
        except Exception:
            pass

        # 3) fallback to str(response)
        try:
            return str(response)
        except Exception:
            return ""

    def _extract_list_candidate(self, text):
        """
        Finds the first [...] substring and returns it (or None).
        """
        if not text:
            return None
        match = re.search(r"\[.*\]", text, flags=re.DOTALL)
        if match:
            return match.group(0)
        return None

    def generate_sql_payloads(self, url, field_name, max_payloads=12):
        """
        Returns a list of SQL payload strings (possibly empty).
        Defensive: never raises on LLM parsing errors.
        """
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
            response = self.model.generate_content(prompt)
            raw_text = self._extract_text_from_response(response)
            # log raw reply
            self._write_debug("RAW_RESPONSE", raw_text)

            if not raw_text or raw_text.strip() == "":
                return []

            cleaned = self._strip_backticks(raw_text)

            # Try JSON first
            try:
                payloads = json.loads(cleaned)
                if isinstance(payloads, list):
                    # ensure strings and limit count
                    out = [str(p) for p in payloads][:max_payloads]
                    return out
            except Exception:
                pass

            # Try to extract bracket substring and json.loads
            candidate = self._extract_list_candidate(cleaned)
            if candidate:
                try:
                    payloads = json.loads(candidate)
                    if isinstance(payloads, list):
                        return [str(p) for p in payloads][:max_payloads]
                except Exception:
                    # try a safe ast eval fallback (after replacing smart quotes)
                    try:
                        safe = candidate.replace("\u2018", "'").replace("\u2019", "'")
                        payloads = ast.literal_eval(safe)
                        if isinstance(payloads, list):
                            return [str(p) for p in payloads][:max_payloads]
                    except Exception:
                        pass

            # Final fallback: extract quoted substrings
            pairs = re.findall(r'"([^"]+)"|\'([^\']+)\'', cleaned)
            flat = []
            for a, b in pairs:
                flat.append(a if a else b)
            if flat:
                # preserve order unique
                seen = set()
                out = []
                for s in flat:
                    if s not in seen:
                        seen.add(s)
                        out.append(s)
                        if len(out) >= max_payloads:
                            break
                return out

            # nothing parsed
            self._write_debug("PARSE_FAILED", cleaned)
            return []
        except Exception as e:
            # log exception + raw_text for debugging but do not raise
            self._write_debug("EXCEPTION", f"{str(e)}\nRAW:\n{raw_text}")
            return []
