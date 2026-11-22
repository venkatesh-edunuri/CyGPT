"""
CyGPT Local LLM & Threat Intelligence Service

Integrates local Ollama LLM with an offline cybersecurity fallback.

Response flow:
1. Semantic cache lookup
2. Ollama generation
3. Offline CyberKnowledge / heuristic fallback
4. Cache successful responses for future users
"""

import os
import re
import time
import logging
import requests

from django.conf import settings
from knowledgegraph.models import CyberKnowledge
from django.db.models import Q

logger = logging.getLogger(__name__)


# ============================================================
# CYBERSECURITY KEYWORDS
# ============================================================

CYBER_KEYWORDS = [
    "malware",
    "ransomware",
    "phishing",
    "sql injection",
    "xss",
    "csrf",
    "ddos",
    "dos",
    "attack",
    "vulnerability",
    "exploit",
    "zero-day",
    "firewall",
    "encryption",
    "authentication",
    "authorization",
    "mitm",
    "man-in-the-middle",
    "brute force",
    "social engineering",
    "trojan",
    "virus",
    "worm",
    "rootkit",
    "keylogger",
    "spyware",
    "adware",
    "botnet",
    "apt",
    "penetration",
    "pen test",
    "cve",
    "cvss",
    "intrusion",
    "ids",
    "ips",
    "siem",
    "soc",
    "threat",
    "security",
    "cybersecurity",
    "hacking",
    "breach",
    "data leak",
    "privilege escalation",
    "buffer overflow",
    "remote code execution",
    "rce",
    "lateral movement",
]


# ============================================================
# THREAT CODE REMEDIATIONS
# ============================================================

THREAT_CODE_REMEDIATIONS = {
    "SQL Injection": {
        "vulnerable": (
            "```python\n"
            "# VULNERABLE: Direct string interpolation allows payload execution\n"
            "query = f\"SELECT * FROM users WHERE username = '{user_input}' "
            "AND password = '{password}'\"\n"
            "cursor.execute(query)\n"
            "```"
        ),
        "secure": (
            "```python\n"
            "# SECURE: Parameterized query\n"
            "query = \"SELECT * FROM users WHERE username = ? AND password = ?\"\n"
            "cursor.execute(query, (user_input, password))\n"
            "```"
        ),
    },

    "Cross-Site Scripting (XSS)": {
        "vulnerable": (
            "```javascript\n"
            "// VULNERABLE: Direct HTML injection\n"
            "const comment = getQueryParam('comment');\n"
            "document.getElementById('display').innerHTML = comment;\n"
            "```"
        ),
        "secure": (
            "```javascript\n"
            "// SECURE: Render user input as text\n"
            "const comment = getQueryParam('comment');\n"
            "const display = document.getElementById('display');\n"
            "display.textContent = comment;\n"
            "```"
        ),
    },

    "Ransomware": {
        "vulnerable": (
            "```python\n"
            "# INSECURE: Single local file storage\n"
            "with open('invoice.pdf', 'wb') as f:\n"
            "    f.write(data)\n"
            "```"
        ),
        "secure": (
            "```python\n"
            "# SECURE: Isolated backup\n"
            "import shutil\n"
            "import datetime\n"
            "\n"
            "def perform_offline_backup(source_dir, target_remote_mount):\n"
            "    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')\n"
            "    backup_name = f\"secure_backup_{timestamp}\"\n"
            "    shutil.make_archive(\n"
            "        os.path.join(target_remote_mount, backup_name),\n"
            "        'zip',\n"
            "        source_dir,\n"
            "    )\n"
            "```"
        ),
    },

    "Remote Code Execution (RCE)": {
        "vulnerable": (
            "```python\n"
            "# VULNERABLE: Direct shell execution using user input\n"
            "import os\n"
            "os.system(f\"ping -c 1 {user_ip}\")\n"
            "```"
        ),
        "secure": (
            "```python\n"
            "# SECURE: Validate input and avoid shell=True\n"
            "import subprocess\n"
            "import ipaddress\n"
            "\n"
            "def secure_ping(user_ip):\n"
            "    try:\n"
            "        ipaddress.ip_address(user_ip)\n"
            "        result = subprocess.run(\n"
            "            ['ping', '-c', '1', user_ip],\n"
            "            capture_output=True,\n"
            "            text=True,\n"
            "            check=True,\n"
            "        )\n"
            "        return result.stdout\n"
            "    except ValueError:\n"
            "        return 'Error: Invalid IP address.'\n"
            "```"
        ),
    },

    "Cross-Site Request Forgery (CSRF)": {
        "vulnerable": (
            "```html\n"
            "<!-- VULNERABLE: No CSRF token -->\n"
            "<form action=\"/transfer\" method=\"POST\">\n"
            "  <input type=\"hidden\" name=\"amount\" value=\"10000\" />\n"
            "</form>\n"
            "```"
        ),
        "secure": (
            "```html\n"
            "<!-- SECURE: CSRF protection -->\n"
            "<form action=\"/transfer\" method=\"POST\">\n"
            "  {% csrf_token %}\n"
            "  <input type=\"hidden\" name=\"amount\" value=\"10000\" />\n"
            "</form>\n"
            "```"
        ),
    },

    "Brute Force Attack": {
        "vulnerable": (
            "```python\n"
            "# INSECURE: Unlimited login attempts\n"
            "def login(username, password):\n"
            "    return authenticate_user(username, password)\n"
            "```"
        ),
        "secure": (
            "```python\n"
            "# SECURE: Rate limiting and lockout\n"
            "MAX_ATTEMPTS = 5\n"
            "LOCKOUT_TIME = 900\n"
            "\n"
            "def secure_login(username, password):\n"
            "    # Apply rate limiting and account lockout here.\n"
            "    return authenticate_user(username, password)\n"
            "```"
        ),
    },
}


# ============================================================
# AI SERVICE
# ============================================================

class GroqService:
    """
    Groq AI + offline cybersecurity service.

    Semantic cache is optional. If the Chroma service is unavailable,
    normal AI/fallback processing continues without interruption.
    """

    def __init__(self):
        self.groq_api_key = getattr(
            settings,
            "GROQ_API_KEY",
            ""
        )
        self.groq_url = "https://api.groq.com/openai/v1/chat/completions"

        self.primary_model = getattr(
            settings,
            "GROQ_PRIMARY_MODEL",
            "openai/gpt-oss-20b",
        )

        self.backup_model = getattr(
            settings,
            "GROQ_BACKUP_MODEL",
            "groq/compound",
        )

        self.timeout = float(
            getattr(settings, "GROQ_TIMEOUT", 10.0)
        )

        # Lazy-loaded to avoid circular imports.
        self._chroma_service = None

    # ========================================================
    # CHROMA CACHE
    # ========================================================

    def _get_chroma_service(self):
        """
        Lazily load ChromaService.

        Cache must never prevent the chatbot from working.
        """
        if self._chroma_service is not None:
            return self._chroma_service

        try:
            from services.chroma_service import ChromaService

            self._chroma_service = ChromaService()
            return self._chroma_service

        except Exception as exc:
            logger.warning(
                "Semantic cache unavailable: %s",
                exc,
            )
            return None

    def _check_cache(self, user_query):
        """
        Check semantic cache.

        Returns cached response dictionary or None.
        """
        try:
            chroma = self._get_chroma_service()

            if not chroma:
                return None

            result = chroma.check_cache(user_query)

            if not result:
                return None

            # Support either:
            #   {"response": "..."}
            # or the complete response dictionary.
            if isinstance(result, dict):
                cached_response = result.get(
                    "response_payload",
                    result,
                )

                if isinstance(cached_response, dict):
                    return cached_response

            return None

        except Exception as exc:
            logger.warning(
                "Semantic cache lookup failed: %s",
                exc,
            )
            return None

    def _save_to_cache(self, user_query, response_data):
        """
        Save successful response to semantic cache.

        Cache errors are intentionally ignored so they cannot break chat.
        """
        try:
            if not response_data:
                return

            if not response_data.get("success"):
                return

            response_text = response_data.get("response")

            if not response_text or not str(response_text).strip():
                return

            chroma = self._get_chroma_service()

            if not chroma:
                return

            chroma.add_to_cache(
                user_query,
                response_data,
            )

            logger.info(
                "AI response cached successfully."
            )

        except Exception as exc:
            logger.warning(
                "Failed to save AI response to semantic cache: %s",
                exc,
            )

    # ========================================================
    # PROMPTS
    # ========================================================

    def build_system_prompt(self):
        return (
            "You are CyGPT, an AI cybersecurity assistant built specifically for this project. "
            "IMPORTANT RULE: You MUST ONLY answer questions related to cybersecurity, information security, threats, vulnerabilities, or mitigation strategies. "
            "If a user asks about general topics (e.g., cooking, programming not related to security, history, math, writing essays, etc.) "
            "or anything irrelevant to the cybersecurity project, YOU MUST REFUSE TO ANSWER. "
            "Reply strictly with: '🌐 CyGPT Advisory: I am configured to work only for this cybersecurity project. I can only assist with cybersecurity topics.' "
            "For valid cybersecurity questions, answer only what the user asks concisely. "
            "Use standard markdown only when useful."
        )

    def build_enhanced_prompt(
        self,
        user_query: str,
        knowledge_context: str,
    ) -> str:

        prompt = (
            f"System Instruction:\n"
            f"{self.build_system_prompt()}\n\n"
            f"User Question:\n"
            f"{user_query}\n\n"
        )

        if knowledge_context:
            prompt += (
                "Relevant Cybersecurity Knowledge:\n"
                f"{knowledge_context}\n\n"
                "Use this information only when it directly answers "
                "the user's question.\n"
            )
        else:
            prompt += (
                "Answer the user's cybersecurity question accurately "
                "and concisely.\n"
            )

        return prompt

    # ========================================================
    # MAIN QUERY
    # ========================================================

    def query(
        self,
        user_query: str,
        knowledge_context: str = "",
        username: str = None,
    ) -> dict:
        """
        Main AI response flow.

        Cache → Ollama → Offline fallback → Cache.
        """

        user_query = (user_query or "").strip()

        if not user_query:
            return {
                "response": "Please enter a question.",
                "tokens_used": 0,
                "success": False,
            }

        # ----------------------------------------------------
        # 1. SEMANTIC CACHE
        # ----------------------------------------------------

        cached_response = self._check_cache(user_query)

        if cached_response:
            logger.info(
                "Semantic cache HIT for query: %s",
                user_query[:100],
            )

            # Mark internally as cached.
            # Do not expose implementation details in response text.
            cached_response = dict(cached_response)
            cached_response["cached"] = True

            return cached_response

        logger.info(
            "Semantic cache MISS for query: %s",
            user_query[:100],
        )

        # ----------------------------------------------------
        # 2. GROQ
        # ----------------------------------------------------

        groq_response = self._query_groq(
            user_query,
            knowledge_context,
        )

        if groq_response:
            self._save_to_cache(
                user_query,
                groq_response,
            )

            return groq_response

        # ----------------------------------------------------
        # 3. OFFLINE FALLBACK
        # ----------------------------------------------------

        logger.info(
            "Groq AI unavailable or missing key. Using offline cybersecurity engine."
        )

        fallback_response = (
            self._generate_dynamic_expert_synthesis(
                user_query,
                username,
            )
        )

        if fallback_response:
            self._save_to_cache(
                user_query,
                fallback_response,
            )

        return fallback_response

    # ========================================================
    # GROQ API
    # ========================================================

    def _query_groq(
        self,
        user_query: str,
        knowledge_context: str,
    ) -> dict:

        if not self.groq_api_key:
            return None

        enhanced_prompt = self.build_enhanced_prompt(
            user_query,
            knowledge_context,
        )

        for model in [
            self.primary_model,
            self.backup_model,
        ]:

            try:
                response = requests.post(
                    self.groq_url,
                    headers={
                        "Authorization": f"Bearer {self.groq_api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": model,
                        "messages": [{"role": "user", "content": enhanced_prompt}],
                    },
                    timeout=self.timeout,
                )

                if response.status_code != 200:
                    logger.warning(f"Groq API error {response.status_code}: {response.text}")
                    continue

                result = response.json()

                content = result.get("choices", [{}])[0].get("message", {}).get("content", "").strip()

                if not content:
                    continue

                return {
                    "response": content,
                    "tokens_used": result.get("usage", {}).get("total_tokens", len(content.split())),
                    "success": True,
                    "provider": "groq",
                    "model": model,
                    "cached": False,
                }

            except requests.exceptions.RequestException as exc:
                logger.error(
                    "Network error querying Groq model %s: %s",
                    model,
                    exc,
                )
                continue

            except Exception as exc:
                logger.error(
                    "Error parsing Groq model %s response: %s",
                    model,
                    exc,
                )
                continue

        return None

    # ========================================================
    # OFFLINE EXPERT SYNTHESIS
    # ========================================================

    def _generate_dynamic_expert_synthesis(
        self,
        query: str,
        username: str = None,
    ) -> dict:

        query_lower = query.lower().strip()

        # ----------------------------------------------------
        # 1. GREETINGS
        # ----------------------------------------------------

        greetings = [
            "hi",
            "hello",
            "hey",
            "greetings",
            "good morning",
            "good afternoon",
            "good evening",
            "sup",
            "howdy",
        ]

        words = query_lower.split()

        is_greeting = (
            len(words) <= 3
            and any(g in words for g in greetings)
        )

        if is_greeting:
            greeting_name = (
                f" {username.title()},"
                if username
                else ","
            )

            greeting_response = (
                f"Hello{greeting_name} "
                "I am CyGPT, your cybersecurity assistant. "
                "How can I help you?"
            )

            return {
                "response": greeting_response,
                "tokens_used": len(
                    greeting_response.split()
                ),
                "success": True,
                "provider": "offline",
                "model": "heuristic",
                "cached": False,
            }

        # ----------------------------------------------------
        # 2. INTENT DETECTION
        # ----------------------------------------------------

        intent_query = (
            query_lower
            .replace("remote code execution", "")
            .replace("rce", "")
        )

        code_words = [
            "script",
            "program",
            "write",
            "example",
            "develop",
            "implement",
        ]

        is_code_request = (
            any(w in intent_query for w in code_words)
            or re.search(
                r"\bcode\b",
                intent_query,
            )
            is not None
        )

        prevention_words = [
            "prevent",
            "mitigate",
            "stop",
            "defend",
            "fix",
            "remediate",
            "protection",
        ]

        is_prevention_request = (
            any(
                w in intent_query
                for w in prevention_words
            )
            or re.search(
                r"\bsecure\b",
                intent_query,
            )
            is not None
        )

        is_workflow_request = any(
            w in intent_query
            for w in [
                "how does",
                "how do",
                "mechanism",
                "workflow",
                "process",
                "steps",
                "execute",
                "work",
            ]
        )

        # ----------------------------------------------------
        # 3. MATCH KNOWLEDGE GRAPH
        # ----------------------------------------------------

        matched_keywords = [
            kw
            for kw in CYBER_KEYWORDS
            if kw in query_lower
        ]

        generic_kws = {
            "attack",
            "vulnerability",
            "exploit",
            "threat",
            "security",
            "cybersecurity",
            "hacking",
            "breach",
            "dos",
        }

        specific_kws = [
            kw
            for kw in matched_keywords
            if kw not in generic_kws
        ]

        if specific_kws:
            matched_keywords = specific_kws

        q_filter = Q()

        for kw in matched_keywords:
            q_filter |= (
                Q(
                    threat_name__icontains=kw
                )
                |
                Q(
                    threat_type__icontains=kw
                )
            )

        results = []
        seen_ids = set()

        all_threats = CyberKnowledge.objects.all()

        for threat in all_threats:

            threat_words = set(
                threat.threat_name.lower().split()
            )

            query_words = set(
                query_lower.split()
            )

            if (
                threat.threat_name.lower()
                in query_lower
            ):
                results.append(threat)
                seen_ids.add(threat.id)

            elif (
                threat_words.intersection(
                    query_words
                )
                and len(threat_words) <= 2
            ):
                results.append(threat)
                seen_ids.add(threat.id)

        if q_filter and not results:

            broad_matches = (
                CyberKnowledge.objects
                .filter(q_filter)
                .order_by("-risk_score")
            )

            for match in broad_matches:

                if len(results) >= 2:
                    break

                if match.id not in seen_ids:
                    results.append(match)
                    seen_ids.add(match.id)

        # ----------------------------------------------------
        # 4. GENERATE DATABASE-BASED RESPONSE
        # ----------------------------------------------------

        if results:

            primary_threat = results[0]

            threat_name = primary_threat.threat_name

            sev_upper = (
                primary_threat.severity.upper()
            )

            sev_badge = (
                "🔴 CRITICAL"
                if sev_upper == "CRITICAL"
                else "🟠 HIGH"
                if sev_upper == "HIGH"
                else "🟡 MEDIUM"
                if sev_upper == "MEDIUM"
                else "🟢 LOW"
            )

            response_parts = [
                f"### 🛡️ {threat_name}",
            ]

            # CODE
            if is_code_request:

                snippets = (
                    THREAT_CODE_REMEDIATIONS.get(
                        threat_name
                    )
                )

                if snippets:

                    response_parts.append(
                        "#### Secure Implementation"
                    )

                    response_parts.append(
                        snippets["secure"]
                    )

                else:

                    response_parts.append(
                        f"To mitigate **{threat_name}**, "
                        "validate input, use secure APIs, "
                        "apply least privilege, and keep "
                        "dependencies patched."
                    )

            # PREVENTION
            elif is_prevention_request:

                response_parts.append(
                    f"#### Prevention"
                )

                prevention_points = (
                    primary_threat.prevention
                    .split(". ")
                )

                for point in prevention_points:

                    if point.strip():

                        response_parts.append(
                            f"- {point.strip().rstrip('.')}"
                        )

            # WORKFLOW
            elif is_workflow_request:

                response_parts.append(
                    "#### How it works"
                )

                attack_steps = (
                    primary_threat.attack_method
                    .split(". ")
                )

                for i, step in enumerate(
                    attack_steps,
                    start=1,
                ):

                    if step.strip():

                        response_parts.append(
                            f"{i}. "
                            f"{step.strip().rstrip('.')}"
                        )

            # DEFAULT
            else:

                response_parts.append(
                    primary_threat.description
                )

            response_text = "\n\n".join(
                response_parts
            )

            return {
                "response": response_text,
                "tokens_used": len(
                    response_text.split()
                ),
                "success": True,
                "provider": "offline",
                "model": "knowledge_graph",
                "cached": False,
            }

        # ----------------------------------------------------
        # 5. BUILT-IN KNOWLEDGE
        # ----------------------------------------------------

        if matched_keywords:

            keyword = matched_keywords[0].upper()

            fallback_knowledge = {

                "SQL INJECTION":
                    "SQL Injection (SQLi) is a vulnerability "
                    "where an application improperly handles "
                    "user input, allowing unauthorized SQL "
                    "commands to be executed.",

                "XSS":
                    "Cross-Site Scripting (XSS) is a vulnerability "
                    "that allows malicious scripts to execute "
                    "in a user's browser.",

                "RANSOMWARE":
                    "Ransomware is malware that encrypts data "
                    "or blocks system access and demands payment.",

                "PHISHING":
                    "Phishing is a social-engineering attack "
                    "that tricks users into revealing sensitive "
                    "information.",

                "DDOS":
                    "A Distributed Denial-of-Service (DDoS) attack "
                    "overwhelms a service with traffic to make it "
                    "unavailable.",

                "DOS":
                    "A Denial-of-Service (DoS) attack attempts "
                    "to make a system or network unavailable.",

                "MALWARE":
                    "Malware is software intentionally designed "
                    "to damage systems, disrupt operations, "
                    "or gain unauthorized access.",

                "CSRF":
                    "Cross-Site Request Forgery (CSRF) tricks an "
                    "authenticated user into performing an unwanted "
                    "action on a web application.",

                "BRUTE FORCE":
                    "A brute-force attack repeatedly attempts "
                    "different credentials until valid credentials "
                    "are discovered.",
            }

            desc = fallback_knowledge.get(
                keyword,
                f"{keyword.title()} is a recognized "
                "cybersecurity concept or threat."
            )

            general_response = desc

            return {
                "response": general_response,
                "tokens_used": len(
                    general_response.split()
                ),
                "success": True,
                "provider": "offline",
                "model": "built_in_knowledge",
                "cached": False,
            }

        # ----------------------------------------------------
        # 6. FINAL FALLBACK
        # ----------------------------------------------------

        general_response = (
            "🌐 CyGPT Advisory: I am configured to work only for this cybersecurity project. "
            "I can only assist with cybersecurity topics. Please provide a specific cybersecurity question."
        )

        return {
            "response": general_response,
            "tokens_used": len(
                general_response.split()
            ),
            "success": True,
            "provider": "offline",
            "model": "fallback",
            "cached": False,
        }