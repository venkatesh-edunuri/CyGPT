"""
Response Evaluation Module
- Keyword relevance checking
- Hallucination detection
- Confidence scoring
- Verification status
"""
import re
import logging

logger = logging.getLogger(__name__)

HALLUCINATION_FLAGS = [
    'i made up', 'fabricated', 'not sure', "i don't know", "i'm not certain",
    'may not be accurate', 'cannot verify', 'i cannot confirm',
]

CYBER_TERMS = [
    'attack', 'threat', 'vulnerability', 'exploit', 'malware', 'security',
    'encryption', 'authentication', 'firewall', 'intrusion', 'breach', 'ransomware',
    'phishing', 'sql', 'xss', 'csrf', 'ddos', 'cve', 'patch', 'mitigation',
    'prevention', 'detection', 'incident', 'response', 'forensics',
]


class EvaluationService:
    def evaluate(self, query: str, response: str, knowledge_entries: list) -> dict:
        """Evaluate LLM response quality"""
        response_lower = response.lower()
        query_lower = query.lower()

        # 1. Relevance: how many cyber terms appear in response
        cyber_hits = sum(1 for term in CYBER_TERMS if term in response_lower)
        relevance_score = min(cyber_hits / max(len(CYBER_TERMS) * 0.3, 1), 1.0)

        # 2. Knowledge alignment: response mentions retrieved threat names
        kg_hits = 0
        for entry in knowledge_entries:
            if entry.threat_name.lower() in response_lower or entry.threat_type.lower() in response_lower:
                kg_hits += 1
        knowledge_alignment = kg_hits / max(len(knowledge_entries), 1) if knowledge_entries else 0.5

        # 3. Hallucination score: presence of uncertainty flags
        hallucination_hits = sum(1 for flag in HALLUCINATION_FLAGS if flag in response_lower)
        hallucination_score = min(hallucination_hits / 3, 1.0)

        # 4. Keyword matches between query and response
        query_words = set(re.findall(r'\b\w{4,}\b', query_lower))
        response_words = set(re.findall(r'\b\w{4,}\b', response_lower))
        keyword_matches = len(query_words & response_words)

        # 5. Response length sanity
        length_ok = 50 <= len(response.split()) <= 2000

        # 6. Verification status
        if relevance_score >= 0.6 and hallucination_score < 0.2 and length_ok:
            verification_status = 'verified'
        elif relevance_score >= 0.3:
            verification_status = 'partial'
        else:
            verification_status = 'unverified'

        # Boost relevance with knowledge alignment
        final_relevance = round(relevance_score * 0.7 + knowledge_alignment * 0.3, 3)

        return {
            'relevance_score': final_relevance,
            'hallucination_score': round(hallucination_score, 3),
            'verification_status': verification_status,
            'keyword_matches': keyword_matches,
            'cyber_term_hits': cyber_hits,
            'kg_alignment': round(knowledge_alignment, 3),
        }
