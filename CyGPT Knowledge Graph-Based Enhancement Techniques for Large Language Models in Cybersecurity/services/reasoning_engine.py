"""
Joint Reasoning Engine — Core of CyGPT
Integrates Neo4j Knowledge Graph, ChromaDB vector search (RAG), and local LLM.
Runs an advanced reasoning chain:
  Step 1: Extract query intents and keywords.
  Step 2: Semantic RAG search (ChromaDB) for high-dimensional context.
  Step 3: Entity/relationship retrieval (Neo4j Graph) for CVEs, threat links.
  Step 4: Heuristic synthesis & validation.
  Step 5: Query Local Ollama LLM with augmented prompt.
  Step 6: Real-time response quality evaluation and hallucination detection.
"""
import re
import logging
from django.db.models import Q
from knowledgegraph.models import CyberKnowledge
from services.groq_service import GroqService
from services.evaluation_service import EvaluationService
from services.neo4j_service import Neo4jService
from services.chroma_service import ChromaService

logger = logging.getLogger(__name__)

CYBER_KEYWORDS = [
    'malware', 'ransomware', 'phishing', 'sql injection', 'xss', 'csrf',
    'ddos', 'dos', 'attack', 'vulnerability', 'exploit', 'zero-day',
    'firewall', 'encryption', 'authentication', 'authorization', 'mitm',
    'man-in-the-middle', 'brute force', 'social engineering', 'trojan',
    'virus', 'worm', 'rootkit', 'keylogger', 'spyware', 'adware',
    'botnet', 'apt', 'penetration', 'pen test', 'cve', 'cvss',
    'intrusion', 'ids', 'ips', 'siem', 'soc', 'threat', 'security',
    'cybersecurity', 'hacking', 'breach', 'data leak', 'privilege escalation',
    'buffer overflow', 'remote code execution', 'rce', 'lateral movement',
]

class JointReasoningEngine:
    def __init__(self):
        self.groq_service = GroqService()
        self.eval_service = EvaluationService()
        self.neo4j_service = Neo4jService()
        self.chroma_service = ChromaService()

    def extract_keywords(self, query: str) -> list:
        query_lower = query.lower()
        return [kw for kw in CYBER_KEYWORDS if kw in query_lower]

    def search_knowledge_base(self, query: str) -> list:
        """
        Retrieves knowledge from both Neo4j (Graph) and ChromaDB (Vector RAG).
        De-duplicates and filters results based on query context.
        """
        results = []
        seen_names = set()

        # 1. Retrieve entities & relations from Neo4j Knowledge Graph
        try:
            kg_entries = self.neo4j_service.retrieve_threat_intelligence(query)
            for entry in kg_entries:
                if entry.threat_name.lower() not in seen_names:
                    results.append(entry)
                    seen_names.add(entry.threat_name.lower())
        except Exception as e:
            logger.warning(f"Neo4j retrieval error: {e}")

        # 2. Retrieve semantic context from ChromaDB vector database (RAG)
        try:
            rag_entries = self.chroma_service.semantic_search(query, limit=3)
            for entry in rag_entries:
                if entry.threat_name.lower() not in seen_names:
                    results.append(entry)
                    seen_names.add(entry.threat_name.lower())
        except Exception as e:
            logger.warning(f"ChromaDB retrieval error: {e}")

        # 3. No fallback to top risk scores; if no matches, return empty to trigger general response
        return results[:5]

    def build_knowledge_context(self, knowledge_entries: list) -> str:
        if not knowledge_entries:
            return ""
        parts = []
        for entry in knowledge_entries:
            parts.append(
                f"--- Threat: {entry.threat_name} ---\n"
                f"Type: {entry.threat_type} | Severity: {entry.severity.upper()} | Risk Score: {entry.risk_score}/10\n"
                f"Description: {entry.description}\n"
                f"Attack Method: {entry.attack_method}\n"
                f"Prevention: {entry.prevention}\n"
                + (f"Related Vulnerabilities: {entry.related_vulnerabilities}\n" if entry.related_vulnerabilities else "")
                + (f"CVE References: {entry.cve_references}\n" if entry.cve_references else "")
            )
        return "\n".join(parts)

    def process(self, user_query: str, username: str = None) -> dict:
        """Run the full Joint Reasoning Chain and return enriched result"""
        
        # Step 0: Check Semantic Cache for exact/equivalent questions
        cached_result = self.chroma_service.check_cache(user_query)
        if cached_result:
            logger.info(f"Semantic Cache HIT for query: {user_query[:60]}")
            return cached_result
            
        logger.info(f"Semantic Cache MISS for query: {user_query[:60]}")
        
        # Step 2-3: Knowledge Graph & Vector RAG retrieval
        knowledge_entries = self.search_knowledge_base(user_query)
        knowledge_context = self.build_knowledge_context(knowledge_entries)
        threats_found = [e.threat_name for e in knowledge_entries]

        logger.info(f"Hybrid retrieval: {len(knowledge_entries)} entries for query: {user_query[:60]}")

        # Step 5: LLM query with enhanced prompt
        llm_result = self.groq_service.query(user_query, knowledge_context, username)
        response_text = llm_result['response']

        # Step 6: Evaluation
        evaluation = self.eval_service.evaluate(
            query=user_query,
            response=response_text,
            knowledge_entries=knowledge_entries,
        )

        # Step 7: Compute confidence score
        confidence_score = self._compute_confidence(evaluation, knowledge_entries, llm_result)

        result_dict = {
            'response': response_text,
            'confidence_score': confidence_score,
            'knowledge_context': knowledge_context[:500] if knowledge_context else '',
            'threats_found': threats_found,
            'evaluation': evaluation,
            'tokens_used': llm_result.get('tokens_used', 0),
        }
        
        # Save to semantic cache for future equivalent queries
        self.chroma_service.add_to_cache(user_query, result_dict)
        
        return result_dict

    def _compute_confidence(self, evaluation: dict, knowledge_entries: list, llm_result: dict) -> float:
        """Weighted confidence: relevance + knowledge hits + low hallucination"""
        base = evaluation['relevance_score'] * 0.5
        hallucination_penalty = (1 - evaluation['hallucination_score']) * 0.3
        knowledge_bonus = min(len(knowledge_entries) / 5, 1.0) * 0.2
        score = base + hallucination_penalty + knowledge_bonus
        return round(min(max(score, 0.0), 1.0), 3)
