"""
ChromaDB Vector Search / RAG Service
Manages semantic search, prompt augmentation, and context grounding.
Provides a graceful local keyword-based fallback if ChromaDB is unavailable.
"""
import os
import logging
import numpy as np
from django.conf import settings
from knowledgegraph.models import CyberKnowledge

logger = logging.getLogger(__name__)

class ChromaService:
    def __init__(self):
        self.client = None
        self.collection = None
        self.connected = False
        self.db_path = os.path.join(settings.BASE_DIR, "chroma_db")
        
        try:
            # pyrefly: ignore [missing-import]
            import chromadb
            # Initialize persistent client
            self.client = chromadb.PersistentClient(path=self.db_path)
            
            # Simple custom lightweight embedding function to avoid downloading 
            # external sentence-transformers models which can fail in offline mode.
            # Using simple bag-of-words / TF-IDF style vectorization
            class SimpleEmbeddingFunction:
                def name(self) -> str:
                    return "SimpleEmbeddingFunction"
                def __call__(self, input):
                    # Generates simple normalized character/word hash-based embeddings
                    embeddings = []
                    for text in input:
                        vec = np.zeros(128)
                        words = text.lower().split()
                        for i, w in enumerate(words):
                            idx = hash(w) % 128
                            vec[idx] += 1.0 / (i + 1)
                        norm = np.linalg.norm(vec)
                        if norm > 0:
                            vec = vec / norm
                        embeddings.append(vec.tolist())
                    return embeddings
                
                def embed_documents(self, *args, **kwargs):
                    input_data = kwargs.get('input') or kwargs.get('texts') or args[0]
                    if isinstance(input_data, str):
                        input_data = [input_data]
                    return self.__call__(input_data)
                    
                def embed_query(self, *args, **kwargs):
                    input_data = kwargs.get('input') or kwargs.get('text') or args[0]
                    if isinstance(input_data, str):
                        input_data = [input_data]
                    return self.__call__(input_data)

            self.embedding_function = SimpleEmbeddingFunction()
            self.collection = self.client.get_or_create_collection(
                name="cybersecurity_knowledge",
                embedding_function=self.embedding_function
            )
            self.cache_collection = self.client.get_or_create_collection(
                name="semantic_query_cache",
                embedding_function=self.embedding_function
            )
            self.connected = True
            
            # Seed the vector database if empty
            if self.collection.count() == 0:
                self._seed_chroma()
            logger.info("ChromaDB service initialized and connected.")
        except Exception as e:
            logger.warning(f"ChromaDB initialization failed: {e}. Falling back to database semantic emulation.")
            self.connected = False

    def _seed_chroma(self):
        """Seeds ChromaDB collection with data from CyberKnowledge MySQL database."""
        try:
            knowledge_entries = CyberKnowledge.objects.all()
            if not knowledge_entries:
                return
                
            documents = []
            ids = []
            metadatas = []
            
            for entry in knowledge_entries:
                doc = f"Threat: {entry.threat_name}. Type: {entry.threat_type}. Description: {entry.description}. Attack: {entry.attack_method}. Prevention: {entry.prevention}."
                documents.append(doc)
                ids.append(str(entry.id))
                metadatas.append({
                    "threat_name": entry.threat_name,
                    "threat_type": entry.threat_type,
                    "severity": entry.severity,
                    "risk_score": entry.risk_score
                })
                
            if documents:
                self.collection.add(
                    documents=documents,
                    ids=ids,
                    metadatas=metadatas
                )
                logger.info(f"Seeded {len(documents)} entries into ChromaDB.")
        except Exception as e:
            logger.error(f"Error seeding ChromaDB: {e}")

    def semantic_search(self, query_text: str, limit: int = 3) -> list:
        """
        Performs semantic search across cybersecurity collection.
        Returns matching database records.
        """
        if not self.connected or not self.collection:
            return self._fallback_search(query_text, limit)
            
        try:
            results = self.collection.query(
                query_texts=[query_text],
                n_results=limit
            )
            
            if not results or not results["ids"] or not results["ids"][0]:
                return self._fallback_search(query_text, limit)
                
            matching_ids = [int(idx) for idx in results["ids"][0]]
            # Preserve order of relevance
            db_records = {r.id: r for r in CyberKnowledge.objects.filter(id__in=matching_ids)}
            ordered_records = [db_records[rid] for rid in matching_ids if rid in db_records]
            return ordered_records
            
        except Exception as e:
            logger.error(f"Error in ChromaDB semantic search: {e}. Using database fallback.")
            return self._fallback_search(query_text, limit)

    def _fallback_search(self, query_text: str, limit: int) -> list:
        """Local fallback using SQL-based search."""
        from django.db.models import Q
        query_lower = query_text.lower()
        
        # Look up match on CyberKnowledge
        return list(CyberKnowledge.objects.filter(
            Q(threat_name__icontains=query_lower) |
            Q(description__icontains=query_lower) |
            Q(attack_method__icontains=query_lower)
        ).order_by('-risk_score')[:limit])

    def _build_cache_response(self, meta: dict) -> dict:
        return {
            'response': meta.get('response', ''),
            'confidence_score': float(meta.get('confidence_score', 0.95)),
            'knowledge_context': meta.get('knowledge_context', ''),
            'threats_found': meta.get('threats_found', '').split(',') if meta.get('threats_found') else [],
            'evaluation': {
                'hallucination_score': float(meta.get('hallucination_score', 0.0)),
                'relevance_score': float(meta.get('relevance_score', 1.0)),
                'verification_status': 'verified',
                'keyword_matches': int(meta.get('keyword_matches', 0)),
            },
            'tokens_used': 0,
            'cached': True
        }

    def check_cache(self, query_text: str, threshold: float = 0.15) -> dict | None:
        """Check if an equivalent question exists in semantic cache."""
        if getattr(self, 'cache_collection', None) is None:
            return None
            
        try:
            results = self.cache_collection.query(
                query_texts=[query_text],
                n_results=5
            )
            
            if results['distances'] and len(results['distances'][0]) > 0:
                for i in range(len(results['distances'][0])):
                    distance = results['distances'][0][i]
                    cached_query = results['documents'][0][i].lower()
                    query_lower = query_text.lower()
                    
                    from services.reasoning_engine import CYBER_KEYWORDS
                    q_kws = set(kw for kw in CYBER_KEYWORDS if kw in query_lower)
                    c_kws = set(kw for kw in CYBER_KEYWORDS if kw in cached_query)
                    
                    if q_kws and q_kws != c_kws:
                        continue # Different primary topic, skip
                        
                    def_words = ['what', 'explain', 'meaning', 'how does', 'define', 'describe']
                    is_q_def = any(w in query_lower for w in def_words)
                    is_c_def = any(w in cached_query for w in def_words)
                    
                    # If they share the exact same cyber keyword and both ask for a definition
                    if q_kws == c_kws and len(q_kws) > 0 and is_q_def and is_c_def:
                        meta = results['metadatas'][0][i]
                        return self._build_cache_response(meta)
                        
                    # Exact string match fallback
                    if query_lower.strip() == cached_query.strip():
                        meta = results['metadatas'][0][i]
                        return self._build_cache_response(meta)
                        
                    # Strict distance fallback
                    if distance < threshold:
                        meta = results['metadatas'][0][i]
                        return self._build_cache_response(meta)
                        
        except Exception as e:
            logger.warning(f"Cache check failed: {e}")
            
        return None

    def add_to_cache(self, query_text: str, result_dict: dict):
        """Save a new question and generated response to the semantic cache."""
        if getattr(self, 'cache_collection', None) is None:
            return
            
        response = result_dict.get('response', '')
        if not response or len(response) < 10 or '### 🌐 CyGPT Cybersecurity Advisory' in response:
            # Never cache empty, very short, or generic fallback failures
            return 
            
        try:
            import uuid
            cache_id = str(uuid.uuid4())
            threats = ",".join(result_dict.get('threats_found', []))
            
            # Extract evaluation metrics safely
            eval_data = result_dict.get('evaluation', {})
            
            self.cache_collection.add(
                ids=[cache_id],
                documents=[query_text],
                metadatas=[{
                    'response': response,
                    'confidence_score': result_dict.get('confidence_score', 0.95),
                    'knowledge_context': result_dict.get('knowledge_context', ''),
                    'threats_found': threats,
                    'hallucination_score': eval_data.get('hallucination_score', 0.0),
                    'relevance_score': eval_data.get('relevance_score', 1.0),
                    'keyword_matches': eval_data.get('keyword_matches', 0)
                }]
            )
        except Exception as e:
            logger.warning(f"Failed to add to semantic cache: {e}")
