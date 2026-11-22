"""
Neo4j Knowledge Graph Service
Manages connections to Neo4j for cybersecurity entity & relationship retrieval.
Provides graceful fallback to relational database (MySQL CyberKnowledge) if Neo4j is unavailable.
"""
import os
import logging
from django.conf import settings
from knowledgegraph.models import CyberKnowledge

logger = logging.getLogger(__name__)

class Neo4jService:
    def __init__(self):
        self.uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = os.getenv("NEO4J_USER", "neo4j")
        self.password = os.getenv("NEO4J_PASSWORD", "password")
        self.driver = None
        self.connected = False
        
        # Try dynamic import and connection
        try:
            from neo4j import GraphDatabase
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            # Verify connectivity (timeout 2s)
            self.driver.verify_connectivity()
            self.connected = True
            logger.info("Successfully connected to Neo4j Knowledge Graph.")
        except Exception as e:
            logger.warning(f"Neo4j connection failed: {e}. Falling back to MySQL relational Knowledge Graph.")
            self.connected = False

    def retrieve_threat_intelligence(self, query_text: str) -> list:
        """
        Queries Neo4j database for matching entities and relationships.
        Falls back to database-level lookup if Neo4j is not connected.
        """
        if not self.connected:
            return self._fallback_db_lookup(query_text)
            
        try:
            # Query Neo4j for threat matches and related vulnerabilities/CVEs
            # Using Cypher matches
            with self.driver.session() as session:
                result = session.run(
                    "MATCH (t:Threat) WHERE t.name CONTAINS $query "
                    "OPTIONAL MATCH (t)-[r]->(v:Vulnerability) "
                    "RETURN t.name as name, t.type as type, t.description as description, "
                    "t.attack_method as attack_method, t.prevention as prevention, "
                    "t.severity as severity, t.risk_score as risk_score, "
                    "collect(v.cve) as cves, collect(v.name) as vulnerabilities "
                    "LIMIT 5",
                    query=query_text
                )
                records = []
                for record in result:
                    # Construct matching format for CyberKnowledge fields
                    records.append(CyberKnowledge(
                        threat_name=record["name"],
                        threat_type=record["type"] or "Unknown",
                        description=record["description"] or "",
                        attack_method=record["attack_method"] or "",
                        prevention=record["prevention"] or "",
                        severity=record["severity"] or "medium",
                        risk_score=float(record["risk_score"] or 5.0),
                        related_vulnerabilities=", ".join(record["vulnerabilities"]) if record["vulnerabilities"] else "",
                        cve_references=", ".join(record["cves"]) if record["cves"] else ""
                    ))
                
                if not records:
                    return self._fallback_db_lookup(query_text)
                return records
        except Exception as e:
            logger.error(f"Error querying Neo4j Knowledge Graph: {e}. Using fallback database.")
            return self._fallback_db_lookup(query_text)

    def _fallback_db_lookup(self, query_text: str) -> list:
        """Fallback to database-level CyberKnowledge search."""
        from django.db.models import Q
        import re
        
        query_lower = query_text.lower()
        results = []
        seen_ids = set()

        all_threats = CyberKnowledge.objects.all()
        for threat in all_threats:
            if threat.threat_name.lower() in query_lower:
                results.append(threat)
                seen_ids.add(threat.id)

        # Basic keyword filtering
        keywords = [word for word in query_lower.split() if len(word) > 3]
        q_filter = Q()
        for kw in keywords:
            clean_kw = re.sub(r'[^\w\s]', '', kw)
            if clean_kw:
                q_filter |= (
                    Q(threat_name__icontains=clean_kw) |
                    Q(threat_type__icontains=clean_kw) |
                    Q(description__icontains=clean_kw)
                )

        if q_filter:
            broad_matches = CyberKnowledge.objects.filter(q_filter).order_by('-risk_score')
            for match in broad_matches:
                if len(results) >= 5:
                    break
                if match.id not in seen_ids:
                    results.append(match)
                    seen_ids.add(match.id)

        return results[:5]

    def close(self):
        if self.driver:
            self.driver.close()
