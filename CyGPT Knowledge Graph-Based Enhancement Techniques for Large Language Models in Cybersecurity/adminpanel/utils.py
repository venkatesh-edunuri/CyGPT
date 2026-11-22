import time
import requests
from django.db import connection
from services.neo4j_service import Neo4jService
import logging

logger = logging.getLogger(__name__)

def check_system_health():
    health_status = {
        'mysql': {'status': 'offline', 'latency': 0},
        'neo4j': {'status': 'offline', 'latency': 0},
        'groq': {'status': 'offline', 'latency': 0},
    }

    # Check MySQL
    start = time.time()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        health_status['mysql']['status'] = 'online'
    except Exception as e:
        logger.error(f"MySQL health check failed: {e}")
    health_status['mysql']['latency'] = round((time.time() - start) * 1000)

    # Check Neo4j (fast fail using socket)
    start = time.time()
    try:
        import socket
        import os
        neo4j_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        host = neo4j_uri.split("://")[-1].split(":")[0]
        port = int(neo4j_uri.split(":")[-1]) if ":" in neo4j_uri.split("://")[-1] else 7687
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            neo4j_service = Neo4jService()
            if neo4j_service.driver:
                with neo4j_service.driver.session() as session:
                    session.run("RETURN 1")
                health_status['neo4j']['status'] = 'online'
            neo4j_service.close()
    except Exception as e:
        logger.error(f"Neo4j health check failed: {e}")
    health_status['neo4j']['latency'] = round((time.time() - start) * 1000)

    # Check Groq
    start = time.time()
    try:
        from cygpt.settings import GROQ_API_KEY
        if GROQ_API_KEY:
            response = requests.get(
                'https://api.groq.com/openai/v1/models', 
                headers={'Authorization': f'Bearer {GROQ_API_KEY}'},
                timeout=1.5
            )
            if response.status_code == 200:
                health_status['groq']['status'] = 'online'
    except Exception as e:
        logger.error(f"Groq health check failed: {e}")
    health_status['groq']['latency'] = round((time.time() - start) * 1000)

    return health_status
