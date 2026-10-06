import logging
import chromadb
from chromadb.config import Settings
from typing import Any

logger = logging.getLogger(__name__)

class VectorMemory:
    """Stateful RAG Feedback Loop memory using ChromaDB."""
    def __init__(self, db_path: str = "./chroma_db"):
        self.db_path = db_path
        # Allow running in-memory or persisted. Telemetry is disabled: an
        # incident-response tool never phones home, and air-gapped deployments
        # must not stall on telemetry timeouts.
        try:
            self.client = chromadb.PersistentClient(
                path=self.db_path,
                settings=Settings(anonymized_telemetry=False),
            )
            self.collection = self.client.get_or_create_collection(name="arbalest_vuln_memory")
            logger.info("ChromaDB VectorMemory initialized.")
        except Exception as e:
            logger.error(f"Failed to initialize ChromaDB: {e}")
            self.collection = None

    async def ingest_finding(self, finding_id: str, summary: str, context: str) -> bool:
        """Ingests a missed vulnerability into the vector database for future reference."""
        if not self.collection:
            return False
            
        try:
            # The document is the context/summary of the vulnerability
            self.collection.upsert(
                documents=[f"Vulnerability: {summary}\nContext: {context}"],
                metadatas=[{"finding_id": finding_id}],
                ids=[finding_id]
            )
            logger.info(f"Ingested finding {finding_id} into vector memory.")
            return True
        except Exception as e:
            logger.error(f"Error ingesting finding into vector memory: {e}")
            return False

    async def query_similar(self, query_text: str, n_results: int = 3) -> list[dict[str, Any]]:
        """Queries for similar past vulnerabilities."""
        if not self.collection:
            return []
            
        try:
            results = self.collection.query(
                query_texts=[query_text],
                n_results=n_results
            )
            if not results or not results.get("documents") or not results["documents"][0]:
                return []
                
            docs = results["documents"][0]
            metas = results["metadatas"][0] if results.get("metadatas") else [{}] * len(docs)
            return [{"document": d, "metadata": m} for d, m in zip(docs, metas)]
        except Exception as e:
            logger.error(f"Error querying vector memory: {e}")
            return []

# Singleton instance
vector_memory = VectorMemory()
