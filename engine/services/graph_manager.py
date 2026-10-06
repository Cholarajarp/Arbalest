"""Async Neo4j persistence for the Arbalest architecture graph.

This service stores a normalized, queryable representation of the discovered
application: projects contain files, files contain functions, services expose
routes, and findings/mutations are connected to impacted graph nodes.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from neo4j import AsyncDriver, AsyncGraphDatabase

_PLACEHOLDER_PASSWORDS = frozenset(
    {"changeme", "replace-in-local-env", "set-a-strong-secret-in-your-secret-manager", "password", "neo4j"}
)
_LOCAL_NEO4J_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "neo4j"})


@dataclass(frozen=True, slots=True)
class FunctionNode:
    """A source-level callable discovered during API reverse engineering."""

    project_id: str
    file_path: str
    qualified_name: str
    language: str
    start_line: int
    end_line: int
    signature: str | None = None


@dataclass(frozen=True, slots=True)
class RouteNode:
    """An HTTP route mapped back to its implementation function."""

    project_id: str
    method: str
    path: str
    handler_name: str
    auth_required: bool = False


class GraphManager:
    """Owns Neo4j schema, writes, and bounded blast-radius queries.

    Create one instance per FastAPI process and call ``close`` during lifespan
    shutdown.  The official driver's pool is thread-safe and supports many
    concurrent async requests.
    """

    def __init__(
        self,
        uri: str | None = None,
        username: str | None = None,
        password: str | None = None,
        database: str | None = None,
    ) -> None:
        self._uri = uri or os.getenv("NEO4J_URI")
        self._username = username or os.getenv("NEO4J_USERNAME")
        self._password = password or os.getenv("NEO4J_PASSWORD")
        self._database = database or os.getenv("NEO4J_DATABASE") or "neo4j"
        self._driver: AsyncDriver | None = None
        self._lifecycle_lock = asyncio.Lock()

    async def connect(self) -> None:
        """Open the driver pool and fail early when Neo4j is unavailable."""
        async with self._lifecycle_lock:
            if self._driver is None:
                uri, username, password = self._validated_connection_settings()
                self._driver = AsyncGraphDatabase.driver(
                    uri,
                    auth=(username, password),
                    max_connection_pool_size=50,
                    connection_acquisition_timeout=15,
                )
            await self._driver.verify_connectivity()

    async def close(self) -> None:
        async with self._lifecycle_lock:
            if self._driver is not None:
                await self._driver.close()
                self._driver = None

    def validate_configuration(self) -> None:
        """Validate credentials and transport settings without opening a socket."""
        self._validated_connection_settings()

    @property
    def _session_kwargs(self) -> dict[str, str]:
        return {"database": self._database}

    def _require_driver(self) -> AsyncDriver:
        if self._driver is None:
            raise RuntimeError("GraphManager is not connected; call await connect() during application startup")
        return self._driver

    def _validated_connection_settings(self) -> tuple[str, str, str]:
        if not self._uri or not self._username or not self._password:
            raise RuntimeError("NEO4J_URI, NEO4J_USERNAME, and NEO4J_PASSWORD must be configured")
        if self._password.strip().lower() in _PLACEHOLDER_PASSWORDS:
            raise RuntimeError("NEO4J_PASSWORD must not use a default or placeholder value")

        parsed = urlsplit(self._uri)
        hostname = (parsed.hostname or "").lower()
        if parsed.scheme not in {"neo4j", "bolt", "neo4j+s", "bolt+s", "neo4j+ssc", "bolt+ssc"} or not hostname:
            raise RuntimeError("NEO4J_URI must be a valid Neo4j connection URI")
        if hostname not in _LOCAL_NEO4J_HOSTS and parsed.scheme not in {"neo4j+s", "bolt+s"}:
            raise RuntimeError("Remote Neo4j connections must use certificate-verified TLS (+s URI scheme)")
        return self._uri, self._username, self._password

    async def ensure_schema(self) -> None:
        """Install idempotent uniqueness constraints and useful traversal indexes."""
        statements = (
            "CREATE CONSTRAINT project_id IF NOT EXISTS FOR (n:Project) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT file_key IF NOT EXISTS FOR (n:File) REQUIRE (n.project_id, n.path) IS UNIQUE",
            "CREATE CONSTRAINT function_key IF NOT EXISTS FOR (n:Function) REQUIRE (n.project_id, n.qualified_name) IS UNIQUE",
            "CREATE CONSTRAINT route_key IF NOT EXISTS FOR (n:Route) REQUIRE (n.project_id, n.method, n.path) IS UNIQUE",
            "CREATE CONSTRAINT finding_id IF NOT EXISTS FOR (n:Finding) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT vulnerability_pattern_key IF NOT EXISTS FOR (n:VulnerabilityPattern) REQUIRE (n.project_id, n.pattern_key) IS UNIQUE",
            "CREATE INDEX function_project IF NOT EXISTS FOR (n:Function) ON (n.project_id)",
        )
        async with self._require_driver().session(**self._session_kwargs) as session:
            for statement in statements:
                result = await session.run(statement)
                await result.consume()

    async def upsert_project(self, project_id: str, name: str) -> None:
        query = """
        MERGE (project:Project {id: $project_id})
        SET project.name = $name, project.updated_at = datetime($updated_at)
        """
        await self._execute_write(query, project_id=project_id, name=name, updated_at=_now())

    async def upsert_functions(self, functions: Iterable[FunctionNode]) -> None:
        """Batch-upsert files and functions; safe to repeat after incremental scans."""
        rows = [asdict(function) for function in functions]
        if not rows:
            return
        query = """
        UNWIND $rows AS row
        MERGE (project:Project {id: row.project_id})
        MERGE (file:File {project_id: row.project_id, path: row.file_path})
        ON CREATE SET file.created_at = datetime($updated_at)
        SET file.language = row.language, file.updated_at = datetime($updated_at)
        MERGE (project)-[:CONTAINS]->(file)
        MERGE (function:Function {project_id: row.project_id, qualified_name: row.qualified_name})
        SET function.file_path = row.file_path,
            function.language = row.language,
            function.start_line = row.start_line,
            function.end_line = row.end_line,
            function.signature = row.signature,
            function.updated_at = datetime($updated_at)
        WITH file, function
        OPTIONAL MATCH (previous_file:File)-[stale_contains:CONTAINS]->(function)
        WHERE previous_file.project_id = function.project_id AND previous_file <> file
        WITH file, function, collect(stale_contains) AS stale_contains_relationships
        FOREACH (relationship IN stale_contains_relationships | DELETE relationship)
        MERGE (file)-[:CONTAINS]->(function)
        """
        await self._execute_write(query, rows=rows, updated_at=_now())

    async def upsert_routes(self, routes: Iterable[RouteNode]) -> None:
        """Map observed HTTP routes to the implementation selected by the scanner."""
        rows = [asdict(route) for route in routes]
        if not rows:
            return
        query = """
        UNWIND $rows AS row
        MATCH (function:Function {project_id: row.project_id, qualified_name: row.handler_name})
        MERGE (route:Route {project_id: row.project_id, method: toUpper(row.method), path: row.path})
        SET route.auth_required = row.auth_required, route.updated_at = datetime($updated_at)
        WITH route, function
        OPTIONAL MATCH (route)-[stale_handler:HANDLED_BY]->(previous_handler:Function)
        WHERE stale_handler IS NOT NULL AND previous_handler <> function
        WITH route, function, collect(stale_handler) AS stale_handler_relationships
        FOREACH (relationship IN stale_handler_relationships | DELETE relationship)
        MERGE (route)-[:HANDLED_BY]->(function)
        """
        await self._execute_write(query, rows=rows, updated_at=_now())

    async def reconcile_project_inventory(
        self,
        project_id: str,
        functions: Iterable[FunctionNode],
        routes: Iterable[RouteNode],
    ) -> None:
        """Persist a complete scan and remove graph elements absent from it.

        A pipeline scan is authoritative for one project.  Upserts alone retain
        deleted files, functions, and routes indefinitely, which can make a
        later mutation plan target stale architecture.  This method first
        writes the latest inventory, then purges project-local elements not
        present in that inventory.  Orphaned findings are removed only after
        no function in any project references them.
        """
        function_nodes = list(functions)
        route_nodes = list(routes)
        if any(node.project_id != project_id for node in function_nodes) or any(node.project_id != project_id for node in route_nodes):
            raise ValueError("Every graph node must belong to the project being reconciled")

        await self.upsert_functions(function_nodes)
        await self.upsert_routes(route_nodes)

        qualified_names = [node.qualified_name for node in function_nodes]
        file_paths = [node.file_path for node in function_nodes]
        route_keys = [{"method": node.method.upper(), "path": node.path} for node in route_nodes]

        await self._execute_write(
            """
            MATCH (route:Route {project_id: $project_id})
            WHERE NOT any(active IN $route_keys WHERE route.method = active.method AND route.path = active.path)
            DETACH DELETE route
            """,
            project_id=project_id,
            route_keys=route_keys,
        )
        await self._execute_write(
            """
            MATCH (function:Function {project_id: $project_id})
            WHERE NOT (function.qualified_name IN $qualified_names)
            DETACH DELETE function
            """,
            project_id=project_id,
            qualified_names=qualified_names,
        )
        await self._execute_write(
            """
            MATCH (file:File {project_id: $project_id})
            WHERE NOT (file.path IN $file_paths)
            DETACH DELETE file
            """,
            project_id=project_id,
            file_paths=file_paths,
        )
        await self._execute_write(
            """
            MATCH (finding:Finding)
            WHERE NOT EXISTS { MATCH (:Function)-[:HAS_FINDING]->(finding) }
            DELETE finding
            """
        )

    async def link_calls(self, project_id: str, caller: str, callee: str) -> None:
        """Create a directed call edge only when both discovered functions exist."""
        query = """
        MATCH (caller:Function {project_id: $project_id, qualified_name: $caller})
        MATCH (callee:Function {project_id: $project_id, qualified_name: $callee})
        MERGE (caller)-[:CALLS]->(callee)
        """
        await self._execute_write(query, project_id=project_id, caller=caller, callee=callee)

    async def add_finding(
        self,
        *,
        finding_id: str,
        project_id: str,
        target_qualified_name: str,
        cwe: str,
        severity: str,
        summary: str,
        cve_ids: list[str] | None = None,
    ) -> None:
        """Attach threat-intelligence output to a function without interpolating Cypher."""
        query = """
        MATCH (target:Function {project_id: $project_id, qualified_name: $target_qualified_name})
        MERGE (finding:Finding {id: $finding_id})
        SET finding.cwe = $cwe, finding.severity = $severity, finding.summary = $summary,
            finding.cve_ids = $cve_ids, finding.updated_at = datetime($updated_at)
        MERGE (target)-[:HAS_FINDING]->(finding)
        """
        await self._execute_write(
            query,
            finding_id=finding_id,
            project_id=project_id,
            target_qualified_name=target_qualified_name,
            cwe=cwe,
            severity=severity.upper(),
            summary=summary,
            cve_ids=cve_ids or [],
            updated_at=_now(),
        )

    async def add_vulnerability_pattern(
        self,
        *,
        project_id: str,
        threat_name: str,
        cwe_category: str,
        cypher_pattern: str,
    ) -> str:
        """Persist a learned, read-only threat pattern as graph data.

        ``cypher_pattern`` is deliberately passed as a query parameter and is
        never executed by this manager. The deterministic key makes repeated
        observations of one generalized pattern idempotent within a project.
        """
        project_id = project_id.strip()
        threat_name = threat_name.strip()
        cwe_category = cwe_category.strip().upper()
        cypher_pattern = cypher_pattern.strip()
        if not project_id or not threat_name or not cwe_category or not cypher_pattern:
            raise ValueError("Learned vulnerability pattern fields cannot be blank")
        if len(threat_name) > 160 or len(cwe_category) > 32 or len(cypher_pattern) > 4_000:
            raise ValueError("Learned vulnerability pattern exceeds graph storage limits")

        pattern_key = hashlib.sha256(f"{cwe_category}\0{cypher_pattern}".encode("utf-8")).hexdigest()
        query = """
        MERGE (project:Project {id: $project_id})
        MERGE (pattern:VulnerabilityPattern {project_id: $project_id, pattern_key: $pattern_key})
        ON CREATE SET pattern.created_at = datetime($updated_at)
        SET pattern.threat_name = $threat_name,
            pattern.cwe_category = $cwe_category,
            pattern.cypher_pattern = $cypher_pattern,
            pattern.updated_at = datetime($updated_at)
        MERGE (project)-[:LEARNED_PATTERN]->(pattern)
        """
        await self._execute_write(
            query,
            project_id=project_id,
            pattern_key=pattern_key,
            threat_name=threat_name,
            cwe_category=cwe_category,
            cypher_pattern=cypher_pattern,
            updated_at=_now(),
        )
        return pattern_key

    async def blast_radius(self, project_id: str, qualified_name: str, max_depth: int = 4) -> list[dict[str, Any]]:
        """Return callers and dependents up to a capped depth to protect Neo4j.

        Traversing incoming ``CALLS`` edges identifies code that could regress if
        the selected function is rewritten.  A strict depth cap avoids runaway
        graph traversals on large monorepos.
        """
        if not 1 <= max_depth <= 8:
            raise ValueError("max_depth must be between 1 and 8")
        query = """
        MATCH path = (target:Function {project_id: $project_id, qualified_name: $qualified_name})
                     <-[:CALLS*1..8]-(dependent:Function {project_id: $project_id})
        WHERE length(path) <= $max_depth
        RETURN DISTINCT dependent.qualified_name AS qualified_name,
                        dependent.file_path AS file_path,
                        dependent.start_line AS start_line,
                        length(path) AS distance
        ORDER BY distance ASC, qualified_name ASC
        LIMIT 500
        """
        driver = self._require_driver()
        async with driver.session(**self._session_kwargs) as session:
            result = await session.run(query, project_id=project_id, qualified_name=qualified_name, max_depth=max_depth)
            return [record.data() async for record in result]

    async def project_snapshot(self, project_id: str) -> dict[str, list[dict[str, Any]]]:
        """Return a bounded, serialization-ready architecture subgraph for agents.

        The snapshot intentionally contains node properties and relationship
        types, but not arbitrary source blobs. Source is supplied to the
        coding agent by the repository reader under a separate size limit.
        Stored learned-pattern queries are excluded because they are untrusted
        model output and must never become executable or prompt context.
        """
        query = """
        MATCH (project:Project {id: $project_id})
        OPTIONAL MATCH (project)-[:CONTAINS*0..3]->(descendant)
        WITH project, collect(DISTINCT descendant) AS descendants
        OPTIONAL MATCH (project)-[:LEARNED_PATTERN]->(pattern:VulnerabilityPattern)
        WITH collect(DISTINCT project) AS projects,
             descendants,
             collect(DISTINCT pattern) AS learned_patterns
        WITH projects
             + [node IN descendants WHERE node IS NOT NULL]
             + [node IN learned_patterns WHERE node IS NOT NULL] AS nodes
        UNWIND nodes AS source
        OPTIONAL MATCH (source)-[relationship]->(target)
        WHERE target IN nodes
        RETURN collect(DISTINCT {
                   id: elementId(source),
                   labels: labels(source),
                   properties: CASE
                       WHEN source:VulnerabilityPattern THEN {
                           project_id: source.project_id,
                           pattern_key: source.pattern_key,
                           threat_name: source.threat_name,
                           cwe_category: source.cwe_category,
                           created_at: source.created_at,
                           updated_at: source.updated_at
                       }
                       ELSE properties(source)
                   END
               }) AS nodes,
               collect(DISTINCT CASE WHEN relationship IS NULL THEN NULL ELSE {
                   source_id: elementId(source),
                   target_id: elementId(target),
                   relationship_type: type(relationship),
                   properties: properties(relationship)
               } END) AS edges
        """
        driver = self._require_driver()
        async with driver.session(**self._session_kwargs) as session:
            result = await session.run(query, project_id=project_id)
            record = await result.single()
        if record is None:
            return {"nodes": [], "edges": []}
        return {
            "nodes": [_json_safe(item) for item in record["nodes"] if item is not None],
            "edges": [_json_safe(item) for item in record["edges"] if item is not None],
        }

    async def _execute_write(self, query: str, **parameters: Any) -> None:
        driver = self._require_driver()

        async def execute(tx: Any) -> None:
            result = await tx.run(query, **parameters)
            await result.consume()

        async with driver.session(**self._session_kwargs) as session:
            await session.execute_write(execute)


def _now() -> str:
    """Generate an ISO-8601 value Neo4j parses with ``datetime()``."""
    return datetime.now(UTC).isoformat()


def _json_safe(value: Any) -> Any:
    """Normalize Neo4j temporal/spatial values before exposing agent context."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    # Neo4j temporal and spatial values have stable string representations; do
    # not leak driver-specific objects into Pydantic/JSON serialization.
    return str(value)
