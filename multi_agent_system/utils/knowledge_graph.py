"""
Knowledge Graph untuk Shared Context Multi-Agent System

Implementasi graph-based context untuk menggantikan simple dict.
Mendukung relasi antar entities dan query berbasis graph.

Author: RAJDOLL Research Project
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict

from ..core.db import get_db
from ..models.models import SharedContext


class EntityType(str, Enum):
    """Types of entities in the knowledge graph"""
    TARGET = "target"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    TECHNOLOGY = "technology"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    SESSION = "session"
    FINDING = "finding"
    ATTACK_CHAIN = "attack_chain"


class RelationType(str, Enum):
    """Types of relationships between entities"""
    HAS_ENDPOINT = "has_endpoint"
    HAS_PARAMETER = "has_parameter"
    RUNS_ON = "runs_on"
    VULNERABLE_TO = "vulnerable_to"
    LEADS_TO = "leads_to"           # For attack chains
    AUTHENTICATED_BY = "authenticated_by"
    DISCOVERED_BY = "discovered_by"
    PART_OF = "part_of"             # Component relationship
    EXPLOITS = "exploits"           # Attack exploits vulnerability
    REQUIRES = "requires"           # Dependency relationship


@dataclass
class Entity:
    """A node in the knowledge graph"""
    id: str
    entity_type: EntityType
    name: str
    properties: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    discovered_by: str = ""  # Agent name
    discovered_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.discovered_at is None:
            self.discovered_at = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "entity_type": self.entity_type.value if isinstance(self.entity_type, EntityType) else self.entity_type,
            "name": self.name,
            "properties": self.properties,
            "confidence": self.confidence,
            "discovered_by": self.discovered_by,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Entity":
        entity_type = data.get("entity_type", EntityType.FINDING.value)
        if isinstance(entity_type, str):
            try:
                entity_type = EntityType(entity_type)
            except ValueError:
                entity_type = EntityType.FINDING
        
        discovered_at = data.get("discovered_at")
        if isinstance(discovered_at, str):
            try:
                discovered_at = datetime.fromisoformat(discovered_at)
            except:
                discovered_at = None
        
        return cls(
            id=data.get("id", ""),
            entity_type=entity_type,
            name=data.get("name", ""),
            properties=data.get("properties", {}),
            confidence=data.get("confidence", 1.0),
            discovered_by=data.get("discovered_by", ""),
            discovered_at=discovered_at,
        )


@dataclass
class Relationship:
    """An edge in the knowledge graph"""
    source_id: str
    target_id: str
    relation_type: RelationType
    properties: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    discovered_by: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation_type": self.relation_type.value if isinstance(self.relation_type, RelationType) else self.relation_type,
            "properties": self.properties,
            "confidence": self.confidence,
            "discovered_by": self.discovered_by,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Relationship":
        relation_type = data.get("relation_type", RelationType.PART_OF.value)
        if isinstance(relation_type, str):
            try:
                relation_type = RelationType(relation_type)
            except ValueError:
                relation_type = RelationType.PART_OF
        
        return cls(
            source_id=data.get("source_id", ""),
            target_id=data.get("target_id", ""),
            relation_type=relation_type,
            properties=data.get("properties", {}),
            confidence=data.get("confidence", 1.0),
            discovered_by=data.get("discovered_by", ""),
        )


class KnowledgeGraph:
    """
    Graph-based knowledge representation for multi-agent context sharing.
    
    Features:
    - Entity and relationship management
    - Graph traversal queries
    - Persistence to database
    - Serialization/deserialization
    
    Example:
        kg = KnowledgeGraph(job_id=1)
        
        # Add entities
        kg.add_entity(Entity(
            id="target-1",
            entity_type=EntityType.TARGET,
            name="http://juice-shop:3000",
            properties={"base_url": "http://juice-shop:3000"},
            discovered_by="ReconnaissanceAgent"
        ))
        
        kg.add_entity(Entity(
            id="endpoint-login",
            entity_type=EntityType.ENDPOINT,
            name="/rest/user/login",
            properties={"method": "POST", "params": ["email", "password"]},
            discovered_by="ReconnaissanceAgent"
        ))
        
        # Add relationship
        kg.add_relationship(Relationship(
            source_id="target-1",
            target_id="endpoint-login",
            relation_type=RelationType.HAS_ENDPOINT,
            discovered_by="ReconnaissanceAgent"
        ))
        
        # Query
        endpoints = kg.get_related("target-1", RelationType.HAS_ENDPOINT)
        vulns = kg.query_by_type(EntityType.VULNERABILITY)
    """
    
    def __init__(self, job_id: int):
        self.job_id = job_id
        self._entities: Dict[str, Entity] = {}
        self._relationships: List[Relationship] = []
        self._adjacency: Dict[str, List[Tuple[str, Relationship]]] = defaultdict(list)
        self._reverse_adjacency: Dict[str, List[Tuple[str, Relationship]]] = defaultdict(list)
        
        # Load existing graph from database
        self._load_from_db()
    
    def add_entity(self, entity: Entity) -> None:
        """Add or update an entity in the graph"""
        self._entities[entity.id] = entity
        self._persist()
    
    def add_entities(self, entities: List[Entity]) -> None:
        """Bulk add entities"""
        for entity in entities:
            self._entities[entity.id] = entity
        self._persist()
    
    def get_entity(self, entity_id: str) -> Optional[Entity]:
        """Get entity by ID"""
        return self._entities.get(entity_id)
    
    def add_relationship(self, relationship: Relationship) -> None:
        """Add a relationship between two entities"""
        # Validate entities exist
        if relationship.source_id not in self._entities:
            raise ValueError(f"Source entity not found: {relationship.source_id}")
        if relationship.target_id not in self._entities:
            raise ValueError(f"Target entity not found: {relationship.target_id}")
        
        self._relationships.append(relationship)
        self._adjacency[relationship.source_id].append((relationship.target_id, relationship))
        self._reverse_adjacency[relationship.target_id].append((relationship.source_id, relationship))
        self._persist()
    
    def add_relationship_safe(self, relationship: Relationship) -> bool:
        """Add relationship, creating placeholder entities if needed. Returns True if added."""
        # Auto-create placeholder entities if missing
        if relationship.source_id not in self._entities:
            self._entities[relationship.source_id] = Entity(
                id=relationship.source_id,
                entity_type=EntityType.FINDING,
                name=relationship.source_id,
                discovered_by=relationship.discovered_by
            )
        if relationship.target_id not in self._entities:
            self._entities[relationship.target_id] = Entity(
                id=relationship.target_id,
                entity_type=EntityType.FINDING,
                name=relationship.target_id,
                discovered_by=relationship.discovered_by
            )
        
        self._relationships.append(relationship)
        self._adjacency[relationship.source_id].append((relationship.target_id, relationship))
        self._reverse_adjacency[relationship.target_id].append((relationship.source_id, relationship))
        self._persist()
        return True
    
    def get_related(
        self, 
        entity_id: str, 
        relation_type: Optional[RelationType] = None,
        direction: str = "outgoing"  # "outgoing", "incoming", "both"
    ) -> List[Tuple[Entity, Relationship]]:
        """Get entities related to the given entity"""
        results = []
        
        if direction in ("outgoing", "both"):
            for target_id, rel in self._adjacency.get(entity_id, []):
                if relation_type is None or rel.relation_type == relation_type:
                    if target_id in self._entities:
                        results.append((self._entities[target_id], rel))
        
        if direction in ("incoming", "both"):
            for source_id, rel in self._reverse_adjacency.get(entity_id, []):
                if relation_type is None or rel.relation_type == relation_type:
                    if source_id in self._entities:
                        results.append((self._entities[source_id], rel))
        
        return results
    
    def query_by_type(self, entity_type: EntityType) -> List[Entity]:
        """Get all entities of a specific type"""
        return [e for e in self._entities.values() if e.entity_type == entity_type]
    
    def query_by_property(self, key: str, value: Any) -> List[Entity]:
        """Find entities with a specific property value"""
        return [
            e for e in self._entities.values()
            if e.properties.get(key) == value
        ]
    
    def query_vulnerabilities_for_endpoint(self, endpoint_id: str) -> List[Entity]:
        """Get all vulnerabilities affecting an endpoint"""
        vulns = []
        for target_id, rel in self._adjacency.get(endpoint_id, []):
            if rel.relation_type == RelationType.VULNERABLE_TO:
                entity = self._entities.get(target_id)
                if entity and entity.entity_type == EntityType.VULNERABILITY:
                    vulns.append(entity)
        return vulns
    
    def query_attack_chains(self) -> List[List[Entity]]:
        """Find all attack chains (sequences of vulnerabilities that chain together)"""
        chains = []
        chain_entities = self.query_by_type(EntityType.ATTACK_CHAIN)
        
        for chain_entity in chain_entities:
            chain = [chain_entity]
            # Follow LEADS_TO relationships
            current = chain_entity.id
            visited = {current}
            
            while True:
                next_hops = [
                    (target_id, rel) for target_id, rel in self._adjacency.get(current, [])
                    if rel.relation_type == RelationType.LEADS_TO and target_id not in visited
                ]
                if not next_hops:
                    break
                
                next_id, _ = next_hops[0]
                if next_id in self._entities:
                    chain.append(self._entities[next_id])
                    visited.add(next_id)
                    current = next_id
                else:
                    break
            
            if len(chain) > 1:
                chains.append(chain)
        
        return chains
    
    def get_all_entities(self) -> List[Entity]:
        """Get all entities in the graph"""
        return list(self._entities.values())
    
    def get_all_relationships(self) -> List[Relationship]:
        """Get all relationships in the graph"""
        return list(self._relationships)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get graph statistics"""
        entity_counts = defaultdict(int)
        for entity in self._entities.values():
            entity_counts[entity.entity_type.value] += 1
        
        relation_counts = defaultdict(int)
        for rel in self._relationships:
            relation_counts[rel.relation_type.value] += 1
        
        return {
            "total_entities": len(self._entities),
            "total_relationships": len(self._relationships),
            "entity_counts": dict(entity_counts),
            "relationship_counts": dict(relation_counts),
            "discovered_by_agents": list(set(e.discovered_by for e in self._entities.values() if e.discovered_by)),
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize graph to dictionary"""
        return {
            "entities": [e.to_dict() for e in self._entities.values()],
            "relationships": [r.to_dict() for r in self._relationships],
            "statistics": self.get_statistics(),
        }
    
    def merge_from_dict(self, data: Dict[str, Any]) -> None:
        """Merge data from dictionary into graph"""
        for entity_data in data.get("entities", []):
            entity = Entity.from_dict(entity_data)
            self._entities[entity.id] = entity
        
        for rel_data in data.get("relationships", []):
            rel = Relationship.from_dict(rel_data)
            if rel.source_id in self._entities and rel.target_id in self._entities:
                self._relationships.append(rel)
                self._adjacency[rel.source_id].append((rel.target_id, rel))
                self._reverse_adjacency[rel.target_id].append((rel.source_id, rel))
        
        self._persist()
    
    def _persist(self) -> None:
        """Persist graph to database"""
        data = self.to_dict()
        with get_db() as db:
            record = db.query(SharedContext).filter(
                SharedContext.job_id == self.job_id,
                SharedContext.key == "knowledge_graph"
            ).one_or_none()
            
            if record:
                record.value = data
            else:
                db.add(SharedContext(
                    job_id=self.job_id,
                    key="knowledge_graph",
                    value=data
                ))
            db.commit()
    
    def _load_from_db(self) -> None:
        """Load graph from database"""
        with get_db() as db:
            record = db.query(SharedContext).filter(
                SharedContext.job_id == self.job_id,
                SharedContext.key == "knowledge_graph"
            ).one_or_none()
            
            if record and record.value:
                data = record.value
                for entity_data in data.get("entities", []):
                    entity = Entity.from_dict(entity_data)
                    self._entities[entity.id] = entity
                
                for rel_data in data.get("relationships", []):
                    rel = Relationship.from_dict(rel_data)
                    self._relationships.append(rel)
                    self._adjacency[rel.source_id].append((rel.target_id, rel))
                    self._reverse_adjacency[rel.target_id].append((rel.source_id, rel))
    
    # ============== CONVENIENCE METHODS FOR AGENTS ==============
    
    def add_target(self, url: str, agent_name: str, properties: Dict[str, Any] = None) -> Entity:
        """Add a target entity"""
        entity = Entity(
            id=f"target:{url}",
            entity_type=EntityType.TARGET,
            name=url,
            properties=properties or {"base_url": url},
            discovered_by=agent_name
        )
        self.add_entity(entity)
        return entity
    
    def add_endpoint(
        self, 
        path: str, 
        method: str,
        target_id: str,
        agent_name: str,
        params: List[str] = None,
        properties: Dict[str, Any] = None
    ) -> Entity:
        """Add an endpoint entity and link to target"""
        props = properties or {}
        props.update({
            "path": path,
            "method": method,
            "params": params or [],
        })
        
        entity = Entity(
            id=f"endpoint:{method}:{path}",
            entity_type=EntityType.ENDPOINT,
            name=f"{method} {path}",
            properties=props,
            discovered_by=agent_name
        )
        self.add_entity(entity)
        
        # Link to target
        self.add_relationship_safe(Relationship(
            source_id=target_id,
            target_id=entity.id,
            relation_type=RelationType.HAS_ENDPOINT,
            discovered_by=agent_name
        ))
        
        return entity
    
    def add_vulnerability(
        self,
        vuln_type: str,
        endpoint_id: str,
        agent_name: str,
        severity: str = "medium",
        confidence: float = 0.8,
        evidence: List[str] = None,
        properties: Dict[str, Any] = None
    ) -> Entity:
        """Add a vulnerability entity and link to endpoint"""
        props = properties or {}
        props.update({
            "vulnerability_type": vuln_type,
            "severity": severity,
            "evidence": evidence or [],
        })
        
        entity = Entity(
            id=f"vuln:{vuln_type}:{endpoint_id}:{datetime.utcnow().timestamp()}",
            entity_type=EntityType.VULNERABILITY,
            name=f"{vuln_type} on {endpoint_id}",
            properties=props,
            confidence=confidence,
            discovered_by=agent_name
        )
        self.add_entity(entity)
        
        # Link endpoint to vulnerability
        self.add_relationship_safe(Relationship(
            source_id=endpoint_id,
            target_id=entity.id,
            relation_type=RelationType.VULNERABLE_TO,
            confidence=confidence,
            discovered_by=agent_name
        ))
        
        return entity
    
    def add_technology(
        self,
        tech_name: str,
        version: str,
        target_id: str,
        agent_name: str,
        properties: Dict[str, Any] = None
    ) -> Entity:
        """Add a technology entity and link to target"""
        props = properties or {}
        props.update({
            "technology": tech_name,
            "version": version,
        })
        
        entity = Entity(
            id=f"tech:{tech_name}:{version}",
            entity_type=EntityType.TECHNOLOGY,
            name=f"{tech_name} {version}",
            properties=props,
            discovered_by=agent_name
        )
        self.add_entity(entity)
        
        # Link target to technology
        self.add_relationship_safe(Relationship(
            source_id=target_id,
            target_id=entity.id,
            relation_type=RelationType.RUNS_ON,
            discovered_by=agent_name
        ))
        
        return entity
    
    def add_credential(
        self,
        username: str,
        auth_type: str,
        agent_name: str,
        properties: Dict[str, Any] = None
    ) -> Entity:
        """Add a credential entity"""
        props = properties or {}
        props.update({
            "username": username,
            "auth_type": auth_type,
        })
        
        entity = Entity(
            id=f"cred:{username}:{auth_type}",
            entity_type=EntityType.CREDENTIAL,
            name=f"{auth_type} credential for {username}",
            properties=props,
            discovered_by=agent_name
        )
        self.add_entity(entity)
        return entity
    
    def link_attack_chain(
        self,
        vuln_ids: List[str],
        chain_name: str,
        agent_name: str,
        impact: str = "high"
    ) -> Entity:
        """Create an attack chain linking multiple vulnerabilities"""
        chain_entity = Entity(
            id=f"chain:{chain_name}:{datetime.utcnow().timestamp()}",
            entity_type=EntityType.ATTACK_CHAIN,
            name=chain_name,
            properties={
                "vulnerabilities": vuln_ids,
                "impact": impact,
                "chain_length": len(vuln_ids),
            },
            discovered_by=agent_name
        )
        self.add_entity(chain_entity)
        
        # Link vulnerabilities in sequence
        for i, vuln_id in enumerate(vuln_ids):
            self.add_relationship_safe(Relationship(
                source_id=chain_entity.id,
                target_id=vuln_id,
                relation_type=RelationType.PART_OF,
                properties={"order": i},
                discovered_by=agent_name
            ))
            
            # Link consecutive vulnerabilities
            if i > 0:
                self.add_relationship_safe(Relationship(
                    source_id=vuln_ids[i-1],
                    target_id=vuln_id,
                    relation_type=RelationType.LEADS_TO,
                    discovered_by=agent_name
                ))
        
        return chain_entity
    
    def to_context_dict(self) -> Dict[str, Any]:
        """Convert graph to legacy shared_context format for backward compatibility"""
        context = {
            "knowledge_graph_version": "1.0",
            "endpoints": [],
            "vulnerabilities": [],
            "tech_stack": {},
            "credentials": [],
            "attack_chains": [],
        }
        
        for entity in self._entities.values():
            if entity.entity_type == EntityType.ENDPOINT:
                context["endpoints"].append({
                    "path": entity.properties.get("path"),
                    "method": entity.properties.get("method"),
                    "params": entity.properties.get("params", []),
                })
            elif entity.entity_type == EntityType.VULNERABILITY:
                context["vulnerabilities"].append({
                    "type": entity.properties.get("vulnerability_type"),
                    "severity": entity.properties.get("severity"),
                    "endpoint": entity.name,
                    "confidence": entity.confidence,
                    "evidence": entity.properties.get("evidence", []),
                })
            elif entity.entity_type == EntityType.TECHNOLOGY:
                tech = entity.properties.get("technology")
                version = entity.properties.get("version")
                if tech:
                    context["tech_stack"][tech] = version
            elif entity.entity_type == EntityType.CREDENTIAL:
                context["credentials"].append({
                    "username": entity.properties.get("username"),
                    "auth_type": entity.properties.get("auth_type"),
                })
            elif entity.entity_type == EntityType.ATTACK_CHAIN:
                context["attack_chains"].append({
                    "name": entity.name,
                    "vulnerabilities": entity.properties.get("vulnerabilities", []),
                    "impact": entity.properties.get("impact"),
                })
        
        # Add statistics
        context["_statistics"] = self.get_statistics()
        
        return context


# Factory function for easy access
def get_knowledge_graph(job_id: int) -> KnowledgeGraph:
    """Get or create knowledge graph for a job"""
    return KnowledgeGraph(job_id)
