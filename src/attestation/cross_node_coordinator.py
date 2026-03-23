#!/usr/bin/env python3
"""
AEGIS Cross-Node Coordinator

Coordinates attestation across multiple compute nodes to detect
coordinated attacks (e.g., multi-agent covert channel exfiltration).

The coordinator maintains a cluster-wide access graph and correlates
events across nodes to detect attacks that single-node monitoring misses.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

# Try to import from AEGIS framework
try:
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from src.common.logger import get_logger
except ImportError:
    import logging
    def get_logger(name: str) -> logging.Logger:
        logging.basicConfig(level=logging.INFO)
        return logging.getLogger(name)

logger = get_logger("aegis.coordinator")


class CorrelationType(Enum):
    """Types of cross-node correlations."""
    COVERT_CHANNEL = "covert_channel"        # Write-read between agents
    DATA_LEAK = "data_leak"                  # Unusual data flow
    ANOMALOUS_CLUSTER_BEHAVIOR = "cluster"   # Multi-node anomaly


@dataclass
class AccessEdge:
    """An edge in the access graph (one agent accessing a resource)."""
    agent_id: str
    node_id: str
    resource_path: str
    action: str  # "read" or "write"
    timestamp: float
    size_bytes: int = 0


@dataclass
class CovertChannel:
    """Detected covert channel between agents."""
    source_agent: str
    target_agent: str
    via_path: str
    detection_time: float
    severity: str  # "MINOR", "MODERATE", "CRITICAL"
    evidence: List[dict] = field(default_factory=list)


@dataclass
class ClusterState:
    """Global cluster state for correlation."""
    access_graph: Dict[str, List[AccessEdge]] = field(default_factory=dict)
    agent_nodes: Dict[str, str] = field(default_factory=dict)  # agent -> node
    node_agents: Dict[str, Set[str]] = field(default_factory=dict)  # node -> agents
    last_update: float = field(default_factory=time.time)


class CrossNodeCoordinator:
    """
    Coordinates attestation across cluster nodes.
    
    Detects coordinated attacks by correlating access patterns
    across all nodes in the HPC cluster.
    """
    
    def __init__(self, 
                 node_id: str,
                 coordinator_address: str = "localhost",
                 coordinator_port: int = 9090,
                 correlation_window: float = 60.0,
                 check_interval: float = 5.0):
        """
        Initialize cross-node coordinator.
        
        Args:
            node_id: This node's identifier
            coordinator_address: Central coordinator address
            coordinator_port: Central coordinator port
            correlation_window: Time window for correlation (seconds)
            check_interval: How often to check for correlations
        """
        self.node_id = node_id
        self.coordinator_address = coordinator_address
        self.coordinator_port = coordinator_port
        self.correlation_window = correlation_window
        self.check_interval = check_interval
        
        # Local state
        self.local_edges: List[AccessEdge] = []
        self.running = False
        
        # Cluster-wide state (in distributed setup, this would be shared)
        self.cluster_state = ClusterState()
        
        # Callbacks
        self.correlation_callbacks: List[Callable[[CorrelationType, list], None]] = []
        
        # For distributed mode: connection to central coordinator
        self.coordinator_conn: Optional[asyncio.StreamReader] = None
        
        # Thread safety
        self.lock = threading.RLock()
        
    def register_correlation_callback(self, 
                                       callback: Callable[[CorrelationType, list], None]):
        """Register callback for correlation detections."""
        self.correlation_callbacks.append(callback)
    
    # ==================== Event Ingestion ====================
    
    def ingest_local_event(self, 
                          agent_id: str, 
                          resource_path: str,
                          action: str,
                          size_bytes: int = 0):
        """Ingest a local event from this node's attestation engine."""
        with self.lock:
            edge = AccessEdge(
                agent_id=agent_id,
                node_id=self.node_id,
                resource_path=resource_path,
                action=action,
                timestamp=time.time(),
                size_bytes=size_bytes
            )
            self.local_edges.append(edge)
            
            # Also update cluster state
            self.cluster_state.access_graph.setdefault(agent_id, []).append(edge)
            self.cluster_state.agent_nodes[agent_id] = self.node_id
            self.cluster_state.node_agents.setdefault(self.node_id, set()).add(agent_id)
            self.cluster_state.last_update = time.time()
            
    def ingest_remote_event(self, edge: AccessEdge):
        """Ingest an event from another node (via coordinator)."""
        with self.lock:
            self.cluster_state.access_graph.setdefault(edge.agent_id, []).append(edge)
            self.cluster_state.agent_nodes[edge.agent_id] = edge.node_id
            self.cluster_state.node_agents.setdefault(edge.node_id, set()).add(edge.agent_id)
    
    # ==================== Correlation Detection ====================
    
    def check_covert_channels(self) -> List[CovertChannel]:
        """
        Check for covert channel patterns.
        
        Detection logic:
        1. Agent A writes to path P
        2. Agent B reads from path P
        3. Within correlation_window
        4. Different nodes OR different agents
        
        This is the key detection for Exp 4 (Coordinated Multi-Agent Exfiltration).
        """
        channels = []
        cutoff_time = time.time() - self.correlation_window
        
        with self.lock:
            # Group by resource path
            path_events: Dict[str, List[AccessEdge]] = defaultdict(list)
            
            for agent_id, edges in self.cluster_state.access_graph.items():
                for edge in edges:
                    if edge.timestamp >= cutoff_time:
                        path_events[edge.resource_path].append(edge)
            
            # Check each path for write-read patterns
            for path, events in path_events.items():
                writes = [e for e in events if e.action == "write"]
                reads = [e for e in events if e.action == "read"]
                
                if not writes or not reads:
                    continue
                
                # Check write-read pairs
                for write in writes:
                    for read in reads:
                        # Must be different agents
                        if write.agent_id == read.agent_id:
                            continue
                        
                        # Must be temporal correlation
                        time_diff = abs(read.timestamp - write.timestamp)
                        if time_diff > self.correlation_window:
                            continue
                        
                        # This is a covert channel!
                        severity = self._assess_covert_severity(write, read, time_diff)
                        
                        channel = CovertChannel(
                            source_agent=write.agent_id,
                            target_agent=read.agent_id,
                            via_path=path,
                            detection_time=time.time(),
                            severity=severity,
                            evidence=[
                                {
                                    "agent": write.agent_id,
                                    "node": write.node_id,
                                    "action": "write",
                                    "timestamp": write.timestamp,
                                    "size": write.size_bytes
                                },
                                {
                                    "agent": read.agent_id,
                                    "node": read.node_id,
                                    "action": "read", 
                                    "timestamp": read.timestamp,
                                    "size": read.size_bytes
                                }
                            ]
                        )
                        channels.append(channel)
                        
                        logger.warning(
                            f"COVERT CHANNEL DETECTED: {write.agent_id} -> {read.agent_id} "
                            f"via {path} (time_diff={time_diff:.2f}s, severity={severity})"
                        )
        
        return channels
    
    def _assess_covert_severity(self, write: AccessEdge, read: AccessEdge, 
                                time_diff: float) -> str:
        """Assess severity of detected covert channel."""
        # Same node = easier to detect = less severe
        same_node = write.node_id == read.node_id
        
        # Same agent = self-loop = less concerning
        same_agent = write.agent_id == read.agent_id
        
        # Time correlation (closer = more suspicious)
        if time_diff < 5.0:
            time_score = "CRITICAL"
        elif time_diff < 30.0:
            time_score = "MODERATE"
        else:
            time_score = "MINOR"
        
        if same_node and same_agent:
            return "MINOR"
        elif not same_node:
            return "CRITICAL"  # Cross-node covert channel is worst
        else:
            return time_score
    
    def check_anomalous_cluster_behavior(self) -> List[dict]:
        """
        Check for anomalous multi-node patterns.
        
        Examples:
        - Unusual number of agents per node
        - Data volume spikes
        - Network egress patterns
        """
        anomalies = []
        
        with self.lock:
            # Check agent distribution
            for node, agents in self.cluster_state.node_agents.items():
                if len(agents) > 10:  # Threshold
                    anomalies.append({
                        "type": "HIGH_AGENT_DENSITY",
                        "node": node,
                        "count": len(agents),
                        "severity": "MODERATE"
                    })
            
            # Check for data exfiltration patterns
            for agent_id, edges in self.cluster_state.access_graph.items():
                read_bytes = sum(e.size_bytes for e in edges 
                               if e.action == "read" and e.timestamp > time.time() - 3600)
                write_bytes = sum(e.size_bytes for e in edges 
                                if e.action == "write" and e.timestamp > time.time() - 3600)
                
                # Unusual read/write ratio
                if read_bytes > 100 * 1024 * 1024 and write_bytes < 1024:  # 100MB read, 1KB write
                    anomalies.append({
                        "type": "HIGH_READ_LOW_WRITE",
                        "agent": agent_id,
                        "read_mb": read_bytes / (1024*1024),
                        "write_mb": write_bytes / (1024*1024),
                        "severity": "MINOR"
                    })
        
        return anomalies
    
    def check_all_correlations(self) -> Dict[CorrelationType, List]:
        """Run all correlation checks."""
        results = {}
        
        # Check covert channels
        channels = self.check_covert_channels()
        if channels:
            results[CorrelationType.COVERT_CHANNEL] = channels
            for callback in self.correlation_callbacks:
                try:
                    callback(CorrelationType.COVERT_CHANNEL, channels)
                except Exception as e:
                    logger.error(f"Callback error: {e}")
        
        # Check cluster anomalies
        anomalies = self.check_anomalous_cluster_behavior()
        if anomalies:
            results[CorrelationType.ANOMALOUS_CLUSTER_BEHAVIOR] = anomalies
        
        return results
    
    # ==================== Distributed Mode ====================
    
    async def connect_to_coordinator(self):
        """Connect to central coordinator for distributed correlation."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.coordinator_address,
                    self.coordinator_port
                ),
                timeout=5.0
            )
            self.coordinator_conn = reader
            logger.info(f"Connected to coordinator at {self.coordinator_address}")
            return True
        except Exception as e:
            logger.warning(f"Could not connect to coordinator: {e}")
            return False
    
    async def sync_events_to_coordinator(self):
        """Send local events to central coordinator."""
        if not self.coordinator_conn:
            return
        
        try:
            with self.lock:
                # Serialize and send
                event_data = {
                    "node_id": self.node_id,
                    "events": [
                        {
                            "agent_id": e.agent_id,
                            "resource_path": e.resource_path,
                            "action": e.action,
                            "timestamp": e.timestamp,
                            "size_bytes": e.size_bytes
                        }
                        for e in self.local_edges[-100:]  # Last 100 events
                    ]
                }
            
            writer = self.coordinator_writer  # Would need proper async writer
            writer.write(json.dumps(event_data).encode() + b'\n')
            await writer.drain()
            
        except Exception as e:
            logger.error(f"Sync error: {e}")
    
    # ==================== Main Loop ====================
    
    def start(self):
        """Start correlation monitoring loop."""
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Cross-node coordinator started")
    
    def stop(self):
        """Stop correlation monitoring."""
        self.running = False
        logger.info("Cross-node coordinator stopped")
    
    def _monitor_loop(self):
        """Background monitoring loop."""
        while self.running:
            try:
                # Run correlation checks
                results = self.check_all_correlations()
                
                if results:
                    logger.info(f"Correlation check complete: {list(results.keys())}")
                    
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
            
            # Sleep until next check
            time.sleep(self.check_interval)
    
    def get_cluster_state(self) -> ClusterState:
        """Get current cluster state."""
        with self.lock:
            return self.cluster_state
    
    def export_state(self) -> dict:
        """Export cluster state for debugging/visualization."""
        with self.lock:
            return {
                "node_id": self.node_id,
                "timestamp": time.time(),
                "access_graph": {
                    agent: [
                        {
                            "node": e.node_id,
                            "path": e.resource_path,
                            "action": e.action,
                            "timestamp": e.timestamp
                        }
                        for e in edges
                    ]
                    for agent, edges in self.cluster_state.access_graph.items()
                },
                "agent_nodes": self.cluster_state.agent_nodes,
                "node_counts": {
                    node: len(agents)
                    for node, agents in self.cluster_state.node_agents.items()
                }
            }


class CentralCoordinator:
    """
    Central coordinator that aggregates events from all nodes.
    
    In a production deployment, this would run on a dedicated
    management node and maintain the global access graph.
    """
    
    def __init__(self, port: int = 9090):
        self.port = port
        self.node_states: Dict[str, dict] = {}
        self.global_graph: Dict[str, List[AccessEdge]] = defaultdict(list)
        self.running = False
        
    async def handle_node_connection(self, reader: asyncio.StreamReader, 
                                     writer: asyncio.StreamWriter):
        """Handle incoming connection from a compute node."""
        addr = writer.get_extra_info('peername')
        logger.info(f"Node connected: {addr}")
        
        try:
            while True:
                data = await reader.readline()
                if not data:
                    break
                    
                node_data = json.loads(data.decode())
                self._process_node_data(node_data)
                
        except Exception as e:
            logger.error(f"Connection error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    def _process_node_data(self, node_data: dict):
        """Process events received from a node."""
        node_id = node_data.get("node_id")
        events = node_data.get("events", [])
        
        self.node_states[node_id] = node_data
        
        for event in events:
            edge = AccessEdge(
                agent_id=event["agent_id"],
                node_id=node_id,
                resource_path=event["resource_path"],
                action=event["action"],
                timestamp=event["timestamp"],
                size_bytes=event.get("size_bytes", 0)
            )
            self.global_graph[edge.agent_id].append(edge)
    
    async def start(self):
        """Start the central coordinator server."""
        server = await asyncio.start_server(
            self.handle_node_connection,
            '0.0.0.0',
            self.port
        )
        
        async with server:
            await server.serve_forever()


# Standalone test
if __name__ == "__main__":
    logger.setLevel("INFO")
    
    print("=== AEGIS Cross-Node Coordinator Test ===")
    
    # Create coordinator for node "compute-01"
    coordinator = CrossNodeCoordinator(
        node_id="compute-01",
        correlation_window=60.0
    )
    
    # Simulate some events
    print("Ingesting test events...")
    coordinator.ingest_local_event(
        agent_id="agent-001",
        resource_path="/tmp/.hidden_cache",
        action="write",
        size_bytes=2048
    )
    coordinator.ingest_local_event(
        agent_id="agent-002", 
        resource_path="/tmp/.hidden_cache",
        action="read",
        size_bytes=2048
    )
    
    # Check for covert channels
    print("Checking for covert channels...")
    channels = coordinator.check_covert_channels()
    
    if channels:
        for ch in channels:
            print(f"  ⚠ COVERT CHANNEL: {ch.source_agent} -> {ch.target_agent}")
            print(f"    Via: {ch.via_path}")
            print(f"    Severity: {ch.severity}")
    else:
        print("  ✓ No covert channels detected")
    
    # Start monitor
    coordinator.start()
    print("Coordinator running. Press Ctrl+C to stop.")
    
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        coordinator.stop()
        print("Stopped.")