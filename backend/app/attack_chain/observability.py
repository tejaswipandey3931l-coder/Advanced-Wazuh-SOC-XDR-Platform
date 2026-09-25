"""
Observability stubs for Attack Chain Reconstruction.
"""

from prometheus_client import Counter, Histogram

RECONSTRUCTION_DURATION = Histogram(
    "attack_chain_reconstruction_duration_seconds",
    "Time spent reconstructing the attack chain graph per incident",
    ["status"]
)

RECONSTRUCTION_NODES_PRODUCED = Histogram(
    "attack_chain_reconstruction_nodes_produced",
    "Number of nodes generated in a chain version"
)

RECONSTRUCTION_EDGES_PRODUCED = Histogram(
    "attack_chain_reconstruction_edges_produced",
    "Number of edges generated in a chain version"
)

RECONSTRUCTION_ERRORS = Counter(
    "attack_chain_reconstruction_errors_total",
    "Total errors during attack chain reconstruction",
    ["error_type"]
)
