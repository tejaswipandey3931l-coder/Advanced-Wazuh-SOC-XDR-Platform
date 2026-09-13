"""
Phase 4: Threat Intelligence Enrichment Package.
"""

from threat_intel.cache import InMemoryCTICache, ThreatIntelCache
from threat_intel.consensus import ConsensusEngine
from threat_intel.extractor import IOCExtractor
from threat_intel.models import (
    EnrichedObservable,
    EnrichmentConsensus,
    IPClassification,
    NormalizedObservable,
    ProviderHealth,
    ProviderResult,
    ProviderStatus,
    ThreatSeverity,
    ThreatVerdict,
)
from threat_intel.normalizer import (
    classify_ip,
    normalize_domain,
    normalize_email,
    normalize_hash,
    normalize_ip,
    normalize_observable,
    normalize_url,
    refang,
)
from threat_intel.providers import (
    AbuseIPDBProvider,
    BaseThreatIntelProvider,
    LocalFeedProvider,
    ProviderRegistry,
    VirusTotalProvider,
    create_default_registry,
)
from threat_intel.service import ThreatIntelService

__all__ = [
    "ThreatIntelService",
    "IOCExtractor",
    "ConsensusEngine",
    "ThreatIntelCache",
    "InMemoryCTICache",
    "NormalizedObservable",
    "ProviderResult",
    "EnrichedObservable",
    "EnrichmentConsensus",
    "ProviderHealth",
    "ThreatVerdict",
    "ThreatSeverity",
    "ProviderStatus",
    "IPClassification",
    "refang",
    "classify_ip",
    "normalize_observable",
    "normalize_ip",
    "normalize_domain",
    "normalize_url",
    "normalize_hash",
    "normalize_email",
    "BaseThreatIntelProvider",
    "LocalFeedProvider",
    "AbuseIPDBProvider",
    "VirusTotalProvider",
    "ProviderRegistry",
    "create_default_registry",
]
