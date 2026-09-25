import hashlib
import urllib.parse
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
import uuid

from .ip_utils import canonical_ip
from ..models.normalized_event import NormalizedEvent

@dataclass
class EntityInfo:
    entity_type: str
    canonical_id: str
    value: str  # For API display / human readable

def normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")

def normalize_url(url: str) -> str:
    """
    Parse URL; lowercase scheme and host; strip default ports (80/443); 
    sort query parameters by key; strip fragment.
    """
    url = url.strip()
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    
    # Handle default ports
    if ":" in netloc:
        host, port = netloc.split(":", 1)
        if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
            netloc = host
            
    query = parsed.query
    if query:
        # Sort query parameters by key
        qs = urllib.parse.parse_qsl(query, keep_blank_values=True)
        qs = sorted(qs, key=lambda x: x[0])
        query = urllib.parse.urlencode(qs)
        
    normalized_parsed = urllib.parse.SplitResult(scheme, netloc, parsed.path, query, "")
    return urllib.parse.urlunsplit(normalized_parsed)

def extract_entities_from_event(event: NormalizedEvent, add_warning_cb) -> List[EntityInfo]:
    entities = []
    
    if event.hostname and event.hostname.strip():
        val = event.hostname.strip().lower()
        entities.append(EntityInfo("HOST", f"host:{val}", val))
        
    if event.user and event.user.strip():
        val = event.user.strip().lower()
        entities.append(EntityInfo("USER", f"user:{val}", val))
        
    if event.agent_id and event.agent_id.strip():
        val = event.agent_id.strip()
        entities.append(EntityInfo("AGENT", f"agent:{val}", val))
        
    for ip_field in [event.src_ip, event.dst_ip]:
        if ip_field and ip_field.strip():
            try:
                val = canonical_ip(ip_field)
                entities.append(EntityInfo("IP", f"ip:{val}", val))
            except ValueError as e:
                add_warning_cb({"type": "invalid_ip_format", "raw_value": ip_field, "error": str(e)})

    if event.domain and event.domain.strip():
        val = normalize_domain(event.domain)
        entities.append(EntityInfo("DOMAIN", f"domain:{val}", val))
        
    if event.url and event.url.strip():
        val = normalize_url(event.url)
        h = hashlib.sha256(val.encode("utf-8")).hexdigest()
        entities.append(EntityInfo("URL", f"url:{h}", event.url.strip()))
        
    if event.process_name and event.process_name.strip():
        pid = event.process_pid if event.process_pid is not None else 0
        pname = event.process_name.strip()
        h_input = f"{event.id}:{pname}:{pid}"
        h = hashlib.sha256(h_input.encode("utf-8")).hexdigest()
        entities.append(EntityInfo("PROCESS", f"process_obs:{h}", f"{pname} ({pid})"))
        
    if (event.file_hash_sha256 and event.file_hash_sha256.strip()) or (event.file_path and event.file_path.strip()):
        if event.file_hash_sha256 and event.file_hash_sha256.strip():
            val = event.file_hash_sha256.strip().lower()
            entities.append(EntityInfo("FILE", f"file_sha256:{val}", val))
        else:
            val = event.file_path.strip()
            h = hashlib.sha256(val.encode("utf-8")).hexdigest()
            entities.append(EntityInfo("FILE", f"file_path:{h}", val))
            
    if event.file_hash_md5 and event.file_hash_md5.strip():
        val = event.file_hash_md5.strip().lower()
        entities.append(EntityInfo("FILE_HASH_MD5", f"hash_md5:{val}", val))

    return entities

def canonicalize_ioc(ioc_type: str, ioc_value: str) -> Optional[str]:
    """
    Returns canonical IOC representation or None if invalid/unsupported (e.g. email).
    """
    ioc_value = ioc_value.strip()
    if not ioc_value:
        return None
        
    if ioc_type == "ip":
        try:
            return canonical_ip(ioc_value)
        except ValueError:
            return None
    elif ioc_type == "domain":
        return normalize_domain(ioc_value)
    elif ioc_type == "url":
        return normalize_url(ioc_value)
    elif ioc_type == "file_hash":
        return ioc_value.lower()
    else:
        # email or other unsupported types
        return None
