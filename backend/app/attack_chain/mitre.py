import json
import os
from typing import Dict, List, Optional, Tuple

class MitreCatalog:
    def __init__(self, catalog_path: str = None):
        if catalog_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            catalog_path = os.path.join(base_dir, "data", "attck_catalog.json")
            
        with open(catalog_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        self.version = data.get("version", "unknown")
        self.techniques = data.get("techniques", {})
        self.tactics = data.get("tactics", {})
        
    def get_technique_info(self, technique_id: str) -> Tuple[str, List[str]]:
        """
        Returns (name, list of tactic_ids).
        If not found, returns ("Unknown Technique", []).
        """
        info = self.techniques.get(technique_id)
        if info:
            return info.get("name", "Unknown Technique"), info.get("tactics", [])
        return "Unknown Technique", []
        
    def get_tactic_name(self, tactic_id: str) -> str:
        """
        Returns the tactic name or "Unknown Tactic".
        """
        return self.tactics.get(tactic_id, "Unknown Tactic")
