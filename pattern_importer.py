"""
Pattern Importer for KeyLeak Detector
Imports secret detection patterns from GitLeaks and secrets-patterns-db
to enhance the runtime web scanner's detection capabilities.
"""

import requests
import re
import json
import logging
from typing import Dict, Optional
from pathlib import Path
import time

logger = logging.getLogger(__name__)


class GitleaksPatternImporter:
    """Import regex patterns from GitLeaks configuration."""
    
    GITLEAKS_CONFIG_URL = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"
    
    def fetch_patterns(self) -> Dict[str, str]:
        """
        Fetch regex patterns from GitLeaks' TOML config.
        
        Returns:
            Dictionary of {pattern_name: regex_string}
        """
        try:
            logger.info("Fetching GitLeaks patterns...")
            response = requests.get(self.GITLEAKS_CONFIG_URL, timeout=10)
            response.raise_for_status()
            
            patterns = {}
            content = response.text
            
            # Extract patterns from TOML format
            # Pattern: id = "pattern-name" ... regex = '''regex_here'''
            rule_sections = content.split('[[rules]]')[1:]  # Skip header
            
            for section in rule_sections:
                # Extract id
                id_match = re.search(r'id\s*=\s*"([^"]+)"', section)
                if not id_match:
                    continue
                
                rule_id = id_match.group(1).lower().replace('-', '_')
                
                # Extract regex (handle both ''' and "" formats)
                regex_match = re.search(r'regex\s*=\s*\'\'\'([^\']+)\'\'\'', section, re.DOTALL)
                if not regex_match:
                    regex_match = re.search(r'regex\s*=\s*"([^"]+)"', section)
                
                if regex_match:
                    regex_pattern = regex_match.group(1).strip()
                    patterns[rule_id] = regex_pattern
            
            logger.info(f"Loaded {len(patterns)} patterns from GitLeaks")
            return patterns
            
        except (requests.RequestException, ValueError, KeyError) as e:
            logger.exception(f"Failed to fetch GitLeaks patterns: {e}")
            return {}


class SecretsPatternsDB:
    """Import patterns from secrets-patterns-db (1,600+ patterns)."""
    
    # Using the stable rules database
    DB_URL = "https://raw.githubusercontent.com/mazen160/secrets-patterns-db/master/db/rules-stable.json"
    
    def fetch_patterns(self, min_confidence: str = "high") -> Dict[str, str]:
        """
        Fetch patterns from secrets-patterns-db.
        
        Args:
            min_confidence: Minimum confidence level ('high', 'medium', 'low')
            
        Returns:
            Dictionary of {pattern_name: regex_string}
        """
        try:
            logger.info("Fetching patterns from secrets-patterns-db...")
            response = requests.get(self.DB_URL, timeout=10)
            response.raise_for_status()
            
            rules = response.json()
            patterns = {}
            
            confidence_levels = {'high': 3, 'medium': 2, 'low': 1}
            min_level = confidence_levels.get(min_confidence.lower(), 3)
            
            for rule in rules:
                confidence = rule.get('confidence', 'low').lower()
                rule_level = confidence_levels.get(confidence, 0)
                
                if rule_level >= min_level:
                    pattern_id = rule.get('id', '')
                    if not pattern_id:
                        pattern_id = rule.get('name', '').lower().replace(' ', '_').replace('-', '_')
                    
                    regex_pattern = rule.get('pattern') or rule.get('regex')
                    
                    if regex_pattern and pattern_id:
                        patterns[pattern_id] = regex_pattern
            
            logger.info(f"Loaded {len(patterns)} patterns from secrets-patterns-db (min confidence: {min_confidence})")
            return patterns
            
        except (requests.RequestException, ValueError, KeyError) as e:
            logger.exception(f"Failed to fetch secrets-patterns-db: {e}")
            return {}


class PatternManager:
    """
    Unified pattern management system.
    Combines patterns from multiple sources with caching.
    """
    
    CACHE_FILE = Path('patterns_cache.json')
    CACHE_EXPIRY_HOURS = 24
    
    def __init__(self, use_cache: bool = True):
        self.use_cache = use_cache
        self.patterns = {}
    
    def load_all_sources(self, include_secrets_db: bool = True) -> Dict[str, str]:
        """
        Load patterns from all available sources.
        
        Args:
            include_secrets_db: Whether to include secrets-patterns-db (1,600+ patterns)
                               Set to False if you only want GitLeaks patterns
        
        Returns:
            Merged dictionary of all patterns
        """
        # Check cache first
        if self.use_cache:
            cached = self._load_from_cache()
            if cached:
                logger.info(f"Loaded {len(cached)} patterns from cache")
                return cached
        
        patterns = {}
        
        # 1. Load from secrets-patterns-db (optional, but comprehensive)
        if include_secrets_db:
            db_importer = SecretsPatternsDB()
            db_patterns = db_importer.fetch_patterns(min_confidence='high')
            patterns.update(db_patterns)
            logger.info(f"Added {len(db_patterns)} patterns from secrets-patterns-db")
        
        # 2. Load from GitLeaks (industry standard)
        gitleaks_importer = GitleaksPatternImporter()
        gitleaks_patterns = gitleaks_importer.fetch_patterns()
        patterns.update(gitleaks_patterns)  # GitLeaks patterns override DB patterns
        logger.info(f"Added {len(gitleaks_patterns)} patterns from GitLeaks")
        
        # Save to cache
        if self.use_cache and patterns:
            self._save_to_cache(patterns)
        
        return patterns
    
    def merge_with_custom(self, custom_patterns: Dict[str, str]) -> Dict[str, str]:
        """
        Merge imported patterns with custom patterns.
        Custom patterns take priority.
        
        Args:
            custom_patterns: Your hand-crafted patterns
            
        Returns:
            Merged dictionary with custom patterns taking priority
        """
        all_patterns = self.load_all_sources()
        
        # Custom patterns override imported ones
        all_patterns.update(custom_patterns)
        
        logger.info(f"Total patterns after merge: {len(all_patterns)}")
        return all_patterns
    
    def get_compiled_patterns(self, patterns: Optional[Dict[str, str]] = None) -> Dict:
        """
        Compile regex patterns for performance.
        
        Args:
            patterns: Pattern dictionary (if None, loads from all sources)
            
        Returns:
            Dictionary of {name: compiled_regex}
        """
        if patterns is None:
            patterns = self.load_all_sources()
        
        compiled = {}
        for name, pattern in patterns.items():
            try:
                compiled[name] = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            except (re.error, Exception) as e:
                logger.warning(f"Failed to compile pattern '{name}': {e}")
                # Don't add this pattern to compiled patterns
        
        logger.info(f"Successfully compiled {len(compiled)}/{len(patterns)} patterns")
        return compiled
    
    def _load_from_cache(self) -> Optional[Dict[str, str]]:
        """Load patterns from cache file if valid."""
        try:
            if not self.CACHE_FILE.exists():
                return None
            
            # Check cache age
            cache_age = time.time() - self.CACHE_FILE.stat().st_mtime
            if cache_age > self.CACHE_EXPIRY_HOURS * 3600:
                logger.info("Pattern cache expired")
                return None
            
            with open(self.CACHE_FILE, 'r') as f:
                patterns = json.load(f)
            
            # Validate cache structure
            if not isinstance(patterns, dict):
                logger.warning("Invalid cache format - expected dict")
                return None
            
            if not all(isinstance(k, str) and isinstance(v, str) for k, v in patterns.items()):
                logger.warning("Invalid cache content - expected string key-value pairs")
                return None
            
            return patterns
            
        except (IOError, json.JSONDecodeError, ValueError) as e:
            logger.exception(f"Failed to load cache: {e}")
            return None
    
    def _save_to_cache(self, patterns: Dict[str, str]):
        """Save patterns to cache file."""
        try:
            with open(self.CACHE_FILE, 'w') as f:
                json.dump(patterns, f, indent=2)
            logger.info(f"Saved {len(patterns)} patterns to cache")
        except Exception as e:
            logger.warning(f"Failed to save cache: {e}")
    
    def clear_cache(self):
        """Clear the pattern cache."""
        try:
            if self.CACHE_FILE.exists():
                self.CACHE_FILE.unlink()
                logger.info("Pattern cache cleared")
        except Exception as e:
            logger.warning(f"Failed to clear cache: {e}")


# Convenience function for simple usage
def get_enhanced_patterns(custom_patterns: Dict[str, str], 
                          use_cache: bool = True,
                          include_secrets_db: bool = False) -> Dict[str, str]:
    """
    Quick function to get enhanced patterns.
    
    Args:
        custom_patterns: Your existing SECRET_PATTERNS
        use_cache: Whether to use caching (recommended)
        include_secrets_db: Include 1,600+ patterns from secrets-patterns-db
                           (GitLeaks' 160 patterns are always included)
    
    Returns:
        Merged pattern dictionary (imported + custom)
    
    Example:
        from pattern_importer import get_enhanced_patterns
        
        SECRET_PATTERNS = get_enhanced_patterns(
            custom_patterns=MY_CUSTOM_PATTERNS,
            use_cache=True,
            include_secrets_db=False  # Just GitLeaks patterns
        )
    """
    manager = PatternManager(use_cache=use_cache)
    
    # Load imported patterns
    imported = manager.load_all_sources(include_secrets_db=include_secrets_db)
    
    # Merge with custom (custom takes priority)
    merged = {**imported, **custom_patterns}
    
    return merged


# CLI for testing
if __name__ == '__main__':
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) > 1 and sys.argv[1] == '--clear-cache':
        PatternManager().clear_cache()
        print("Cache cleared")
        sys.exit(0)
    
    # Test pattern fetching
    print("Testing pattern importers...\n")
    
    # Test GitLeaks
    gitleaks = GitleaksPatternImporter()
    gitleaks_patterns = gitleaks.fetch_patterns()
    print(f"✓ GitLeaks: {len(gitleaks_patterns)} patterns")
    print(f"  Sample: {list(gitleaks_patterns.keys())[:5]}\n")
    
    # Test secrets-patterns-db
    secrets_db = SecretsPatternsDB()
    db_patterns = secrets_db.fetch_patterns(min_confidence='high')
    print(f"✓ Secrets-patterns-db: {len(db_patterns)} patterns")
    print(f"  Sample: {list(db_patterns.keys())[:5]}\n")
    
    # Test merged
    manager = PatternManager()
    all_patterns = manager.load_all_sources(include_secrets_db=True)
    print(f"✓ Total merged: {len(all_patterns)} patterns")
    
    # Save sample output
    with open('patterns_sample.json', 'w') as f:
        sample = dict(list(all_patterns.items())[:10])
        json.dump(sample, f, indent=2)
    print("\n✓ Sample saved to patterns_sample.json")
