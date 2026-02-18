"""
Cache Manager for Query Results and Insights

Implements intelligent caching to reduce AWS service calls and improve performance
while staying within Free Tier limits.
"""

import hashlib
import json
import logging
import pickle
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union
from pathlib import Path
import threading

from aws_bedrock_athena_ai.cost_optimization.models import CacheEntry, CacheStats

logger = logging.getLogger(__name__)


class CacheManager:
    """Manages caching of query results and AI insights"""
    
    def __init__(self, 
                 max_size_mb: int = 100,
                 default_ttl_seconds: int = 3600,
                 cache_dir: Optional[str] = None):
        
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.default_ttl_seconds = default_ttl_seconds
        
        # In-memory cache
        self.cache: Dict[str, CacheEntry] = {}
        self.stats = CacheStats()
        
        # File-based persistent cache
        self.cache_dir = Path(cache_dir) if cache_dir else Path.cwd() / ".cache"
        self.cache_dir.mkdir(exist_ok=True)
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Load persistent cache on startup
        self._load_persistent_cache()
    
    def _generate_cache_key(self, prefix: str, *args, **kwargs) -> str:
        """Generate a unique cache key from arguments"""
        
        # Create a deterministic string from arguments
        key_data = {
            'prefix': prefix,
            'args': args,
            'kwargs': sorted(kwargs.items()) if kwargs else {}
        }
        
        key_string = json.dumps(key_data, sort_keys=True, default=str)
        
        # Generate hash
        return hashlib.sha256(key_string.encode()).hexdigest()[:16]
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        
        with self._lock:
            entry = self.cache.get(key)
            
            if entry is None:
                self.stats.miss_count += 1
                return None
            
            # Check if expired
            if entry.is_expired():
                self._remove_entry(key)
                self.stats.miss_count += 1
                return None
            
            # Update access statistics
            entry.update_access()
            self.stats.hit_count += 1
            
            logger.debug(f"Cache hit for key: {key}")
            return entry.value
    
    def put(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> bool:
        """Put value in cache"""
        
        with self._lock:
            ttl = ttl_seconds or self.default_ttl_seconds
            
            # Estimate size
            try:
                serialized = pickle.dumps(value)
                size_bytes = len(serialized)
            except Exception as e:
                logger.warning(f"Failed to serialize cache value: {e}")
                return False
            
            # Check if we need to make space
            if not self._ensure_space(size_bytes):
                logger.warning(f"Failed to make space for cache entry of size {size_bytes}")
                return False
            
            # Create cache entry
            entry = CacheEntry(
                key=key,
                value=value,
                created_at=datetime.utcnow(),
                last_accessed=datetime.utcnow(),
                ttl_seconds=ttl,
                size_bytes=size_bytes
            )
            
            # Remove existing entry if present
            if key in self.cache:
                self._remove_entry(key)
            
            # Add new entry
            self.cache[key] = entry
            self.stats.total_entries += 1
            self.stats.total_size_bytes += size_bytes
            
            logger.debug(f"Cached value for key: {key} (size: {size_bytes} bytes, TTL: {ttl}s)")
            
            # Persist to disk for important entries
            self._persist_entry(key, entry)
            
            return True
    
    def cache_query_result(self, query: str, parameters: Dict[str, Any], 
                          result: Any, ttl_seconds: Optional[int] = None) -> str:
        """Cache a query result with automatic key generation"""
        
        key = self._generate_cache_key("query", query, **parameters)
        
        # Use longer TTL for query results (they're expensive to regenerate)
        query_ttl = ttl_seconds or (self.default_ttl_seconds * 2)
        
        if self.put(key, result, query_ttl):
            logger.info(f"Cached query result (key: {key})")
            return key
        else:
            logger.warning(f"Failed to cache query result")
            return ""
    
    def get_cached_query_result(self, query: str, parameters: Dict[str, Any]) -> Optional[Any]:
        """Get cached query result"""
        
        key = self._generate_cache_key("query", query, **parameters)
        result = self.get(key)
        
        if result is not None:
            logger.info(f"Using cached query result (key: {key})")
        
        return result
    
    def cache_ai_insight(self, input_data: Any, model_id: str, 
                        insight: Any, ttl_seconds: Optional[int] = None) -> str:
        """Cache an AI-generated insight"""
        
        key = self._generate_cache_key("insight", model_id, input_data)
        
        # AI insights can be cached longer since they're expensive
        insight_ttl = ttl_seconds or (self.default_ttl_seconds * 4)
        
        if self.put(key, insight, insight_ttl):
            logger.info(f"Cached AI insight (key: {key})")
            return key
        else:
            logger.warning(f"Failed to cache AI insight")
            return ""
    
    def get_cached_ai_insight(self, input_data: Any, model_id: str) -> Optional[Any]:
        """Get cached AI insight"""
        
        key = self._generate_cache_key("insight", model_id, input_data)
        result = self.get(key)
        
        if result is not None:
            logger.info(f"Using cached AI insight (key: {key})")
        
        return result
    
    def _ensure_space(self, required_bytes: int) -> bool:
        """Ensure there's enough space in cache"""
        
        # Check if we have enough space
        if self.stats.total_size_bytes + required_bytes <= self.max_size_bytes:
            return True
        
        # Need to evict entries - use LRU strategy
        entries_by_access = sorted(
            self.cache.items(),
            key=lambda x: x[1].last_accessed
        )
        
        space_freed = 0
        entries_to_remove = []
        
        for key, entry in entries_by_access:
            entries_to_remove.append(key)
            space_freed += entry.size_bytes
            
            if self.stats.total_size_bytes - space_freed + required_bytes <= self.max_size_bytes:
                break
        
        # Remove entries
        for key in entries_to_remove:
            self._remove_entry(key)
            self.stats.eviction_count += 1
        
        logger.info(f"Evicted {len(entries_to_remove)} cache entries to free {space_freed} bytes")
        
        return self.stats.total_size_bytes + required_bytes <= self.max_size_bytes
    
    def _remove_entry(self, key: str):
        """Remove entry from cache"""
        
        if key in self.cache:
            entry = self.cache[key]
            self.stats.total_entries -= 1
            self.stats.total_size_bytes -= entry.size_bytes
            del self.cache[key]
            
            # Remove from persistent storage
            self._remove_persistent_entry(key)
    
    def _persist_entry(self, key: str, entry: CacheEntry):
        """Persist cache entry to disk"""
        
        try:
            cache_file = self.cache_dir / f"{key}.cache"
            
            with open(cache_file, 'wb') as f:
                pickle.dump(entry, f)
                
        except Exception as e:
            logger.warning(f"Failed to persist cache entry {key}: {e}")
    
    def _remove_persistent_entry(self, key: str):
        """Remove persistent cache entry"""
        
        try:
            cache_file = self.cache_dir / f"{key}.cache"
            if cache_file.exists():
                cache_file.unlink()
        except Exception as e:
            logger.warning(f"Failed to remove persistent cache entry {key}: {e}")
    
    def _load_persistent_cache(self):
        """Load persistent cache entries on startup"""
        
        try:
            cache_files = list(self.cache_dir.glob("*.cache"))
            loaded_count = 0
            
            for cache_file in cache_files:
                try:
                    with open(cache_file, 'rb') as f:
                        entry = pickle.load(f)
                    
                    # Check if entry is still valid
                    if not entry.is_expired():
                        key = cache_file.stem
                        self.cache[key] = entry
                        self.stats.total_entries += 1
                        self.stats.total_size_bytes += entry.size_bytes
                        loaded_count += 1
                    else:
                        # Remove expired persistent entry
                        cache_file.unlink()
                        
                except Exception as e:
                    logger.warning(f"Failed to load cache file {cache_file}: {e}")
                    # Remove corrupted file
                    try:
                        cache_file.unlink()
                    except:
                        pass
            
            if loaded_count > 0:
                logger.info(f"Loaded {loaded_count} persistent cache entries")
                
        except Exception as e:
            logger.warning(f"Failed to load persistent cache: {e}")
    
    def cleanup_expired(self) -> int:
        """Remove expired entries from cache"""
        
        with self._lock:
            expired_keys = []
            
            for key, entry in self.cache.items():
                if entry.is_expired():
                    expired_keys.append(key)
            
            for key in expired_keys:
                self._remove_entry(key)
            
            if expired_keys:
                logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")
            
            return len(expired_keys)
    
    def clear(self):
        """Clear all cache entries"""
        
        with self._lock:
            entry_count = len(self.cache)
            
            # Clear in-memory cache
            self.cache.clear()
            
            # Clear persistent cache
            try:
                for cache_file in self.cache_dir.glob("*.cache"):
                    cache_file.unlink()
            except Exception as e:
                logger.warning(f"Failed to clear persistent cache: {e}")
            
            # Reset statistics
            self.stats = CacheStats()
            
            logger.info(f"Cleared {entry_count} cache entries")
    
    def get_cache_stats(self) -> CacheStats:
        """Get cache performance statistics"""
        
        with self._lock:
            # Update current stats
            self.stats.total_entries = len(self.cache)
            self.stats.total_size_bytes = sum(entry.size_bytes for entry in self.cache.values())
            
            return self.stats
    
    def get_cache_info(self) -> Dict[str, Any]:
        """Get detailed cache information"""
        
        with self._lock:
            stats = self.get_cache_stats()
            
            # Get top accessed entries
            top_entries = sorted(
                self.cache.items(),
                key=lambda x: x[1].access_count,
                reverse=True
            )[:10]
            
            return {
                'stats': {
                    'total_entries': stats.total_entries,
                    'total_size_mb': stats.size_mb,
                    'hit_rate': stats.hit_rate,
                    'hit_count': stats.hit_count,
                    'miss_count': stats.miss_count,
                    'eviction_count': stats.eviction_count
                },
                'configuration': {
                    'max_size_mb': self.max_size_bytes / (1024 * 1024),
                    'default_ttl_seconds': self.default_ttl_seconds,
                    'cache_dir': str(self.cache_dir)
                },
                'top_entries': [
                    {
                        'key': key[:16] + '...' if len(key) > 16 else key,
                        'access_count': entry.access_count,
                        'size_kb': entry.size_bytes / 1024,
                        'age_minutes': (datetime.utcnow() - entry.created_at).total_seconds() / 60
                    }
                    for key, entry in top_entries
                ]
            }
    
    def optimize_cache(self):
        """Optimize cache performance"""
        
        with self._lock:
            # Clean up expired entries
            expired_count = self.cleanup_expired()
            
            # If cache is getting full, preemptively evict least accessed entries
            if self.stats.total_size_bytes > (self.max_size_bytes * 0.8):
                target_size = int(self.max_size_bytes * 0.6)
                space_to_free = self.stats.total_size_bytes - target_size
                
                # Sort by access count and age
                entries_by_priority = sorted(
                    self.cache.items(),
                    key=lambda x: (x[1].access_count, x[1].last_accessed)
                )
                
                space_freed = 0
                removed_count = 0
                
                for key, entry in entries_by_priority:
                    if space_freed >= space_to_free:
                        break
                    
                    self._remove_entry(key)
                    space_freed += entry.size_bytes
                    removed_count += 1
                    self.stats.eviction_count += 1
                
                logger.info(f"Proactively evicted {removed_count} entries to optimize cache")
            
            logger.info(f"Cache optimization complete: {expired_count} expired entries removed")


# Global cache instance (singleton pattern)
_global_cache: Optional[CacheManager] = None


def get_cache_manager(max_size_mb: int = 100, 
                     default_ttl_seconds: int = 3600,
                     cache_dir: Optional[str] = None) -> CacheManager:
    """Get or create global cache manager instance"""
    
    global _global_cache
    
    if _global_cache is None:
        _global_cache = CacheManager(
            max_size_mb=max_size_mb,
            default_ttl_seconds=default_ttl_seconds,
            cache_dir=cache_dir
        )
    
    return _global_cache


# Decorator for automatic caching
def cached(ttl_seconds: Optional[int] = None, 
          cache_key_prefix: str = "func"):
    """Decorator to automatically cache function results"""
    
    def decorator(func):
        def wrapper(*args, **kwargs):
            cache = get_cache_manager()
            
            # Generate cache key
            key = cache._generate_cache_key(cache_key_prefix, func.__name__, *args, **kwargs)
            
            # Try to get from cache
            result = cache.get(key)
            if result is not None:
                return result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            cache.put(key, result, ttl_seconds)
            
            return result
        
        return wrapper
    return decorator