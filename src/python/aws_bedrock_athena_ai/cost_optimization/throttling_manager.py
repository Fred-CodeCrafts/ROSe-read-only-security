"""
Intelligent Throttling Manager

Implements smart throttling near Free Tier limits to prevent overages
while maintaining system functionality for critical operations.
"""

import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass
from enum import Enum

from aws_bedrock_athena_ai.cost_optimization.models import ServiceType, ThrottleLevel, ThrottlingConfig, UsageMetrics
from aws_bedrock_athena_ai.cost_optimization.usage_tracker import UsageTracker

logger = logging.getLogger(__name__)


class RequestPriority(Enum):
    """Request priority levels"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ThrottledRequest:
    """Represents a throttled request waiting for execution"""
    request_id: str
    service_type: ServiceType
    priority: RequestPriority
    callback: Callable
    args: tuple
    kwargs: dict
    created_at: datetime
    retry_count: int = 0
    max_retries: int = 3


class ThrottlingManager:
    """Manages intelligent throttling based on Free Tier usage"""
    
    def __init__(self, usage_tracker: UsageTracker, 
                 config: Optional[ThrottlingConfig] = None):
        self.usage_tracker = usage_tracker
        self.config = config or ThrottlingConfig()
        
        # Request queues by priority
        self.request_queues: Dict[RequestPriority, List[ThrottledRequest]] = {
            priority: [] for priority in RequestPriority
        }
        
        # Throttling state
        self.current_throttle_levels: Dict[ServiceType, ThrottleLevel] = {}
        self.last_usage_check = datetime.utcnow()
        self.usage_check_interval = timedelta(minutes=5)
        
        # Statistics
        self.throttled_requests_count = 0
        self.bypassed_requests_count = 0
        
    def should_throttle(self, service_type: ServiceType, 
                       priority: RequestPriority = RequestPriority.NORMAL) -> bool:
        """Determine if a request should be throttled"""
        
        # Update throttle levels if needed
        self._update_throttle_levels()
        
        current_level = self.current_throttle_levels.get(service_type, ThrottleLevel.NONE)
        
        # Critical requests bypass most throttling
        if priority == RequestPriority.CRITICAL and self.config.critical_query_bypass:
            if current_level != ThrottleLevel.BLOCKED:
                return False
        
        # High priority requests bypass light throttling
        if priority == RequestPriority.HIGH and self.config.high_priority_bypass:
            if current_level in [ThrottleLevel.NONE, ThrottleLevel.LIGHT]:
                return False
        
        # Apply throttling based on level
        return current_level != ThrottleLevel.NONE
    
    def get_throttle_delay(self, service_type: ServiceType) -> float:
        """Get the delay in seconds for throttled requests"""
        current_level = self.current_throttle_levels.get(service_type, ThrottleLevel.NONE)
        
        if current_level == ThrottleLevel.LIGHT:
            return self.config.light_throttle_delay_seconds
        elif current_level == ThrottleLevel.MODERATE:
            return self.config.moderate_throttle_delay_seconds
        elif current_level == ThrottleLevel.HEAVY:
            return self.config.heavy_throttle_delay_seconds
        elif current_level == ThrottleLevel.BLOCKED:
            return float('inf')  # Indefinite delay
        else:
            return 0.0
    
    async def execute_with_throttling(self, 
                                    service_type: ServiceType,
                                    callback: Callable,
                                    priority: RequestPriority = RequestPriority.NORMAL,
                                    *args, **kwargs) -> Any:
        """Execute a request with intelligent throttling"""
        
        request_id = f"{service_type.value}_{int(time.time() * 1000)}"
        
        # Check if we should throttle
        if self.should_throttle(service_type, priority):
            delay = self.get_throttle_delay(service_type)
            
            if delay == float('inf'):
                # Request is blocked - queue it
                request = ThrottledRequest(
                    request_id=request_id,
                    service_type=service_type,
                    priority=priority,
                    callback=callback,
                    args=args,
                    kwargs=kwargs,
                    created_at=datetime.utcnow()
                )
                
                self.request_queues[priority].append(request)
                self.throttled_requests_count += 1
                
                logger.warning(f"Request {request_id} blocked due to usage limits. Queued for later execution.")
                
                # Wait for throttling to be lifted
                return await self._wait_for_execution(request)
            
            else:
                # Apply delay
                logger.info(f"Throttling request {request_id} for {delay:.1f} seconds")
                await asyncio.sleep(delay)
                self.throttled_requests_count += 1
        
        else:
            if priority in [RequestPriority.HIGH, RequestPriority.CRITICAL]:
                self.bypassed_requests_count += 1
        
        # Execute the request
        try:
            if asyncio.iscoroutinefunction(callback):
                return await callback(*args, **kwargs)
            else:
                return callback(*args, **kwargs)
        except Exception as e:
            logger.error(f"Request {request_id} failed: {e}")
            raise
    
    async def _wait_for_execution(self, request: ThrottledRequest) -> Any:
        """Wait for a blocked request to be executable"""
        
        while True:
            # Check if throttling has been lifted
            if not self.should_throttle(request.service_type, request.priority):
                # Remove from queue and execute
                if request in self.request_queues[request.priority]:
                    self.request_queues[request.priority].remove(request)
                
                logger.info(f"Executing previously blocked request {request.request_id}")
                
                try:
                    if asyncio.iscoroutinefunction(request.callback):
                        return await request.callback(*request.args, **request.kwargs)
                    else:
                        return request.callback(*request.args, **request.kwargs)
                except Exception as e:
                    logger.error(f"Queued request {request.request_id} failed: {e}")
                    raise
            
            # Wait before checking again
            await asyncio.sleep(30)  # Check every 30 seconds
            
            # Check for timeout (requests older than 1 hour are dropped)
            if datetime.utcnow() - request.created_at > timedelta(hours=1):
                logger.error(f"Request {request.request_id} timed out after 1 hour")
                if request in self.request_queues[request.priority]:
                    self.request_queues[request.priority].remove(request)
                raise TimeoutError("Request timed out due to prolonged throttling")
    
    def _update_throttle_levels(self):
        """Update throttle levels based on current usage"""
        
        # Only check usage periodically to avoid overhead
        if datetime.utcnow() - self.last_usage_check < self.usage_check_interval:
            return
        
        self.last_usage_check = datetime.utcnow()
        
        try:
            for service_type in ServiceType:
                throttle_level = self.usage_tracker.get_throttle_level(service_type)
                
                # Log throttle level changes
                old_level = self.current_throttle_levels.get(service_type, ThrottleLevel.NONE)
                if old_level != throttle_level:
                    logger.info(f"Throttle level for {service_type.value} changed: "
                               f"{old_level.value} -> {throttle_level.value}")
                
                self.current_throttle_levels[service_type] = throttle_level
                
        except Exception as e:
            logger.error(f"Failed to update throttle levels: {e}")
    
    def process_queued_requests(self):
        """Process queued requests when throttling is lifted"""
        
        for priority in [RequestPriority.CRITICAL, RequestPriority.HIGH, 
                        RequestPriority.NORMAL, RequestPriority.LOW]:
            
            queue = self.request_queues[priority]
            processed = []
            
            for request in queue[:]:  # Copy to avoid modification during iteration
                if not self.should_throttle(request.service_type, request.priority):
                    # Request can now be processed
                    processed.append(request)
                    queue.remove(request)
                    
                    # Execute in background (fire and forget for now)
                    logger.info(f"Processing queued request {request.request_id}")
            
            if processed:
                logger.info(f"Processed {len(processed)} queued {priority.value} priority requests")
    
    def get_throttling_status(self) -> Dict[str, Any]:
        """Get current throttling status and statistics"""
        
        self._update_throttle_levels()
        
        # Count queued requests
        queued_counts = {
            priority.value: len(queue) 
            for priority, queue in self.request_queues.items()
        }
        
        return {
            'throttle_levels': {
                service.value: level.value 
                for service, level in self.current_throttle_levels.items()
            },
            'queued_requests': queued_counts,
            'total_queued': sum(queued_counts.values()),
            'throttled_requests_count': self.throttled_requests_count,
            'bypassed_requests_count': self.bypassed_requests_count,
            'last_usage_check': self.last_usage_check.isoformat()
        }
    
    def force_usage_check(self):
        """Force an immediate usage check and throttle level update"""
        self.last_usage_check = datetime.utcnow() - self.usage_check_interval
        self._update_throttle_levels()
    
    def clear_queues(self):
        """Clear all queued requests (emergency use only)"""
        total_cleared = sum(len(queue) for queue in self.request_queues.values())
        
        for queue in self.request_queues.values():
            queue.clear()
        
        logger.warning(f"Cleared {total_cleared} queued requests")
        return total_cleared
    
    def set_emergency_mode(self, enabled: bool):
        """Enable/disable emergency mode (blocks all non-critical requests)"""
        
        if enabled:
            # Set all services to heavy throttling
            for service_type in ServiceType:
                self.current_throttle_levels[service_type] = ThrottleLevel.HEAVY
            logger.warning("Emergency throttling mode ENABLED - only critical requests allowed")
        else:
            # Reset to normal operation
            self.force_usage_check()
            logger.info("Emergency throttling mode DISABLED - normal operation resumed")


# Decorator for easy throttling integration
def throttled(service_type: ServiceType, priority: RequestPriority = RequestPriority.NORMAL):
    """Decorator to add throttling to functions"""
    
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Get throttling manager from context (would need to be injected)
            # For now, this is a placeholder for the pattern
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator