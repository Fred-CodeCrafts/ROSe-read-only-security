"""
Model Selection Optimizer

Intelligently selects the most cost-effective Bedrock model based on 
query complexity, accuracy requirements, and available budget.
"""

import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from aws_bedrock_athena_ai.cost_optimization.models import ModelSelectionCriteria

logger = logging.getLogger(__name__)


class ModelTier(Enum):
    """Model performance and cost tiers"""
    FAST = "fast"          # Fastest, cheapest (Claude 3 Haiku)
    BALANCED = "balanced"   # Good balance (Claude 3 Sonnet)
    PREMIUM = "premium"     # Best quality (Claude 3 Opus)


@dataclass
class ModelInfo:
    """Information about a Bedrock model"""
    model_id: str
    name: str
    tier: ModelTier
    
    # Cost per 1M tokens (approximate)
    input_cost_per_1m_tokens: float
    output_cost_per_1m_tokens: float
    
    # Performance characteristics
    max_tokens: int
    avg_response_time_ms: int
    
    # Capabilities
    supports_complex_reasoning: bool
    supports_long_context: bool
    
    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Estimate cost for given token usage"""
        input_cost = (input_tokens / 1_000_000) * self.input_cost_per_1m_tokens
        output_cost = (output_tokens / 1_000_000) * self.output_cost_per_1m_tokens
        return input_cost + output_cost


class ModelSelector:
    """Selects optimal Bedrock model based on requirements and budget"""
    
    def __init__(self):
        # Available models with their characteristics
        self.available_models = {
            "anthropic.claude-3-haiku-20240307-v1:0": ModelInfo(
                model_id="anthropic.claude-3-haiku-20240307-v1:0",
                name="Claude 3 Haiku",
                tier=ModelTier.FAST,
                input_cost_per_1m_tokens=0.25,
                output_cost_per_1m_tokens=1.25,
                max_tokens=4096,
                avg_response_time_ms=800,
                supports_complex_reasoning=False,
                supports_long_context=True
            ),
            "anthropic.claude-3-sonnet-20240229-v1:0": ModelInfo(
                model_id="anthropic.claude-3-sonnet-20240229-v1:0",
                name="Claude 3 Sonnet",
                tier=ModelTier.BALANCED,
                input_cost_per_1m_tokens=3.0,
                output_cost_per_1m_tokens=15.0,
                max_tokens=4096,
                avg_response_time_ms=1500,
                supports_complex_reasoning=True,
                supports_long_context=True
            ),
            "anthropic.claude-3-opus-20240229-v1:0": ModelInfo(
                model_id="anthropic.claude-3-opus-20240229-v1:0",
                name="Claude 3 Opus",
                tier=ModelTier.PREMIUM,
                input_cost_per_1m_tokens=15.0,
                output_cost_per_1m_tokens=75.0,
                max_tokens=4096,
                avg_response_time_ms=3000,
                supports_complex_reasoning=True,
                supports_long_context=True
            )
        }
        
        # Default model for fallback
        self.default_model_id = "anthropic.claude-3-haiku-20240307-v1:0"
    
    def select_model(self, criteria: ModelSelectionCriteria) -> str:
        """Select the best model based on criteria"""
        
        # Get candidate models
        candidates = self._filter_candidates(criteria)
        
        if not candidates:
            logger.warning("No suitable models found, using default")
            return self.default_model_id
        
        # Score candidates
        scored_candidates = []
        for model_id, model_info in candidates.items():
            score = self._score_model(model_info, criteria)
            scored_candidates.append((score, model_id, model_info))
        
        # Sort by score (higher is better)
        scored_candidates.sort(reverse=True)
        
        selected_model_id = scored_candidates[0][1]
        selected_model = scored_candidates[0][2]
        
        logger.info(f"Selected model: {selected_model.name} (score: {scored_candidates[0][0]:.2f})")
        
        return selected_model_id
    
    def _filter_candidates(self, criteria: ModelSelectionCriteria) -> Dict[str, ModelInfo]:
        """Filter models based on hard requirements"""
        
        candidates = {}
        
        for model_id, model_info in self.available_models.items():
            
            # Check if model supports required complexity
            if criteria.query_complexity == "complex" and not model_info.supports_complex_reasoning:
                continue
            
            # Check budget constraints (rough estimate)
            estimated_tokens = self._estimate_token_usage(criteria)
            estimated_cost = model_info.estimate_cost(
                estimated_tokens['input'], 
                estimated_tokens['output']
            )
            
            # Convert budget from tokens to cost (assuming Haiku pricing for budget calculation)
            budget_cost = (criteria.available_budget_tokens / 1_000_000) * 1.25  # Output token cost
            
            if estimated_cost > budget_cost * 2:  # Allow some flexibility
                continue
            
            candidates[model_id] = model_info
        
        return candidates
    
    def _score_model(self, model_info: ModelInfo, criteria: ModelSelectionCriteria) -> float:
        """Score a model based on how well it matches criteria"""
        
        score = 0.0
        
        # Query complexity scoring
        if criteria.query_complexity == "simple":
            if model_info.tier == ModelTier.FAST:
                score += 3.0
            elif model_info.tier == ModelTier.BALANCED:
                score += 1.0
        elif criteria.query_complexity == "moderate":
            if model_info.tier == ModelTier.BALANCED:
                score += 3.0
            elif model_info.tier == ModelTier.FAST:
                score += 2.0
            elif model_info.tier == ModelTier.PREMIUM:
                score += 1.0
        elif criteria.query_complexity == "complex":
            if model_info.tier == ModelTier.PREMIUM:
                score += 3.0
            elif model_info.tier == ModelTier.BALANCED:
                score += 2.0
        
        # Accuracy priority scoring
        if criteria.accuracy_priority == "speed":
            if model_info.tier == ModelTier.FAST:
                score += 2.0
            elif model_info.tier == ModelTier.BALANCED:
                score += 1.0
        elif criteria.accuracy_priority == "balanced":
            if model_info.tier == ModelTier.BALANCED:
                score += 2.0
            else:
                score += 1.0
        elif criteria.accuracy_priority == "accuracy":
            if model_info.tier == ModelTier.PREMIUM:
                score += 2.0
            elif model_info.tier == ModelTier.BALANCED:
                score += 1.5
        
        # Response length scoring
        if criteria.response_length_required == "short":
            score += 1.0  # All models handle short responses well
        elif criteria.response_length_required == "long":
            if model_info.supports_long_context:
                score += 1.0
        
        # Cost efficiency bonus (favor cheaper models when appropriate)
        if model_info.tier == ModelTier.FAST:
            score += 0.5
        
        return score
    
    def _estimate_token_usage(self, criteria: ModelSelectionCriteria) -> Dict[str, int]:
        """Estimate token usage based on criteria"""
        
        # Base estimates
        base_input = 500
        base_output = 200
        
        # Adjust based on complexity
        if criteria.query_complexity == "simple":
            input_tokens = base_input
            output_tokens = base_output
        elif criteria.query_complexity == "moderate":
            input_tokens = base_input * 2
            output_tokens = base_output * 2
        else:  # complex
            input_tokens = base_input * 4
            output_tokens = base_output * 3
        
        # Adjust based on response length
        if criteria.response_length_required == "short":
            output_tokens = int(output_tokens * 0.5)
        elif criteria.response_length_required == "long":
            output_tokens = int(output_tokens * 2)
        
        return {
            'input': input_tokens,
            'output': output_tokens
        }
    
    def get_model_recommendations(self, 
                                 query_type: str,
                                 budget_constraint: str = "free_tier") -> List[Tuple[str, str]]:
        """Get model recommendations for common query types"""
        
        recommendations = []
        
        if query_type == "simple_security_check":
            criteria = ModelSelectionCriteria(
                query_complexity="simple",
                response_length_required="short",
                accuracy_priority="speed",
                available_budget_tokens=1000
            )
        elif query_type == "threat_analysis":
            criteria = ModelSelectionCriteria(
                query_complexity="moderate",
                response_length_required="medium",
                accuracy_priority="balanced",
                available_budget_tokens=5000
            )
        elif query_type == "comprehensive_assessment":
            criteria = ModelSelectionCriteria(
                query_complexity="complex",
                response_length_required="long",
                accuracy_priority="accuracy",
                available_budget_tokens=10000
            )
        else:
            # Default case
            criteria = ModelSelectionCriteria(
                query_complexity="moderate",
                response_length_required="medium",
                accuracy_priority="balanced",
                available_budget_tokens=3000
            )
        
        # Get primary recommendation
        primary_model = self.select_model(criteria)
        primary_info = self.available_models[primary_model]
        
        recommendations.append((
            primary_model,
            f"Primary: {primary_info.name} - Best for {query_type}"
        ))
        
        # Get alternative recommendations
        if budget_constraint == "free_tier":
            # Always include the cheapest option
            haiku_model = "anthropic.claude-3-haiku-20240307-v1:0"
            if haiku_model != primary_model:
                recommendations.append((
                    haiku_model,
                    "Budget Alternative: Claude 3 Haiku - Most cost-effective"
                ))
        
        return recommendations
    
    def estimate_monthly_cost(self, 
                            model_id: str,
                            queries_per_day: int,
                            avg_input_tokens: int = 1000,
                            avg_output_tokens: int = 500) -> Dict[str, float]:
        """Estimate monthly cost for a model usage pattern"""
        
        if model_id not in self.available_models:
            return {"error": "Model not found"}
        
        model_info = self.available_models[model_id]
        
        # Calculate monthly usage
        monthly_queries = queries_per_day * 30
        monthly_input_tokens = monthly_queries * avg_input_tokens
        monthly_output_tokens = monthly_queries * avg_output_tokens
        
        # Calculate costs
        monthly_cost = model_info.estimate_cost(monthly_input_tokens, monthly_output_tokens)
        
        return {
            "model_name": model_info.name,
            "monthly_queries": monthly_queries,
            "monthly_input_tokens": monthly_input_tokens,
            "monthly_output_tokens": monthly_output_tokens,
            "monthly_cost_usd": monthly_cost,
            "cost_per_query": monthly_cost / monthly_queries if monthly_queries > 0 else 0
        }
    
    def get_free_tier_recommendations(self) -> Dict[str, any]:
        """Get recommendations for staying within Free Tier limits"""
        
        # Assume Free Tier gives us ~25,000 tokens per month
        free_tier_budget = 25000
        
        recommendations = {
            "primary_model": "anthropic.claude-3-haiku-20240307-v1:0",
            "max_queries_per_month": 0,
            "optimization_tips": []
        }
        
        haiku_info = self.available_models["anthropic.claude-3-haiku-20240307-v1:0"]
        
        # Estimate how many queries we can do with Free Tier
        # Assume average query uses 1000 input + 500 output tokens
        avg_cost_per_query = haiku_info.estimate_cost(1000, 500)
        free_tier_cost_budget = (free_tier_budget / 1_000_000) * 1.25  # Rough budget
        
        max_queries = int(free_tier_cost_budget / avg_cost_per_query)
        recommendations["max_queries_per_month"] = max_queries
        
        # Add optimization tips
        recommendations["optimization_tips"] = [
            "Use Claude 3 Haiku for most queries to maximize Free Tier usage",
            "Cache frequently asked questions to reduce API calls",
            "Batch similar queries together when possible",
            "Use shorter, more focused prompts to reduce token usage",
            f"Limit to ~{max_queries} queries per month to stay within Free Tier"
        ]
        
        return recommendations