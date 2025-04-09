"""
Risk Utility Functions.

This module provides common risk assessment utilities used across detectors.
"""
from typing import List, Dict, Any


def get_risk_level_priority(risk_level: str) -> int:
    """Get numerical priority for risk level for comparison.
    
    Args:
        risk_level: String representation of a risk level
        
    Returns:
        Integer priority value (higher means more severe)
    """
    risk_levels = {
        "safe": 0,
        "unknown": 1,
        "low": 2,
        "medium": 3,
        "high": 4,
        "critical": 5,
        "error": 6
    }
    return risk_levels.get(risk_level.lower(), 0)


def calculate_highest_risk_level(risk_levels: List[str]) -> str:
    """Calculate the highest risk level from a list of risk levels.
    
    Args:
        risk_levels: List of risk level strings
        
    Returns:
        The highest risk level found
    """
    if not risk_levels:
        return "unknown"
        
    # Return the highest risk level found
    highest_risk = "safe"
    highest_index = get_risk_level_priority("safe")
    
    for level in risk_levels:
        level_index = get_risk_level_priority(level)
        if level_index > highest_index:
            highest_index = level_index
            highest_risk = level
                
    return highest_risk


def combine_detector_results(results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Combine results from multiple detectors into a single result.
    
    Args:
        results: Dictionary of detector results by detector ID
        
    Returns:
        Combined result with overall risk level
    """
    risk_levels = []
    all_details = []
    
    for detector_id, result in results.items():
        if result.get("success", False) and "risk_level" in result:
            risk_levels.append(result["risk_level"])
            
        if "details" in result and isinstance(result["details"], list):
            all_details.extend([f"[{detector_id}] {detail}" for detail in result["details"]])
        elif "details" in result and isinstance(result["details"], str):
            all_details.append(f"[{detector_id}] {result['details']}")
                
    overall_risk = calculate_highest_risk_level(risk_levels)
    
    return {
        "overall_risk": overall_risk,
        "details": all_details,
        "detector_results": results
    }