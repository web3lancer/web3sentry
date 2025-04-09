"""
Base Detector Module.

This module provides the base class for all security detectors.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

class BaseDetector(ABC):
    """Base class for all security detectors."""
    
    def __init__(self, name: str, description: str):
        """Initialize the detector with a name and description."""
        self.name = name
        self.description = description
        self.enabled = True
    
    @abstractmethod
    async def analyze(self, transaction_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze transaction data for security issues.
        
        Args:
            transaction_data: Dictionary containing transaction data to analyze.
            
        Returns:
            Dictionary with analysis results including risk level and details.
        """
        pass
    
    def enable(self):
        """Enable the detector."""
        self.enabled = True
        logger.info(f"Detector {self.name} enabled")
        
    def disable(self):
        """Disable the detector."""
        self.enabled = False
        logger.info(f"Detector {self.name} disabled")
        
    @abstractmethod
    def get_detector_info(self) -> Dict[str, Any]:
        """Return detector metadata."""
        return {
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
        }
