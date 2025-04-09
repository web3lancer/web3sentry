"""
Base Detector Module.

This module provides the base class for all security detectors.
Think of this as the foundation for all our security detectors - 
like the basic blueprint that all specific detectors will follow.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import logging

# Set up logging so we can see what's happening
logger = logging.getLogger(__name__)

class BaseDetector(ABC):
    """Base class for all security detectors.
    
    This is the parent class that all our specialized detectors will inherit from.
    It defines the common interface and behavior that every detector should have.
    """
    
    def __init__(self, name: str, description: str):
        """Initialize the detector with a name and description.
        
        Args:
            name: A friendly name for this detector
            description: What this detector does in plain English
        """
        self.name = name
        self.description = description
        self.enabled = True  # Detectors are enabled by default
    
    @abstractmethod
    async def analyze(self, transaction_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze transaction data for security issues.
        
        This is where the magic happens! Each detector will implement its own
        security analysis logic in this method.
        
        Args:
            transaction_data: Dictionary containing transaction data to analyze.
            
        Returns:
            Dictionary with analysis results including risk level and details.
        """
        pass
    
    def enable(self):
        """Enable the detector.
        
        Turn this detector on so it can do its job.
        """
        self.enabled = True
        logger.info(f"Detector {self.name} enabled - ready to catch some bad guys!")
        
    def disable(self):
        """Disable the detector.
        
        Put this detector to sleep mode - won't analyze any transactions.
        """
        self.enabled = False
        logger.info(f"Detector {self.name} disabled - taking a break!")
        
    @abstractmethod
    def get_detector_info(self) -> Dict[str, Any]:
        """Return detector metadata.
        
        This provides information about the detector itself - useful for UIs
        and configuration screens.
        """
        return {
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
        }
