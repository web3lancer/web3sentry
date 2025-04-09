"""
Detector Service API.

This module provides an interface for integrating security detectors into Web3lancer.
"""
import logging
from typing import Dict, Any, List, Optional
import asyncio
from ..detectors.base_detector import BaseDetector
from ..detectors.multisig_detector import MultisigDetector
from ..detectors.approvals_detector import ApprovalsDetector

logger = logging.getLogger(__name__)

class DetectorService:
    """Service for managing and using security detectors."""
    
    def __init__(self):
        """Initialize the detector service."""
        self.detectors = {}
        self.initialize_detectors()
        
    def initialize_detectors(self):
        """Initialize and register all available detectors."""
        try:
            # Initialize multisig detector
            multisig_detector = MultisigDetector()
            self.register_detector("multisig", multisig_detector)
            
            # Initialize approvals detector
            approvals_detector = ApprovalsDetector()
            self.register_detector("approvals", approvals_detector)
            
            logger.info("All detectors initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing detectors: {str(e)}")
            
    def register_detector(self, detector_id: str, detector: BaseDetector):
        """Register a detector with the service."""
        self.detectors[detector_id] = detector
        logger.info(f"Registered detector: {detector_id} - {detector.name}")
        
    def get_detector(self, detector_id: str) -> Optional[BaseDetector]:
        """Get a detector by its ID."""
        return self.detectors.get(detector_id)
        
    def get_all_detectors(self) -> List[Dict[str, Any]]:
        """Get information about all registered detectors."""
        return [
            {
                "id": detector_id,
                **detector.get_detector_info()
            }
            for detector_id, detector in self.detectors.items()
        ]
        
    async def analyze_transaction(self, transaction_data: Dict[str, Any], 
                                 detector_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Analyze a transaction with specified detectors or all detectors.
        
        Args:
            transaction_data: The transaction data to analyze
            detector_ids: Optional list of detector IDs to use. If None, all are used.
            
        Returns:
            Dictionary with analysis results from all detectors
        """
        results = {}
        
        # Determine which detectors to use
        detectors_to_use = {}
        if detector_ids:
            detectors_to_use = {
                detector_id: self.detectors[detector_id]
                for detector_id in detector_ids
                if detector_id in self.detectors
            }
        else:
            detectors_to_use = self.detectors
            
        # Run all selected detectors
        tasks = []
        for detector_id, detector in detectors_to_use.items():
            if detector.enabled:
                tasks.append(self._analyze_with_detector(detector_id, detector, transaction_data))
                
        # Await all analysis tasks
        detector_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, detector_id in enumerate(detectors_to_use.keys()):
            if isinstance(detector_results[i], Exception):
                results[detector_id] = {
                    "success": False,
                    "error": str(detector_results[i]),
                    "risk_level": "error"
                }
            else:
                results[detector_id] = {
                    "success": True,
                    **detector_results[i]
                }
                
        # Calculate overall risk level
        overall_risk = self._calculate_overall_risk(results)
        
        return {
            "overall_risk": overall_risk,
            "detector_results": results
        }
        
    async def _analyze_with_detector(self, detector_id: str, detector: BaseDetector, 
                                    transaction_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run analysis with a single detector."""
        try:
            result = await detector.analyze(transaction_data)
            logger.debug(f"Detector {detector_id} analysis complete")
            return result
        except Exception as e:
            logger.error(f"Error in detector {detector_id}: {str(e)}")
            raise
            
    def _calculate_overall_risk(self, results: Dict[str, Dict[str, Any]]) -> str:
        """Calculate the overall risk level from all detector results."""
        risk_levels = []
        
        for detector_id, result in results.items():
            if result.get("success", False) and "risk_level" in result:
                risk_levels.append(result["risk_level"])
                
        if not risk_levels:
            return "unknown"
            
        # Risk level hierarchy
        risk_hierarchy = ["safe", "unknown", "low", "medium", "high", "critical", "error"]
        
        # Return the highest risk level found
        highest_risk = "safe"
        highest_index = risk_hierarchy.index("safe")
        
        for level in risk_levels:
            if level in risk_hierarchy:
                level_index = risk_hierarchy.index(level)
                if level_index > highest_index:
                    highest_index = level_index
                    highest_risk = level
                    
        return highest_risk
