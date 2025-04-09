"""
Transaction Analyzer Module.

This module provides a unified interface to run all security detectors on a transaction.
Think of it as the main control center for analyzing blockchain transactions.
"""
import asyncio
import logging
from typing import Dict, Any, List

# Import our detector system
from web3sentry.detectors import get_all_detectors, get_detector

logger = logging.getLogger(__name__)

class TransactionAnalyzer:
    """
    Main transaction analysis coordinator.
    
    This class brings together all our detectors and runs them on each transaction,
    combining the results into a comprehensive security assessment.
    """
    
    def __init__(self, use_all_detectors=True, specific_detectors=None):
        """
        Initialize the transaction analyzer.
        
        Args:
            use_all_detectors (bool): Whether to use all available detectors
            specific_detectors (List[str], optional): List of specific detector names to use
        """
        self.detectors = []
        
        if use_all_detectors:
            # Let's load up all our security detectors!
            logger.info("Loading all available security detectors")
            self.detectors = get_all_detectors()
        elif specific_detectors:
            # Or maybe we just want to use specific ones
            logger.info(f"Loading specific detectors: {', '.join(specific_detectors)}")
            self.detectors = [get_detector(name) for name in specific_detectors]
        
        logger.info(f"Initialized TransactionAnalyzer with {len(self.detectors)} detectors")
    
    async def analyze_transaction(self, transaction_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a transaction using all active detectors.
        
        Args:
            transaction_data: The transaction to analyze
            
        Returns:
            Dict containing aggregated analysis results from all detectors
        """
        if not self.detectors:
            logger.warning("No detectors loaded! Analysis will return empty results.")
            return {"overall_risk": "UNKNOWN", "details": [], "detector_results": {}}
        
        # Let's run all our detectors in parallel - efficiency is key!
        logger.debug(f"Running {len(self.detectors)} detectors on transaction")
        detector_tasks = [
            detector.analyze(transaction_data) 
            for detector in self.detectors 
            if detector.enabled
        ]
        
        # Wait for all detectors to finish their analysis
        results = await asyncio.gather(*detector_tasks)
        
        # Time to figure out the overall risk level based on all detector results
        max_risk = self._calculate_overall_risk([r["risk_level"] for r in results])
        
        # Combine all the details from the detectors
        all_details = []
        for result in results:
            all_details.extend([f"[{result['detector']}] {detail}" for detail in result["details"]])
        
        # Put it all together in a nice report
        return {
            "overall_risk": max_risk,
            "details": all_details,
            "detector_results": {r["detector"]: r for r in results},
            "transaction_id": transaction_data.get("hash", "unknown")
        }
    
    def _calculate_overall_risk(self, risk_levels: List[str]) -> str:
        """
        Calculate the highest risk level from a list of risk levels.
        
        Args:
            risk_levels: List of risk levels from different detectors
            
        Returns:
            The highest risk level found
        """
        # Define the risk hierarchy - HIGH is worse than MEDIUM is worse than LOW
        risk_hierarchy = {
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
            "UNKNOWN": 0
        }
        
        # Find the highest risk level in the list
        max_risk = max(risk_levels, key=lambda r: risk_hierarchy.get(r, 0))
        return max_risk
    
    def get_active_detectors(self) -> List[str]:
        """
        Get a list of all currently active detectors.
        
        Returns:
            List of detector names that are currently enabled
        """
        return [detector.name for detector in self.detectors if detector.enabled]

    def enable_detector(self, detector_name: str) -> bool:
        """
        Enable a specific detector by name.
        
        Args:
            detector_name: Name of the detector to enable
            
        Returns:
            True if detector was found and enabled, False otherwise
        """
        for detector in self.detectors:
            if detector.name.lower() == detector_name.lower():
                detector.enable()
                logger.info(f"Enabled detector: {detector.name}")
                return True
        
        logger.warning(f"Could not find detector named '{detector_name}'")
        return False
    
    def disable_detector(self, detector_name: str) -> bool:
        """
        Disable a specific detector by name.
        
        Args:
            detector_name: Name of the detector to disable
            
        Returns:
            True if detector was found and disabled, False otherwise
        """
        for detector in self.detectors:
            if detector.name.lower() == detector_name.lower():
                detector.disable()
                logger.info(f"Disabled detector: {detector.name}")
                return True
        
        logger.warning(f"Could not find detector named '{detector_name}'")
        return False