"""
Web3Sentry Detectors Package.

This package contains all the security detectors used by Web3Sentry to analyze transactions.
Each detector specializes in identifying specific types of risks or suspicious behavior.
"""

from web3sentry.detectors.base_detector import BaseDetector
from web3sentry.detectors.transaction_anomaly_detector import TransactionAnomalyDetector
from web3sentry.detectors.contract_vulnerability_detector import ContractVulnerabilityDetector

# Dictionary of all available detectors for easy access
AVAILABLE_DETECTORS = {
    "transaction_anomaly": TransactionAnomalyDetector,
    "contract_vulnerability": ContractVulnerabilityDetector,
    # Add more detectors here as they are implemented
}

def get_all_detectors():
    """
    Create and return instances of all available detectors.
    
    Returns:
        list: List of instantiated detector objects ready to use
    """
    # Fire up an instance of each detector - makes it easy to use them all at once
    return [detector_class() for detector_class in AVAILABLE_DETECTORS.values()]

def get_detector(detector_name):
    """
    Get a specific detector by name.
    
    Args:
        detector_name (str): Name of the detector to retrieve
        
    Returns:
        BaseDetector: An instance of the requested detector
    
    Raises:
        KeyError: If the detector name isn't recognized
    """
    if detector_name not in AVAILABLE_DETECTORS:
        raise KeyError(f"Detector '{detector_name}' not found. Available detectors: {', '.join(AVAILABLE_DETECTORS.keys())}")
    
    # Create a fresh instance of the requested detector
    return AVAILABLE_DETECTORS[detector_name]()

__all__ = [
    'BaseDetector', 
    'TransactionAnomalyDetector', 
    'ContractVulnerabilityDetector',
    'get_all_detectors',
    'get_detector',
    'AVAILABLE_DETECTORS'
]