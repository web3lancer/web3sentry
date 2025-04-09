"""
Multisig Protection Custom Detector.

This detector enhances                 risk_level = "HIGH"
                results["triggers"].append({
                    "type": "unusual_signers",
                    "description": "Detected unusual signers that don't match historical patterns",
                    "signers": unusual_signers
                })
            
            # Check for time-based anomalies
            time_anomalies = self._detect_time_anomalies(signature_timestamps)
            if time_anomalies:
                # Only update risk level if the new one is higher priority
                new_risk = "MEDIUM"
                if get_risk_level_priority(new_risk) > get_risk_level_priority(results["risk_level"]):
                    results["risk_level"] = new_riskr multisig wallets by detecting:
- Unusual signing patterns
- Unauthorized signing attempts
- Quorum manipulation attacks
- Time-based anomalies in signatures
"""
import time
from typing import Dict, Any, List, Optional
from datetime import datetime
import json
import logging
from web3sentry.detectors.base_detector import BaseDetector
from web3sentry.utils.risk_utils import get_risk_level_priority

logger = logging.getLogger(__name__)

class MultisigDetector(BaseDetector):
    """Multisig Protection Custom Detector for Web3lancer platform."""
    
    def __init__(self):
        """Initialize the Multisig detector."""
        super().__init__(
            name="Multisig Protection Detector",
            description="Detects security threats in multisig wallet operations"
        )
        self.signature_history = {}  # Store signature patterns
        self.threshold_config = {
            "time_anomaly_threshold_seconds": 300,  # 5 minutes
            "unusual_signer_threshold": 0.8,  # 80% confidence for unusual signer
            "quorum_bypass_threshold": 0.9  # 90% confidence for quorum bypass attempt
        }
    
    async def analyze(self, transaction_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze multisig transaction for security issues.
        
        Args:
            transaction_data: Dictionary with multisig transaction details.
            
        Returns:
            Analysis results with risk assessment.
        """
        if not self.enabled:
            return {"risk_level": "unknown", "details": "Detector disabled"}
        
        try:
            # Extract relevant transaction data
            wallet_address = transaction_data.get("wallet_address")
            signers = transaction_data.get("signers", [])
            required_signatures = transaction_data.get("required_signatures", 0)
            provided_signatures = transaction_data.get("provided_signatures", [])
            signature_timestamps = transaction_data.get("signature_timestamps", [])
            
            results = {
                "risk_level": "safe",
                "details": "No security issues detected",
                "triggers": []
            }
            
            # Check for unusual signing patterns
            unusual_signers = self._detect_unusual_signers(wallet_address, signers, provided_signatures)
            if unusual_signers:
                results["risk_level"] = "high"
                results["triggers"].append({
                    "type": "unusual_signers",
                    "description": "Detected unusual signers that don't match historical patterns",
                    "signers": unusual_signers
                })
            
            # Check for time-based anomalies
            time_anomalies = self._detect_time_anomalies(signature_timestamps)
            if time_anomalies:
                results["risk_level"] = "medium" if results["risk_level"] == "safe" else results["risk_level"]
                results["triggers"].append({
                    "type": "time_anomalies",
                    "description": "Detected suspicious timing in signature submissions",
                    "details": time_anomalies
                })
            
            # Check for quorum manipulation
            if self._detect_quorum_manipulation(required_signatures, provided_signatures):
                results["risk_level"] = "critical"
                results["triggers"].append({
                    "type": "quorum_manipulation",
                    "description": "Possible attempt to bypass signature requirements"
                })
            
            # Update history with this transaction
            self._update_signature_history(wallet_address, signers, provided_signatures)
            
            return results
            
        except Exception as e:
            logger.error(f"Error in MultisigDetector analysis: {str(e)}")
            return {
                "risk_level": "error",
                "details": f"Analysis error: {str(e)}",
                "triggers": []
            }
    
    def _detect_unusual_signers(self, wallet_address, current_signers, provided_signatures):
        """Detect if the current signers differ significantly from historical patterns."""
        if not wallet_address in self.signature_history:
            return []  # No history to compare against
            
        historical_signers = self.signature_history[wallet_address].get("common_signers", [])
        unusual_signers = []
        
        for signer in provided_signatures:
            if signer not in historical_signers and signer in current_signers:
                unusual_signers.append(signer)
                
        return unusual_signers
    
    def _detect_time_anomalies(self, timestamps):
        """Detect suspicious timing patterns in signature submissions."""
        if not timestamps or len(timestamps) < 2:
            return []
            
        anomalies = []
        sorted_timestamps = sorted(timestamps)
        
        for i in range(1, len(sorted_timestamps)):
            time_diff = sorted_timestamps[i] - sorted_timestamps[i-1]
            
            # Check for signatures that are too close together (possibly automated)
            if time_diff < 1:  # Less than 1 second apart
                anomalies.append({
                    "type": "signatures_too_close",
                    "timestamps": [sorted_timestamps[i-1], sorted_timestamps[i]],
                    "difference_seconds": time_diff
                })
                
            # Check for signatures that happened much faster than the threshold
            elif time_diff < self.threshold_config["time_anomaly_threshold_seconds"]:
                anomalies.append({
                    "type": "accelerated_signatures",
                    "timestamps": [sorted_timestamps[i-1], sorted_timestamps[i]],
                    "difference_seconds": time_diff
                })
                
        return anomalies
    
    def _detect_quorum_manipulation(self, required_signatures, provided_signatures):
        """Detect attempts to manipulate quorum requirements."""
        # Check if there's evidence of attempted quorum bypass
        if len(provided_signatures) < required_signatures:
            return True
            
        # More sophisticated checks could be implemented here
        return False
    
    def _update_signature_history(self, wallet_address, signers, provided_signatures):
        """Update the signature history for a wallet."""
        if wallet_address not in self.signature_history:
            self.signature_history[wallet_address] = {
                "transaction_count": 0,
                "common_signers": set(),
                "all_signers": set(signers),
                "last_update": time.time()
            }
        
        history = self.signature_history[wallet_address]
        history["transaction_count"] += 1
        
        # Update common signers (signers who frequently sign)
        for signer in provided_signatures:
            history["common_signers"].add(signer)
            
        history["all_signers"].update(signers)
        history["last_update"] = time.time()
    
    def get_detector_info(self) -> Dict[str, Any]:
        """Return detector metadata."""
        base_info = super().get_detector_info()
        base_info.update({
            "category": "multisig",
            "wallets_monitored": len(self.signature_history),
            "configuration": self.threshold_config
        })
        return base_info
