"""
Approvals Custom Detector.

This detector identifies malicious, risky, or deceptive approvals that could
give attackers access to user assets in the Web3lancer platform.
"""
from typing import Dict, Any, List, Optional
import re
import logging
from web3sentry.detectors.base_detector import BaseDetector
from web3sentry.utils.risk_utils import get_risk_level_priority

logger = logging.getLogger(__name__)

class ApprovalsDetector(BaseDetector):
    """Detector for malicious token approvals and permissions."""
    
    def __init__(self):
        """Initialize the Approvals detector."""
        super().__init__(
            name="Approvals Security Detector",
            description="Detects malicious or risky approvals in blockchain transactions"
        )
        self.known_malicious_contracts = set()  # Would be populated from a database
        self.known_safe_contracts = set()  # Known trusted contracts 
        self.approval_history = {}  # Track user approval patterns
        
        # Detector configuration thresholds
        self.config = {
            "unlimited_approval_alert": True,  # Alert on unlimited token approvals
            "high_amount_threshold_percentage": 80,  # Alert if approval is >80% of holdings
            "max_recommended_approval_amount": "115792089237316195423570985008687907853269984665640564039457"  # max uint256
        }
    
    async def analyze(self, transaction_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze approval transactions for security issues.
        
        Args:
            transaction_data: Dictionary with transaction details.
            
        Returns:
            Analysis results with risk assessment.
        """
        if not self.enabled:
            return {"risk_level": "unknown", "details": "Detector disabled"}
        
        try:
            # Extract transaction data
            tx_type = transaction_data.get("type", "")
            from_address = transaction_data.get("from", "")
            to_address = transaction_data.get("to", "")
            user_id = transaction_data.get("user_id", "")
            approval_amount = transaction_data.get("amount", "0")
            token_address = transaction_data.get("token_address", "")
            token_balance = transaction_data.get("token_balance", "0")
            method_id = transaction_data.get("method_id", "")
            
            # Check if this is an approval transaction
            is_approval = self._is_approval_transaction(tx_type, method_id)
            if not is_approval:
                return {
                    "risk_level": "safe", 
                    "details": "Not an approval transaction",
                    "triggers": []
                }
            
            results = {
                "risk_level": "safe",
                "details": "No issues detected with this approval",
                "triggers": []
            }
            
            # Check if target contract is known malicious
            if to_address in self.known_malicious_contracts:
                results["risk_level"] = "critical"
                results["triggers"].append({
                    "type": "malicious_contract",
                    "description": "Approval requested by a known malicious contract",
                    "contract": to_address
                })
            
            # Check for unlimited approvals
            if self._is_unlimited_approval(approval_amount):
                results["risk_level"] = "high" if results["risk_level"] == "safe" else results["risk_level"]
                results["triggers"].append({
                    "type": "unlimited_approval",
                    "description": "Transaction grants unlimited approval for your tokens",
                    "recommendation": "Consider setting a specific approval limit"
                })
            
            # Check if approval amount is high relative to holdings
            risk_level = self._check_approval_amount_risk(approval_amount, token_balance)
            if risk_level != "safe":
                current_level_priority = self._get_risk_level_priority(results["risk_level"])
                new_level_priority = self._get_risk_level_priority(risk_level)
                
                if new_level_priority > current_level_priority:
                    results["risk_level"] = risk_level
                
                results["triggers"].append({
                    "type": "high_approval_amount",
                    "description": f"Approval amount is high relative to your balance ({self._calculate_percentage(approval_amount, token_balance)}%)",
                    "recommendation": "Consider approving a smaller amount"
                })
            
            # Check for unusual approval patterns
            unusual_pattern = self._detect_unusual_approval_pattern(user_id, to_address, token_address)
            if unusual_pattern:
                results["risk_level"] = "medium" if results["risk_level"] == "safe" else results["risk_level"]
                results["triggers"].append({
                    "type": "unusual_pattern",
                    "description": "This approval doesn't match your usual patterns",
                    "details": unusual_pattern
                })
            
            # Update approval history for this user
            self._update_approval_history(user_id, to_address, token_address, approval_amount)
            
            return results
            
        except Exception as e:
            logger.error(f"Error in ApprovalsDetector analysis: {str(e)}")
            return {
                "risk_level": "error",
                "details": f"Analysis error: {str(e)}",
                "triggers": []
            }
    
    def _is_approval_transaction(self, tx_type, method_id):
        """Determine if the transaction is an approval."""
        # ERC20 approve method ID
        if method_id == "0x095ea7b3":
            return True
            
        # Check transaction type if available
        if tx_type and "approval" in tx_type.lower():
            return True
            
        return False
    
    def _is_unlimited_approval(self, amount):
        """Check if the approval amount is unlimited or extremely large."""
        if not amount or amount == "0":
            return False
            
        # Check if approval is unlimited (max uint256 or similar)
        max_amount = self.config["max_recommended_approval_amount"]
        try:
            # Convert to integers for comparison
            amount_int = int(amount)
            max_amount_int = int(max_amount)
            
            return amount_int >= max_amount_int * 0.9  # 90% of max uint256 is considered unlimited
        except (ValueError, TypeError):
            return False
    
    def _check_approval_amount_risk(self, amount, balance):
        """Determine risk based on approval amount vs. balance."""
        if not amount or not balance or balance == "0":
            return "safe"
            
        try:
            amount_int = int(amount)
            balance_int = int(balance)
            
            if balance_int == 0:
                return "medium"  # Approving tokens you don't have
                
            percentage = (amount_int / balance_int) * 100
            
            if percentage >= 100:
                return "high"
            elif percentage >= self.config["high_amount_threshold_percentage"]:
                return "medium"
            else:
                return "safe"
                
        except (ValueError, TypeError, ZeroDivisionError):
            return "unknown"
    
    def _calculate_percentage(self, amount, balance):
        """Calculate approval amount as percentage of balance."""
        try:
            amount_int = int(amount)
            balance_int = int(balance)
            
            if balance_int == 0:
                return 0
                
            return round((amount_int / balance_int) * 100, 2)
            
        except (ValueError, TypeError, ZeroDivisionError):
            return 0
    
    def _detect_unusual_approval_pattern(self, user_id, to_address, token_address):
        """Detect if this approval pattern is unusual for the user."""
        if not user_id in self.approval_history:
            return {"reason": "first_approval"}
            
        user_history = self.approval_history[user_id]
        
        # Check if user has approved this contract before
        if to_address not in user_history.get("approved_contracts", set()):
            return {
                "reason": "new_approval_target",
                "details": "You haven't interacted with this contract before"
            }
            
        # Could implement more sophisticated pattern detection here
        return None
    
    def _update_approval_history(self, user_id, to_address, token_address, amount):
        """Update approval history for a user."""
        if user_id not in self.approval_history:
            self.approval_history[user_id] = {
                "approved_contracts": set(),
                "approved_tokens": set(),
                "approval_count": 0
            }
        
        history = self.approval_history[user_id]
        history["approved_contracts"].add(to_address)
        history["approved_tokens"].add(token_address)
        history["approval_count"] += 1
    
    def _get_risk_level_priority(self, risk_level):
        """Get numerical priority for risk level for comparison."""
        # Using the shared utility function instead of duplicating the risk level mapping
        return get_risk_level_priority(risk_level)
    
    def get_detector_info(self) -> Dict[str, Any]:
        """Return detector metadata."""
        base_info = super().get_detector_info()
        base_info.update({
            "category": "approvals",
            "users_monitored": len(self.approval_history),
            "configuration": self.config,
            "malicious_contracts_count": len(self.known_malicious_contracts)
        })
        return base_info
    
    def add_malicious_contract(self, address):
        """Add a contract to the known malicious list."""
        self.known_malicious_contracts.add(address)
        
    def add_safe_contract(self, address):
        """Add a contract to the known safe list."""
        self.known_safe_contracts.add(address)
