"""
Transaction Anomaly Detector Module.

This module detects unusual transaction patterns that might indicate fraud or attacks.
It's like having a financial detective watching blockchain transactions!
"""
from typing import Dict, Any
import logging
from datetime import datetime

# We'll need to import the base detector once we have it in the right location
try:
    from web3sentry.detectors.base_detector import BaseDetector
except ImportError:
    # Fallback for development 
    from detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)

class TransactionAnomalyDetector(BaseDetector):
    """Detector for unusual transaction patterns.
    
    This detector looks for things that seem "off" about transactions:
    - Transactions that are much larger than usual for an address
    - Rapid sequences of transactions
    - Odd hours of operation
    - Unusual gas prices
    """
    
    def __init__(self):
        """Initialize the anomaly detector with baseline stats.
        
        We start with some basic thresholds, but in a real system,
        these would be learned from historical data.
        """
        super().__init__(
            name="Transaction Anomaly Detector",
            description="Identifies unusual transaction patterns that may indicate security risks"
        )
        # Some example thresholds - in real life these would be dynamic!
        self.large_tx_threshold = 5.0  # ETH 
        self.unusual_hour_start = 1    # 1 AM
        self.unusual_hour_end = 4      # 4 AM
        self.transaction_history = {}  # We'd store recent tx history here
        
    async def analyze(self, transaction_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check if this transaction seems fishy compared to normal patterns.
        
        We're looking for several weird things that might mean trouble:
        - Is this way bigger than normal transactions?
        - Is it happening at 3 AM?
        - Is the gas price weird?
        
        Args:
            transaction_data: All the juicy details about the transaction
            
        Returns:
            Our verdict - how suspicious this transaction looks
        """
        # Start with the benefit of the doubt
        risk_level = "LOW"
        details = []
        
        # Convert value from wei to ETH
        value = int(transaction_data.get("value", "0"), 16) / 1e18
        
        # Check for unusually large transactions
        if value > self.large_tx_threshold:
            risk_level = "MEDIUM"
            details.append(f"Unusually large transaction value: {value} ETH - this is bigger than normal!")
            
        # Check if transaction is occurring during "odd hours"
        current_hour = datetime.now().hour
        if self.unusual_hour_start <= current_hour <= self.unusual_hour_end:
            # Bump up the risk if it's already suspicious, otherwise mark as potentially suspicious
            risk_level = "HIGH" if risk_level != "LOW" else "MEDIUM"
            details.append(f"Transaction at unusual hour ({current_hour}:00) - most legit transactions don't happen at this time")
        
        # Check for unusual gas price (simplified example)
        gas_price = int(transaction_data.get("gasPrice", "0"), 16) / 1e9  # Convert to Gwei
        if gas_price > 500:  # Arbitrarily high gas price example
            details.append(f"Unusually high gas price: {gas_price} Gwei - might be trying to rush something through!")
            risk_level = "MEDIUM" if risk_level == "LOW" else risk_level
            
        # In a real system, we'd also look at:
        # - Frequency of transactions from this address
        # - Typical transaction patterns for this address
        # - Network-wide anomaly detection
            
        return {
            "risk_level": risk_level,
            "details": details,
            "detector": self.name,
        }
    
    def get_detector_info(self) -> Dict[str, Any]:
        """Return info about this detector for configuration panels.
        
        This helps the UI show what this detector is looking for.
        """
        info = super().get_detector_info()
        info.update({
            "thresholds": {
                "large_transaction": f"{self.large_tx_threshold} ETH",
                "unusual_hours": f"{self.unusual_hour_start}:00 - {self.unusual_hour_end}:00"
            }
        })
        return info