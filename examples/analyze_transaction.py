#!/usr/bin/env python
"""
Transaction Analysis Example Script

This example shows how to use the Web3Sentry transaction analyzer to detect
potential security risks in Ethereum transactions.
"""
import asyncio
import json
import logging
import sys

# Add the project to path for this example
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from web3sentry.analyzer import TransactionAnalyzer

# Set up logging - always good to see what's happening!
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Example Ethereum transaction from mainnet
# Let's analyze a real transaction to see if it's suspicious
EXAMPLE_TRANSACTION = {
    "hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    "from": "0xaaaabbbbccccddddeeeeffffgggghhhhiiiijjjj",
    "to": "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",  # Uniswap router address as example
    "value": "0xde0b6b3a7640000",  # 1 ETH in hex
    "gasPrice": "0x3b9aca00",      # 1 Gwei
    "input": "0xa9059cbb000000000000000000000000e592427a0aece92de3edee1f18e0157c05861564000000000000000000000000000000000000000000000000000000000000012c"  # ERC20 transfer function signature
}

async def main():
    """Run a sample transaction analysis."""
    logger.info("Starting Web3Sentry transaction analysis example")
    
    # Create our analyzer with all available detectors
    # In a real app, you might want to customize which detectors to use
    analyzer = TransactionAnalyzer(use_all_detectors=True)
    
    logger.info(f"Loaded detectors: {', '.join(analyzer.get_active_detectors())}")
    
    # Let's analyze our example transaction!
    logger.info(f"Analyzing transaction: {EXAMPLE_TRANSACTION['hash']}")
    results = await analyzer.analyze_transaction(EXAMPLE_TRANSACTION)
    
    # Print the results in a pretty format
    print("\n" + "="*50)
    print("TRANSACTION ANALYSIS RESULTS")
    print("="*50)
    print(f"Transaction: {EXAMPLE_TRANSACTION['hash']}")
    print(f"From: {EXAMPLE_TRANSACTION['from']}")
    print(f"To: {EXAMPLE_TRANSACTION['to']}")
    print(f"Value: {int(EXAMPLE_TRANSACTION['value'], 16) / 1e18} ETH")
    print("-"*50)
    print(f"Overall Risk Level: {results['overall_risk']}")
    print("-"*50)
    print("Details:")
    
    # If we have details to show, print them nicely
    if results['details']:
        for detail in results['details']:
            print(f"  • {detail}")
    else:
        print("  No issues detected")
    
    print("="*50)
    print("\nDetector breakdown:")
    
    # Show individual detector results
    for detector_name, result in results['detector_results'].items():
        print(f"\n{detector_name}:")
        print(f"  Risk Level: {result['risk_level']}")
        if result['details']:
            for detail in result['details']:
                print(f"  • {detail}")
        else:
            print("  No issues detected")
    
    logger.info("Analysis complete!")

if __name__ == "__main__":
    # Run our async function
    asyncio.run(main())