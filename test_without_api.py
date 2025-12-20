#!/usr/bin/env python3
"""
Test script to demonstrate the BAS reviewer without requiring DeepSeek API
Shows what data will be sent to the AI for review
"""

from excel_parser import XeroActivityStatementParser
from prompts import create_review_prompt
import json

# Parse the Excel file
print("=" * 80)
print("XERO BAS REVIEWER - TEST MODE (No API calls)")
print("=" * 80)

parser = XeroActivityStatementParser('/Users/noradelsierra/Downloads/Demo Company AU - Activity Statement.xls')
result = parser.parse()

print(f"\nParsing: Demo Company AU - Activity Statement.xls")
print(f"✓ Found {result['total_transactions']} transactions")
print(f"  Company: {result['metadata'].get('company_name')}")
print(f"  Period: {result['metadata'].get('period')}")

summary = parser.get_summary()
print(f"\n  Sales: ${summary['total_sales']:,.2f}")
print(f"  Purchases: ${summary['total_purchases']:,.2f}")
print(f"  GST Collected: ${summary['total_gst_collected']:,.2f}")
print(f"  GST Paid: ${summary['total_gst_paid']:,.2f}")
print(f"  Net GST: ${summary['net_gst']:,.2f}")

print(f"\n{'=' * 80}")
print("SAMPLE TRANSACTION - WHAT GETS SENT TO AI")
print("=" * 80)

# Show a few example transactions and their prompts
sample_transactions = [
    result['transactions'][0],   # First transaction
    result['transactions'][40],  # An expense transaction
    result['transactions'][78]   # Office equipment purchase
]

for i, transaction in enumerate(sample_transactions, 1):
    print(f"\n--- SAMPLE {i} ---")
    print(f"Row {transaction['row_number']}: {transaction['description'][:60]}")
    print(f"Account: {transaction['account']} | Amount: ${transaction['amount']:,.2f}")
    print(f"GST: ${transaction['gst_amount']:,.2f} | Code: {transaction['gst_code']} | BAS Box: {transaction['bas_box']}")

    # Show what prompt will be sent to AI
    context = {
        'company': result['metadata'].get('company_name'),
        'period': result['metadata'].get('period')
    }

    prompt = create_review_prompt(transaction, context)

    print("\nPrompt that will be sent to DeepSeek:")
    print("-" * 80)
    print(prompt[:500] + "..." if len(prompt) > 500 else prompt)
    print()

print("=" * 80)
print("NEXT STEPS")
print("=" * 80)
print("\n1. Add your DeepSeek API key to .env file:")
print("   DEEPSEEK_API_KEY=your_actual_key_here")
print("\n2. Run the full reviewer:")
print("   python reviewer.py '/Users/noradelsierra/Downloads/Demo Company AU - Activity Statement.xls'")
print("\n3. Review the generated Excel report with flagged items")
print()
