#!/usr/bin/env python3
"""
Quick test of the full workflow with a few transactions
"""

from excel_parser import XeroActivityStatementParser
from deepseek_client import DeepSeekClient
from prompts import create_review_prompt

print("=" * 80)
print("TESTING FULL WORKFLOW")
print("=" * 80)

# Parse Excel
print("\n1. Parsing Excel file...")
parser = XeroActivityStatementParser('/Users/noradelsierra/Downloads/Demo Company AU - Activity Statement.xls')
result = parser.parse()
print(f"✓ Parsed {result['total_transactions']} transactions")

# Initialize AI client
print("\n2. Initializing DeepSeek client...")
client = DeepSeekClient()
print("✓ Client ready")

# Test with a few transactions
print("\n3. Reviewing sample transactions with AI...")
test_transactions = result['transactions'][40:43]  # Test 3 expense transactions

for i, transaction in enumerate(test_transactions, 1):
    print(f"\n   Transaction {i}/{len(test_transactions)}:")
    print(f"   Row {transaction['row_number']}: {transaction['description'][:50]}")
    print(f"   Account: {transaction['account']} | Amount: ${transaction['amount']:,.2f}")

    # Create context
    context = {
        'company': result['metadata'].get('company_name'),
        'period': result['metadata'].get('period')
    }

    # Review with AI
    ai_result = client.review_transaction(transaction, context)

    if ai_result['has_issues']:
        print(f"   🟡 Issues found: {', '.join(ai_result['issues'])}")
        print(f"   Comments: {ai_result['comments'][:100]}...")
    else:
        print(f"   ✓ No issues")

print("\n" + "=" * 80)
print("✓ Full workflow test complete!")
print("=" * 80)
print("\nThe tool is ready to use. Run:")
print("  python3 reviewer.py '/Users/noradelsierra/Downloads/Demo Company AU - Activity Statement.xls'")
