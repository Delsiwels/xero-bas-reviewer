"""
Quick BAS review - first 5 transactions only, generates report immediately
"""
import os
from excel_parser import XeroActivityStatementParser
from deepseek_client import DeepSeekClient
from output_generator import OutputGenerator
from datetime import datetime

print("=" * 80)
print("XERO BAS REVIEWER - QUICK DEMO (First 5 transactions)")
print("=" * 80)

excel_file = "/Users/noradelsierra/Downloads/Demo Company AU - Activity Statement.xls"

print(f"\nParsing Excel file...")

# Parse the Excel file
parser = XeroActivityStatementParser(excel_file)
parsed_data = parser.parse()

print(f"✓ Found {parsed_data['total_transactions']} transactions")

# Get summary
summary = parser.get_summary()

print(f"\n{'=' * 80}")
print("REVIEWING FIRST 5 TRANSACTIONS WITH AI")
print("=" * 80)

# Initialize AI client
ai_client = DeepSeekClient()

# Process only first 5 transactions
transactions = parsed_data['transactions'][:5]
flagged_items = []

for i, transaction in enumerate(transactions, 1):
    print(f"\nTransaction {i}/5: Row {transaction['row_number']} - {transaction['description'][:50]}")

    # Build context
    context = {
        'company': parsed_data['metadata'].get('company_name', ''),
        'period': parsed_data['metadata'].get('period', ''),
    }

    # Review with AI
    result = ai_client.review_transaction(transaction, context)

    if result['has_issues']:
        severity_icons = {'high': '🔴', 'medium': '🟡', 'low': '🟢', 'info': 'ℹ️'}
        icon = severity_icons.get(result['severity'], '❓')
        print(f"  {icon} {result['severity'].upper()}")
        flagged_items.append(result)
    else:
        print(f"  ✓ No issues")

print(f"\n{'=' * 80}")
print("GENERATING REPORT")
print("=" * 80)
print(f"\nTransactions reviewed: {len(transactions)}")
print(f"Flagged items: {len(flagged_items)}")

# Generate report
results = {
    'metadata': parsed_data['metadata'],
    'summary': summary,
    'total_reviewed': len(transactions),
    'flagged_count': len(flagged_items),
    'flagged_items': flagged_items,
    'review_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
}

output_gen = OutputGenerator(results, excel_file)
output_file = output_gen.generate_excel_report()

print(f"\n✓ Review report saved to: {output_file}")
print(f"\nFull path: /Users/noradelsierra/xero-bas-reviewer/{output_file}")
print("\nDone!")
