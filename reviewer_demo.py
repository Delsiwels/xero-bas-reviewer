"""
Demo BAS reviewer - processes first 20 transactions only
"""
import os
import sys
from excel_parser import XeroActivityStatementParser
from deepseek_client import DeepSeekClient
from output_generator import OutputGenerator
from datetime import datetime

print("=" * 80, flush=True)
print("XERO BAS REVIEWER - DEMO (First 20 transactions only)", flush=True)
print("=" * 80, flush=True)

excel_file = "/Users/noradelsierra/Downloads/Demo Company AU - Activity Statement.xls"

print(f"\nParsing Excel file: {excel_file}", flush=True)

# Parse the Excel file
parser = XeroActivityStatementParser(excel_file)
parsed_data = parser.parse()

print(f"✓ Found {parsed_data['total_transactions']} transactions", flush=True)
print(f"  Company: {parsed_data['metadata'].get('company_name', 'Unknown')}", flush=True)
print(f"  Period: {parsed_data['metadata'].get('period', 'Unknown')}", flush=True)

# Get summary
summary = parser.get_summary()
print(f"\n  Sales: ${summary['total_sales']:,.2f}", flush=True)
print(f"  Purchases: ${summary['total_purchases']:,.2f}", flush=True)
print(f"  GST Collected: ${summary['total_gst_collected']:,.2f}", flush=True)
print(f"  GST Paid: ${summary['total_gst_paid']:,.2f}", flush=True)
print(f"  Net GST: ${summary['net_gst']:,.2f}", flush=True)

print(f"\n{'=' * 80}", flush=True)
print("REVIEWING FIRST 20 TRANSACTIONS WITH AI", flush=True)
print("=" * 80, flush=True)

# Initialize AI client
ai_client = DeepSeekClient()

# Process only first 20 transactions
transactions = parsed_data['transactions'][:20]
flagged_items = []

for i, transaction in enumerate(transactions, 1):
    print(f"\nTransaction {i}/20: Row {transaction['row_number']} - {transaction['description'][:40]}", flush=True)

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
        print(f"  {icon} {result['severity'].upper()}: {', '.join(result['issues'])}", flush=True)
        print(f"  Comment: {result['comments'][:80]}...", flush=True)
        flagged_items.append(result)
    else:
        print(f"  ✓ No issues", flush=True)

print(f"\n{'=' * 80}", flush=True)
print("REVIEW COMPLETE", flush=True)
print("=" * 80, flush=True)
print(f"\nTransactions reviewed: {len(transactions)}", flush=True)
print(f"Flagged items: {len(flagged_items)}", flush=True)

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

print(f"\n✓ Review report saved to: {output_file}", flush=True)
print("\nDone!", flush=True)
