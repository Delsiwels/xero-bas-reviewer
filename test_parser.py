#!/usr/bin/env python3
"""Test the Excel parser"""

from excel_parser import XeroActivityStatementParser

# Test the parser
parser = XeroActivityStatementParser('/Users/noradelsierra/Downloads/Demo Company AU - Activity Statement.xls')
result = parser.parse()

print('=== PARSING TEST ===')
print(f'Company: {result["metadata"].get("company_name")}')
print(f'Period: {result["metadata"].get("period")}')
print(f'Total transactions: {result["total_transactions"]}')
print()

# Show first 5 transactions
print('=== FIRST 5 TRANSACTIONS ===')
for i, t in enumerate(result['transactions'][:5]):
    print(f'{i+1}. Row {t["row_number"]}: {t["date"]} | {t["description"][:40]}')
    print(f'   Account: {t["account"]} | Type: {t["type"]}')
    print(f'   Amount: ${t["amount"]:,.2f} | GST: ${t["gst_amount"]:,.2f} | Code: {t["gst_code"]} | BAS: {t["bas_box"]}')
    print()

# Show summary
summary = parser.get_summary()
print('=== SUMMARY ===')
print(f'Total Sales: ${summary["total_sales"]:,.2f}')
print(f'Total Purchases: ${summary["total_purchases"]:,.2f}')
print(f'GST Collected: ${summary["total_gst_collected"]:,.2f}')
print(f'GST Paid: ${summary["total_gst_paid"]:,.2f}')
print(f'Net GST: ${summary["net_gst"]:,.2f}')
