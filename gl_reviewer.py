"""
General Ledger Reviewer - More accurate BAS review
"""
import os
import sys
from gl_parser import GeneralLedgerParser
from deepseek_client import DeepSeekClient
from output_generator import OutputGenerator
from datetime import datetime


def review_general_ledger(excel_file: str, max_transactions: int = None):
    """
    Review General Ledger transactions

    Args:
        excel_file: Path to General Ledger Excel file
        max_transactions: Optional limit on number of transactions to review
    """
    print("=" * 80)
    print("XERO GENERAL LEDGER REVIEWER")
    print("=" * 80)
    print(f"\nParsing Excel file: {excel_file}")

    # Parse the Excel file
    parser = GeneralLedgerParser(excel_file)
    parsed_data = parser.parse()

    print(f"✓ Found {parsed_data['total_transactions']} transactions")
    print(f"  Company: {parsed_data['metadata'].get('company_name', 'Unknown')}")
    print(f"  Period: {parsed_data['metadata'].get('period', 'Unknown')}")

    # Get summary
    summary = parser.get_summary()
    print(f"\n  Income: ${summary['total_income']:,.2f}")
    print(f"  Expenses: ${summary['total_expenses']:,.2f}")
    print(f"  GST Collected: ${summary['total_gst_collected']:,.2f}")
    print(f"  GST Paid: ${summary['total_gst_paid']:,.2f}")
    print(f"  Net GST: ${summary['net_gst']:,.2f}")

    if summary['gst_calculation_errors'] > 0:
        print(f"\n  ⚠️  Pre-check: {summary['gst_calculation_errors']} transactions with GST calculation errors")

    print(f"\n{'=' * 80}")
    print("REVIEWING TRANSACTIONS WITH AI")
    print("=" * 80)

    # Initialize AI client
    ai_client = DeepSeekClient()

    # Determine which transactions to review
    transactions = parsed_data['transactions']
    if max_transactions:
        transactions = transactions[:max_transactions]
        print(f"\nReviewing first {max_transactions} of {parsed_data['total_transactions']} transactions")
    else:
        print(f"\nReviewing all {len(transactions)} transactions")

    flagged_items = []

    for i, transaction in enumerate(transactions, 1):
        print(f"\nTransaction {i}/{len(transactions)}: Row {transaction['row_number']} - {transaction['description'][:50]}")

        # Build context
        context = {
            'company': parsed_data['metadata'].get('company_name', ''),
            'period': parsed_data['metadata'].get('period', ''),
        }

        # Import prompt function
        from gl_prompts import create_gl_review_prompt

        # Create prompt
        prompt = create_gl_review_prompt(transaction, context)

        # Call AI
        messages = [
            {
                'role': 'system',
                'content': 'You are an expert Australian tax accountant conducting a thorough BAS review. Be CRITICAL and flag account coding errors and incorrect GST treatment. Question transactions marked BAS Excluded or GST Free for normal business items.'
            },
            {
                'role': 'user',
                'content': prompt
            }
        ]

        response = ai_client.chat_completion(messages)

        if response:
            # Check if transaction was flagged
            response_lower = response.lower()
            has_issues = not ('ok -' in response_lower or 'appears correct' in response_lower or 'no issues' in response_lower)

            if has_issues:
                severity_icons = {'high': '🔴', 'medium': '🟡', 'low': '🟢', 'info': 'ℹ️'}

                # Determine severity
                if any(word in response_lower for word in ['critical', 'must', 'incorrect', 'error']):
                    severity = 'high'
                elif any(word in response_lower for word in ['should', 'review', 'check', 'unusual']):
                    severity = 'medium'
                else:
                    severity = 'low'

                icon = severity_icons.get(severity, '❓')
                print(f"  {icon} {severity.upper()}")

                flagged_items.append({
                    'row_number': transaction['row_number'],
                    'date': transaction['date'],
                    'account': f"{transaction['account_code']} - {transaction['account']}",
                    'description': transaction['description'],
                    'gross': transaction['gross'],
                    'gst': transaction['gst'],
                    'net': transaction['net'],
                    'gst_rate_name': transaction['gst_rate_name'],
                    'severity': severity,
                    'comments': response,
                    'has_issues': True
                })
            else:
                print(f"  ✓ No issues")

    print(f"\n{'=' * 80}")
    print("REVIEW COMPLETE")
    print("=" * 80)
    print(f"\nTotal transactions reviewed: {len(transactions)}")
    print(f"Flagged items: {len(flagged_items)}")

    if len(flagged_items) > 0:
        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        for item in flagged_items:
            severity_counts[item['severity']] = severity_counts.get(item['severity'], 0) + 1

        print(f"\nSeverity breakdown:")
        for severity, count in severity_counts.items():
            if count > 0:
                icons = {'high': '🔴', 'medium': '🟡', 'low': '🟢'}
                print(f"  {icons[severity]} {severity.upper()}: {count}")

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
    print("\nDone!")

    return output_file


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python gl_reviewer.py <excel_file> [max_transactions]")
        print("\nExample:")
        print("  python gl_reviewer.py 'General_Ledger.xlsx'")
        print("  python gl_reviewer.py 'General_Ledger.xlsx' 10")
        sys.exit(1)

    excel_file = sys.argv[1]
    max_trans = int(sys.argv[2]) if len(sys.argv) > 2 else None

    if not os.path.exists(excel_file):
        print(f"Error: File not found: {excel_file}")
        sys.exit(1)

    review_general_ledger(excel_file, max_trans)


if __name__ == '__main__':
    main()
