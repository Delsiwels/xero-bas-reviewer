"""
Main BAS reviewer engine
"""
import os
from typing import List, Dict, Any
from excel_parser import XeroActivityStatementParser
from deepseek_client import DeepSeekClient
from datetime import datetime


class BASReviewer:
    """Main engine for reviewing BAS transactions"""

    def __init__(self, excel_file: str):
        self.excel_file = excel_file
        self.parser = XeroActivityStatementParser(excel_file)
        self.ai_client = DeepSeekClient()
        self.parsed_data = None
        self.flagged_items = []
        self.review_summary = {}

    def review(self, batch_size: int = 10) -> Dict[str, Any]:
        """
        Run the complete review process

        Args:
            batch_size: Number of transactions to review in each batch

        Returns:
            Dictionary containing review results
        """
        print("=" * 80)
        print("XERO BAS REVIEWER")
        print("=" * 80)
        print(f"\nParsing Excel file: {self.excel_file}")

        # Parse the Excel file
        self.parsed_data = self.parser.parse()

        print(f"✓ Found {self.parsed_data['total_transactions']} transactions")
        print(f"  Company: {self.parsed_data['metadata'].get('company_name', 'Unknown')}")
        print(f"  Period: {self.parsed_data['metadata'].get('period', 'Unknown')}")

        # Get summary
        summary = self.parser.get_summary()
        print(f"\n  Sales: ${summary['total_sales']:,.2f}")
        print(f"  Purchases: ${summary['total_purchases']:,.2f}")
        print(f"  GST Collected: ${summary['total_gst_collected']:,.2f}")
        print(f"  GST Paid: ${summary['total_gst_paid']:,.2f}")
        print(f"  Net GST: ${summary['net_gst']:,.2f}")

        print(f"\n{'=' * 80}")
        print("REVIEWING TRANSACTIONS WITH AI")
        print("=" * 80)

        transactions = self.parsed_data['transactions']

        # Process transactions in batches for efficiency
        for i in range(0, len(transactions), batch_size):
            batch = transactions[i:i + batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = (len(transactions) + batch_size - 1) // batch_size

            print(f"\nBatch {batch_num}/{total_batches} (Transactions {i+1}-{min(i+batch_size, len(transactions))})")

            for transaction in batch:
                result = self._review_transaction(transaction)

                if result['has_issues']:
                    self.flagged_items.append(result)
                    severity_icon = self._get_severity_icon(result['severity'])
                    print(f"  {severity_icon} Row {transaction['row_number']}: {transaction['description'][:50]}")

        print(f"\n{'=' * 80}")
        print("REVIEW COMPLETE")
        print("=" * 80)
        print(f"\nTotal transactions reviewed: {len(transactions)}")
        print(f"Flagged items: {len(self.flagged_items)}")

        if len(self.flagged_items) > 0:
            print(f"\nSeverity breakdown:")
            severity_counts = self._count_by_severity()
            for severity, count in severity_counts.items():
                icon = self._get_severity_icon(severity)
                print(f"  {icon} {severity.upper()}: {count}")

        return {
            'metadata': self.parsed_data['metadata'],
            'summary': summary,
            'total_reviewed': len(transactions),
            'flagged_count': len(self.flagged_items),
            'flagged_items': self.flagged_items,
            'review_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

    def _review_transaction(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Review a single transaction using AI"""

        # Build context for the AI
        context = {
            'company': self.parsed_data['metadata'].get('company_name', ''),
            'period': self.parsed_data['metadata'].get('period', ''),
        }

        # Pre-check: Skip review if GST is correct and account coding seems OK
        # This reduces false positives

        # Call AI to review
        result = self.ai_client.review_transaction(transaction, context)

        # Add transaction details to result
        result['row_number'] = transaction['row_number']
        result['date'] = transaction['date']
        result['account'] = transaction['account']
        result['description'] = transaction['description']
        result['amount'] = transaction['amount']
        result['gst_amount'] = transaction['gst_amount']
        result['net_amount'] = transaction['net_amount']
        result['gst_code'] = transaction['gst_code']

        return result

    def _count_by_severity(self) -> Dict[str, int]:
        """Count flagged items by severity"""
        counts = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}

        for item in self.flagged_items:
            severity = item.get('severity', 'info')
            counts[severity] = counts.get(severity, 0) + 1

        return counts

    def _get_severity_icon(self, severity: str) -> str:
        """Get icon for severity level"""
        icons = {
            'high': '🔴',
            'medium': '🟡',
            'low': '🟢',
            'info': 'ℹ️',
            'error': '❌'
        }
        return icons.get(severity, '❓')


def main():
    """Main entry point for command-line usage"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python reviewer.py <excel_file>")
        print("\nExample:")
        print("  python reviewer.py 'Activity Statement.xls'")
        sys.exit(1)

    excel_file = sys.argv[1]

    if not os.path.exists(excel_file):
        print(f"Error: File not found: {excel_file}")
        sys.exit(1)

    # Create reviewer and run
    reviewer = BASReviewer(excel_file)
    results = reviewer.review()

    # Generate output report
    from output_generator import OutputGenerator

    output_gen = OutputGenerator(results, excel_file)
    output_file = output_gen.generate_excel_report()

    print(f"\n✓ Review report saved to: {output_file}")
    print("\nDone!")


if __name__ == '__main__':
    main()
