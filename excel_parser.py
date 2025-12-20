"""
Excel parser for Xero Activity Statement
"""
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime


class XeroActivityStatementParser:
    """Parse Xero Activity Statement Excel files"""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.raw_data = None
        self.transactions = []
        self.metadata = {}

    def parse(self) -> Dict[str, Any]:
        """
        Parse the Excel file and extract transactions

        Returns:
            Dictionary containing metadata and transactions
        """
        # Read the entire Excel file without headers
        self.raw_data = pd.read_excel(self.file_path, header=None)

        # Extract metadata from header rows
        self._extract_metadata()

        # Extract transactions
        self._extract_transactions()

        return {
            'metadata': self.metadata,
            'transactions': self.transactions,
            'total_transactions': len(self.transactions)
        }

    def _extract_metadata(self):
        """Extract company name and period from header rows"""
        # Row 0: Report title
        # Row 1: Company name
        # Row 2: Period
        if len(self.raw_data) > 1:
            self.metadata['company_name'] = str(self.raw_data.iloc[1, 0]) if not pd.isna(self.raw_data.iloc[1, 0]) else 'Unknown'

        if len(self.raw_data) > 2:
            period_text = str(self.raw_data.iloc[2, 0]) if not pd.isna(self.raw_data.iloc[2, 0]) else ''
            self.metadata['period'] = period_text

    def _extract_transactions(self):
        """Extract all transaction rows from the data"""
        # Find rows with column headers (looking for 'Date', 'Account', etc.)
        header_row_idx = None

        for idx, row in self.raw_data.iterrows():
            if (str(row[0]).strip().lower() == 'date' and
                str(row[1]).strip().lower() == 'account'):
                header_row_idx = idx
                break

        if header_row_idx is None:
            raise ValueError("Could not find header row in Excel file")

        # Extract column names
        columns = [str(self.raw_data.iloc[header_row_idx, i]).strip() for i in range(7)]

        # Process rows after header
        for idx in range(header_row_idx + 1, len(self.raw_data)):
            row = self.raw_data.iloc[idx]

            # Check if this is a valid transaction row
            # Valid rows have a date in column 0 and account in column 1
            if pd.isna(row[0]) or str(row[0]).strip() == '':
                continue

            # Try to parse as date
            date_value = row[0]
            if isinstance(date_value, str):
                try:
                    # Try parsing date formats
                    parsed_date = pd.to_datetime(date_value, format='%d/%m/%Y', errors='coerce')
                    if pd.isna(parsed_date):
                        continue
                except:
                    continue
            elif not isinstance(date_value, (datetime, pd.Timestamp)):
                continue

            # Extract account name and code
            account_full = str(row[1]) if not pd.isna(row[1]) else ''
            account_name, account_code = self._parse_account(account_full)

            # Build transaction dictionary
            transaction = {
                'row_number': idx + 1,  # Excel row number (1-indexed)
                'date': self._format_date(row[0]),
                'account': account_full,
                'account_name': account_name,
                'account_code': account_code,
                'reference': str(row[2]) if not pd.isna(row[2]) else '',
                'description': str(row[3]) if not pd.isna(row[3]) else '',
                'amount': self._parse_amount(row[4]),
                'gst_amount': self._parse_amount(row[5]),
                'net_amount': self._parse_amount(row[6]),
            }

            # Infer GST code and tax type from amounts
            transaction['gst_code'] = self._infer_gst_code(transaction)
            transaction['tax_type'] = self._infer_tax_type(account_name)

            # Determine transaction type (income/expense)
            transaction['type'] = self._determine_transaction_type(account_name, account_code)

            # Determine BAS box
            transaction['bas_box'] = self._determine_bas_box(transaction)

            self.transactions.append(transaction)

    def _parse_account(self, account_full: str) -> Tuple[str, str]:
        """
        Parse account string to extract name and code
        Example: 'Sales (200)' -> ('Sales', '200')
        """
        if '(' in account_full and ')' in account_full:
            # Extract code from parentheses
            start = account_full.rfind('(')
            end = account_full.rfind(')')
            code = account_full[start+1:end].strip()
            name = account_full[:start].strip()
            return name, code
        else:
            return account_full, ''

    def _format_date(self, date_value: Any) -> str:
        """Format date value to string"""
        if isinstance(date_value, str):
            try:
                dt = pd.to_datetime(date_value, format='%d/%m/%Y')
                return dt.strftime('%Y-%m-%d')
            except:
                return date_value
        elif isinstance(date_value, (datetime, pd.Timestamp)):
            return date_value.strftime('%Y-%m-%d')
        else:
            return str(date_value)

    def _parse_amount(self, value: Any) -> float:
        """Parse amount value to float"""
        if pd.isna(value):
            return 0.0

        if isinstance(value, (int, float)):
            return float(value)

        # Remove currency symbols and commas
        value_str = str(value).replace('$', '').replace(',', '').strip()
        try:
            return float(value_str)
        except:
            return 0.0

    def _infer_gst_code(self, transaction: Dict[str, Any]) -> str:
        """
        Infer GST code from transaction amounts
        """
        amount = transaction['amount']
        gst_amount = transaction['gst_amount']
        net_amount = transaction['net_amount']

        if amount == 0:
            return 'N/A'

        # Calculate GST rate
        if net_amount != 0:
            gst_rate = abs(gst_amount / net_amount)
        else:
            gst_rate = 0

        # Determine GST code based on rate
        if abs(gst_rate - 0.10) < 0.001:  # 10% GST
            # Check if it's capital acquisition
            if self._is_capital_purchase(transaction):
                return 'CAP'
            else:
                return 'GST'
        elif gst_amount == 0:
            # Could be GST-free, input taxed, or BAS excluded
            if self._is_export(transaction):
                return 'EXP'
            elif self._is_gst_free(transaction):
                return 'FRE'
            else:
                return 'BAS'
        else:
            return 'GST'

    def _infer_tax_type(self, account_name: str) -> str:
        """Infer tax type from account name"""
        account_lower = account_name.lower()

        if any(word in account_lower for word in ['sales', 'income', 'revenue']):
            return 'Output Tax'
        elif any(word in account_lower for word in ['expense', 'cost', 'purchase']):
            return 'Input Tax'
        else:
            return 'Unknown'

    def _determine_transaction_type(self, account_name: str, account_code: str) -> str:
        """Determine if transaction is income or expense"""
        account_lower = account_name.lower()

        # Sales accounts (usually 200-299)
        if any(word in account_lower for word in ['sales', 'income', 'revenue']):
            return 'income'

        # Expense accounts (usually 400+)
        if any(word in account_lower for word in ['expense', 'cost', 'fees']):
            return 'expense'

        # Check by account code ranges (standard Xero chart of accounts)
        if account_code:
            try:
                code_num = int(account_code)
                if 200 <= code_num < 300:
                    return 'income'
                elif code_num >= 400:
                    return 'expense'
            except:
                pass

        return 'unknown'

    def _determine_bas_box(self, transaction: Dict[str, Any]) -> str:
        """Determine which BAS box this transaction belongs to"""
        trans_type = transaction['type']
        gst_code = transaction['gst_code']
        account_name = transaction['account_name'].lower()

        if trans_type == 'income':
            # Sales transactions
            if gst_code == 'GST':
                return 'G1'  # Total sales including GST
            elif gst_code == 'EXP':
                return 'G2'  # Export sales
            elif gst_code == 'FRE':
                return 'G3'  # Other GST-free sales
            elif gst_code == 'INP':
                return 'G4'  # Input taxed sales
        elif trans_type == 'expense':
            # Purchase transactions
            if gst_code == 'CAP':
                return 'G10'  # Capital purchases
            elif gst_code == 'GST':
                return 'G11'  # Non-capital purchases
            elif gst_code == 'INP':
                return 'G13'  # Purchases for making input taxed sales
            elif gst_code in ['FRE', 'BAS']:
                return 'G14'  # Purchases with no GST

        return 'N/A'

    def _is_capital_purchase(self, transaction: Dict[str, Any]) -> bool:
        """Check if transaction is a capital purchase"""
        account_lower = transaction['account_name'].lower()
        description_lower = transaction['description'].lower()

        capital_keywords = [
            'equipment', 'furniture', 'vehicle', 'computer', 'laptop',
            'machinery', 'building', 'property', 'asset', 'depreciation'
        ]

        return any(keyword in account_lower or keyword in description_lower
                   for keyword in capital_keywords)

    def _is_export(self, transaction: Dict[str, Any]) -> bool:
        """Check if transaction is an export"""
        description_lower = transaction['description'].lower()
        return 'export' in description_lower

    def _is_gst_free(self, transaction: Dict[str, Any]) -> bool:
        """Check if transaction is GST-free"""
        account_lower = transaction['account_name'].lower()

        gst_free_keywords = ['education', 'health', 'medical', 'food']

        return any(keyword in account_lower for keyword in gst_free_keywords)

    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics of parsed transactions"""
        if not self.transactions:
            return {}

        total_sales = sum(t['amount'] for t in self.transactions if t['type'] == 'income')
        total_purchases = sum(abs(t['amount']) for t in self.transactions if t['type'] == 'expense')
        total_gst_collected = sum(t['gst_amount'] for t in self.transactions if t['type'] == 'income')
        total_gst_paid = sum(abs(t['gst_amount']) for t in self.transactions if t['type'] == 'expense')

        return {
            'total_transactions': len(self.transactions),
            'total_sales': total_sales,
            'total_purchases': total_purchases,
            'total_gst_collected': total_gst_collected,
            'total_gst_paid': total_gst_paid,
            'net_gst': total_gst_collected - total_gst_paid,
            'income_transactions': len([t for t in self.transactions if t['type'] == 'income']),
            'expense_transactions': len([t for t in self.transactions if t['type'] == 'expense']),
        }
