"""
Parser for Xero General Ledger with Tax Rates
"""
import pandas as pd
from typing import Dict, List, Any
from datetime import datetime


class GeneralLedgerParser:
    """Parse Xero General Ledger Excel files"""

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
        # Row 0: Company name
        # Row 1: Period
        if len(self.raw_data) > 0:
            self.metadata['company_name'] = str(self.raw_data.iloc[0, 0]) if not pd.isna(self.raw_data.iloc[0, 0]) else 'Unknown'

        if len(self.raw_data) > 1:
            period_text = str(self.raw_data.iloc[1, 0]) if not pd.isna(self.raw_data.iloc[1, 0]) else ''
            self.metadata['period'] = period_text

        if len(self.raw_data) > 3:
            filters_text = str(self.raw_data.iloc[3, 0]) if not pd.isna(self.raw_data.iloc[3, 0]) else ''
            self.metadata['filters'] = filters_text

    def _extract_transactions(self):
        """Extract all transaction rows from the data"""
        # Find row with column headers
        header_row_idx = None

        for idx, row in self.raw_data.iterrows():
            if (str(row[0]).strip().lower() == 'account code'):
                header_row_idx = idx
                break

        if header_row_idx is None:
            raise ValueError("Could not find header row in Excel file")

        # Extract column names
        columns = []
        for i in range(13):
            col_name = str(self.raw_data.iloc[header_row_idx, i]).strip()
            columns.append(col_name)

        # Process rows after header
        for idx in range(header_row_idx + 1, len(self.raw_data)):
            row = self.raw_data.iloc[idx]

            # Check if this is a valid transaction row (has account code and date)
            if pd.isna(row[0]) or str(row[0]).strip() == '':
                continue

            account_code = str(row[0]).strip()

            # Skip if not numeric account code
            try:
                int(account_code)
            except:
                continue

            # Parse date
            date_value = row[2]
            if pd.isna(date_value):
                continue

            # Build transaction dictionary
            transaction = {
                'row_number': idx + 1,
                'account_code': account_code,
                'account': str(row[1]) if not pd.isna(row[1]) else '',
                'date': self._format_date(row[2]),
                'source': str(row[3]) if not pd.isna(row[3]) else '',
                'description': str(row[4]) if not pd.isna(row[4]) else '',
                'invoice_number': str(row[5]) if not pd.isna(row[5]) else '',
                'reference': str(row[6]) if not pd.isna(row[6]) else '',
                'gross': self._parse_amount(row[7]),
                'gst': self._parse_amount(row[8]),
                'net': self._parse_amount(row[9]),
                'gst_rate': self._parse_amount(row[10]),
                'gst_rate_name': str(row[11]) if not pd.isna(row[11]) else '',
                'region': str(row[12]) if not pd.isna(row[12]) else '',
            }

            # Determine transaction type
            transaction['type'] = self._determine_transaction_type(account_code, transaction['account'])

            # Check GST accuracy
            transaction['gst_calculation_correct'] = self._check_gst_calculation(transaction)

            # Check account coding appropriateness
            transaction['account_coding_suspicious'] = self._check_account_coding(transaction)

            # Check for alcohol with GST (should be GST Free)
            transaction['alcohol_gst_error'] = self._check_alcohol_gst(transaction)

            self.transactions.append(transaction)

    def _format_date(self, date_value: Any) -> str:
        """Format date value to string"""
        if isinstance(date_value, str):
            try:
                dt = pd.to_datetime(date_value)
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

    def _determine_transaction_type(self, account_code: str, account_name: str) -> str:
        """Determine if transaction is income or expense"""
        account_lower = account_name.lower()

        # Income accounts (usually 200-399)
        if any(word in account_lower for word in ['sales', 'income', 'revenue']):
            return 'income'

        # Expense accounts (usually 400+)
        if any(word in account_lower for word in ['expense', 'cost', 'fees']):
            return 'expense'

        # Check by account code ranges (standard Xero chart of accounts)
        try:
            code_num = int(account_code)
            if 200 <= code_num < 400:
                return 'income'
            elif code_num >= 400:
                return 'expense'
        except:
            pass

        return 'unknown'

    def _check_gst_calculation(self, transaction: Dict[str, Any]) -> bool:
        """
        Check if GST calculation is correct based on GST Rate Name

        Returns True if calculation appears correct
        """
        gst_rate_name = transaction['gst_rate_name'].lower()
        gst_amount = abs(transaction['gst'])
        net_amount = abs(transaction['net'])
        gross_amount = abs(transaction['gross'])

        # If net is 0, can't validate
        if net_amount == 0:
            return True

        # Calculate expected GST
        if 'gst on' in gst_rate_name:
            # Should be 10% GST
            expected_gst = round(net_amount * 0.10, 2)
            tolerance = 0.02  # 2 cent tolerance for rounding
            return abs(gst_amount - expected_gst) <= tolerance

        elif 'bas excluded' in gst_rate_name or 'gst free' in gst_rate_name:
            # Should be 0% GST
            return gst_amount == 0

        # Unknown rate name, can't validate
        return True

    def _check_alcohol_gst(self, transaction: Dict[str, Any]) -> bool:
        """
        Check if alcohol purchase has GST claimed (should be GST Free)

        Returns True if alcohol has GST error (GST claimed when it shouldn't be)
        """
        description = transaction.get('description', '').lower()
        gst_amount = abs(transaction.get('gst', 0))
        gst_rate_name = transaction.get('gst_rate_name', '').lower()

        # Alcohol/liquor store keywords
        alcohol_keywords = ['dan murphy', 'dan murphys', "dan murphy's", 'bws', 'liquorland',
                           'liquor land', 'first choice liquor', 'vintage cellars',
                           'wine', 'beer', 'spirits', 'alcohol', 'champagne', 'liquor']

        # Check if this is an alcohol purchase
        is_alcohol = any(keyword in description for keyword in alcohol_keywords)

        if is_alcohol:
            # Alcohol should be GST Free - flag if GST is claimed
            if gst_amount > 0 or 'gst on' in gst_rate_name:
                return True  # Error: alcohol has GST claimed

        return False

    def _check_account_coding(self, transaction: Dict[str, Any]) -> bool:
        """
        Check if account coding seems suspicious based on description

        Returns True if coding seems suspicious
        """
        description = transaction['description'].lower()
        account = transaction['account'].lower()
        account_code = transaction['account_code']
        gross = transaction.get('gross', 0)

        # Check for expenses coded to Sales accounts (CRITICAL ERROR)
        # Exception: Sales refunds are allowed (negative amounts/debits to sales)
        if 'sales' in account or account_code in ['200', '201', '202']:
            # Check if this looks like an expense (not a refund)
            is_refund = any(word in description for word in ['refund', 'credit note', 'reversal', 'cancelled', 'returned'])

            # Common expense indicators
            expense_keywords = [
                'flight', 'qantas', 'virgin', 'jetstar', 'airline', 'airfare',
                'hotel', 'accommodation', 'parking', 'taxi', 'uber', 'car park',
                'office', 'stationery', 'supplies', 'toner', 'printer',
                'software', 'subscription', 'license',
                'meal', 'lunch', 'dinner', 'restaurant', 'cafe', 'catering',
                'insurance', 'premium',
                'rent', 'lease',
                'phone', 'mobile', 'internet', 'electricity', 'utilities',
                'bank fee', 'merchant fee',
                'freight', 'courier', 'postage',
                'repairs', 'maintenance',
                'training', 'conference',
                'legal', 'accounting', 'consulting'
            ]

            # If it looks like an expense and is coded to Sales (and not a refund), flag it
            if any(keyword in description for keyword in expense_keywords) and not is_refund:
                return True

        # Check for alcohol purchases in wrong accounts
        # Alcohol should be in Entertainment, Client Gifts, or Gifts
        alcohol_keywords = ['dan murphy', 'dan murphys', "dan murphy's", 'bws', 'liquorland',
                           'liquor land', 'first choice liquor', 'vintage cellars',
                           'wine', 'beer', 'spirits', 'alcohol', 'champagne', 'liquor']
        valid_alcohol_accounts = ['entertainment', 'client gift', 'gift', 'meals and entertainment',
                                  'meals & entertainment']

        if any(keyword in description for keyword in alcohol_keywords):
            # Check if coded to a valid account for alcohol
            if not any(valid_acct in account for valid_acct in valid_alcohol_accounts):
                return True  # Flag: alcohol in wrong account

        # Define obvious mismatches
        mismatches = [
            # Parking/vehicle in wrong accounts
            (['parking', 'car park', 'toll', 'petrol', 'fuel'],
             ['legal', 'professional', 'consulting', 'accounting'],
             'Vehicle expenses in wrong account'),

            # Bank fees in wrong accounts
            (['bank fee', 'account fee', 'transaction fee', 'merchant fee'],
             ['travel', 'entertainment', 'legal', 'professional'],
             'Bank fees in wrong account'),

            # Travel in wrong accounts
            (['flight', 'hotel', 'taxi', 'uber', 'accommodation', 'qantas', 'virgin', 'jetstar', 'airline'],
             ['legal', 'professional', 'office', 'stationery', 'sales'],
             'Travel expenses in wrong account'),

            # Meals in wrong accounts
            (['restaurant', 'catering', 'lunch', 'dinner', 'cafe'],
             ['office', 'stationery', 'supplies', 'legal'],
             'Meals in wrong account'),
        ]

        for desc_keywords, wrong_accounts, reason in mismatches:
            # Check if description contains any keyword
            if any(keyword in description for keyword in desc_keywords):
                # Check if account contains any wrong account name
                if any(wrong_acct in account for wrong_acct in wrong_accounts):
                    return True

        return False

    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics of parsed transactions"""
        if not self.transactions:
            return {}

        income_trans = [t for t in self.transactions if t['type'] == 'income']
        expense_trans = [t for t in self.transactions if t['type'] == 'expense']

        total_income = sum(abs(t['gross']) for t in income_trans)
        total_expenses = sum(abs(t['gross']) for t in expense_trans)
        total_gst_collected = sum(abs(t['gst']) for t in income_trans)
        total_gst_paid = sum(abs(t['gst']) for t in expense_trans)

        # Count GST errors
        gst_errors = len([t for t in self.transactions if not t['gst_calculation_correct']])

        return {
            'total_transactions': len(self.transactions),
            'total_income': total_income,
            'total_expenses': total_expenses,
            'total_gst_collected': total_gst_collected,
            'total_gst_paid': total_gst_paid,
            'net_gst': total_gst_collected - total_gst_paid,
            'income_transactions': len(income_trans),
            'expense_transactions': len(expense_trans),
            'gst_calculation_errors': gst_errors,
        }
