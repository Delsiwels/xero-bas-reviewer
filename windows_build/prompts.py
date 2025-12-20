"""
AI prompts for BAS and GST review
"""
from typing import Dict, Any, List


def create_review_prompt(transaction: Dict[str, Any], context: Dict[str, Any]) -> str:
    """
    Create a detailed prompt for reviewing a transaction

    Args:
        transaction: Transaction data from Xero
        context: Additional context (account mappings, rules, etc.)

    Returns:
        Formatted prompt string
    """
    prompt = f"""Review this Australian BAS/GST transaction for GST TREATMENT and account coding:

TRANSACTION DETAILS:
- Date: {transaction.get('date', 'N/A')}
- Description: {transaction.get('description', 'N/A')}
- Account: {transaction.get('account', 'N/A')} - {transaction.get('account_name', 'N/A')}

AMOUNTS (Activity Statement Format):
- Gross (Inc-GST): ${transaction.get('amount', 0):,.2f}
- GST Amount: ${transaction.get('gst_amount', 0):,.2f}
- Net Amount: ${transaction.get('net_amount', 0):,.2f}

CURRENT GST TREATMENT:
- GST Code: {transaction.get('gst_code', 'N/A')}
- BAS Box: {transaction.get('bas_box', 'N/A')}

IMPORTANT: DO NOT check if GST calculation is mathematically correct - it always is.
ONLY check if the GST TREATMENT (code) is appropriate for this transaction type.

GST TREATMENT VALIDATION:
1. Does this transaction have the CORRECT GST code?

   Common CORRECT uses:
   - GST (10% GST) = Most normal business sales and expenses
   - FRE (GST Free) = Exports, basic food, education, health services
   - BAS (BAS Excluded) = Bank interest, wages, certain financial services
   - CAP (Capital) = Purchase of capital assets with GST
   - INP (Input Taxed) = Financial supplies, residential rent

   Common ERRORS to flag:
   - Normal business sales coded as BAS Excluded (should be GST)
   - Office supplies coded as GST Free (should be GST)
   - Equipment/furniture coded as BAS Excluded (should be CAP or GST)
   - Regular services coded as GST Free without justification

2. Account Coding:
   - Is the expense/income coded to the correct account?
   - Examples of common errors:
     * Bank fees in Travel/Entertainment
     * Meals in Office Supplies
     * Personal expenses in business accounts
     * Capital purchases in Operating Expenses

3. BAS Box Mapping:
   - Does the BAS box match the GST code?
   - G1: Sales with GST, G2: Exports, G3: GST-free sales
   - G10: Capital purchases, G11: Non-capital purchases with GST

REVIEW INSTRUCTIONS:
- IGNORE the GST $ amounts - they are always calculated correctly
- FOCUS ONLY on whether the GST CODE/TREATMENT is appropriate
- Flag if normal business items are marked BAS Excluded or GST Free without justification
- Flag account coding errors (wrong account for the transaction)
- If NO issues found, respond: "OK - Transaction appears correct"
- If issues found, state:
  1. What is incorrect (GST treatment or account coding)
  2. What it should be (correct code or account)
  3. Why it matters

Your review:"""

    return prompt


def create_batch_review_prompt(transactions: List[Dict[str, Any]], context: Dict[str, Any]) -> str:
    """
    Create a prompt for reviewing multiple transactions together
    Useful for identifying patterns and related issues

    Args:
        transactions: List of transaction data
        context: Additional context

    Returns:
        Formatted prompt string
    """
    transaction_summary = "\n".join([
        f"{i+1}. {t.get('date', 'N/A')} | {t.get('description', 'N/A')[:40]} | "
        f"{t.get('account_name', 'N/A')[:30]} | ${t.get('amount', 0):,.2f} | GST: {t.get('gst_code', 'N/A')}"
        for i, t in enumerate(transactions)
    ])

    prompt = f"""Review these {len(transactions)} Australian BAS/GST transactions as a batch:

TRANSACTIONS:
{transaction_summary}

Look for:
1. Patterns of incorrect GST coding
2. Consistent account misclassification
3. Related transactions that should be grouped
4. Duplicate entries
5. Unusual patterns requiring review

For each transaction with issues, respond in this format:
Transaction #: [issue description and recommendation]

If all transactions are correct, respond: "All transactions appear correct"

Your review:"""

    return prompt


def create_summary_prompt(flagged_items: List[Dict[str, Any]]) -> str:
    """
    Create a prompt for generating an executive summary of all issues

    Args:
        flagged_items: List of flagged transactions with issues

    Returns:
        Summary prompt string
    """
    issues_by_type = {}
    for item in flagged_items:
        for issue in item.get('issues', []):
            issues_by_type[issue] = issues_by_type.get(issue, 0) + 1

    summary = "\n".join([f"- {issue}: {count} occurrences" for issue, count in issues_by_type.items()])

    prompt = f"""Summarize these BAS review findings:

ISSUES FOUND ({len(flagged_items)} transactions):
{summary}

Provide:
1. Key compliance risks
2. Priority actions required
3. Common patterns to address
4. Estimated BAS impact (if material)

Keep it concise and actionable for the business owner/accountant.

Summary:"""

    return prompt


# Validation rules for reference
VALIDATION_RULES = {
    'gst_codes': {
        'GST': {'rate': 0.10, 'description': 'Goods & Services Tax', 'bas_boxes': ['G1', 'G11']},
        'FRE': {'rate': 0.00, 'description': 'GST Free', 'bas_boxes': ['G2', 'G3']},
        'INP': {'rate': 0.00, 'description': 'Input Taxed', 'bas_boxes': []},
        'CAP': {'rate': 0.10, 'description': 'Capital Acquisitions', 'bas_boxes': ['G10']},
        'BAS': {'rate': 0.00, 'description': 'BAS Excluded', 'bas_boxes': []},
        'EXP': {'rate': 0.00, 'description': 'Exports', 'bas_boxes': ['G2']},
    },
    'account_patterns': {
        'bank_fees': ['bank fees', 'merchant fees', 'transaction fees', 'account fees'],
        'travel': ['flights', 'accommodation', 'taxi', 'uber', 'parking', 'toll'],
        'meals': ['restaurant', 'catering', 'lunch', 'dinner', 'coffee'],
        'office': ['stationery', 'office supplies', 'printer', 'paper'],
        'software': ['subscription', 'saas', 'software', 'license'],
        'professional_fees': ['accounting', 'legal', 'consulting', 'professional services'],
    },
    'bas_boxes': {
        'G1': 'Total sales (including any GST)',
        'G2': 'Export sales',
        'G3': 'Other GST-free sales',
        'G4': 'Input taxed sales',
        'G10': 'Capital purchases',
        'G11': 'Non-capital purchases',
        'G13': 'Purchases for making input taxed sales',
        'G14': 'Purchases with no GST in the price',
        'G15': 'Estimated net GST for quarter',
    }
}
