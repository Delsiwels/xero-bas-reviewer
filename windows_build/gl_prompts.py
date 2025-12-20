"""
AI prompts for General Ledger review - More accurate validation
"""
from typing import Dict, Any, List


def create_gl_review_prompt(transaction: Dict[str, Any], context: Dict[str, Any]) -> str:
    """
    Create a detailed prompt for reviewing a General Ledger transaction

    Args:
        transaction: Transaction data from General Ledger
        context: Additional context

    Returns:
        Formatted prompt string
    """

    # Determine if GST calculation is correct
    gst_calc_status = "✓ CORRECT" if transaction.get('gst_calculation_correct', True) else "✗ INCORRECT"

    # Determine if account coding is suspicious
    account_coding_status = "⚠️  SUSPICIOUS - Description doesn't match account" if transaction.get('account_coding_suspicious', False) else "Appears OK"

    prompt = f"""Review this Australian General Ledger transaction for compliance and coding accuracy:

TRANSACTION DETAILS:
- Date: {transaction.get('date', 'N/A')}
- Account Code: {transaction.get('account_code', 'N/A')}
- Account Name: {transaction.get('account', 'N/A')}
- Source: {transaction.get('source', 'N/A')}
- Description: {transaction.get('description', 'N/A')}
- Invoice/Reference: {transaction.get('invoice_number', 'N/A')} / {transaction.get('reference', 'N/A')}

AMOUNTS:
- Gross: ${transaction.get('gross', 0):,.2f}
- GST: ${transaction.get('gst', 0):,.2f}
- Net: ${transaction.get('net', 0):,.2f}

GST INFORMATION:
- GST Rate: {transaction.get('gst_rate', 0)}%
- GST Rate Name: {transaction.get('gst_rate_name', 'N/A')}
- GST Calculation: {gst_calc_status}

⚠️  ACCOUNT CODING CHECK:
- Status: {account_coding_status}
{f">>> THIS TRANSACTION HAS A CODING ERROR - YOU MUST FLAG IT <<<" if transaction.get('account_coding_suspicious', False) else ""}

{"⚠️  ALCOHOL GST ERROR: This appears to be an alcohol purchase with GST claimed. Alcohol should be GST FREE due to FBT implications. >>> YOU MUST FLAG THIS <<<" if transaction.get('alcohol_gst_error', False) else ""}

IMPORTANT GST VALIDATION RULES:
1. "GST on Expenses" or "GST on Income" = Should have 10% GST (most common, standard treatment)
2. "BAS Excluded" = Should ONLY be used for specific exempt items (question if used for normal business sales/expenses)
3. "GST Free" = Should ONLY be used for genuinely GST-free items (education, health, basic food, exports)
4. QUESTION why common business expenses/sales are marked as "BAS Excluded" or "GST Free"
5. Most business sales and expenses should have GST - be suspicious if they don't
6. BANK FEES GST RULES:
   - Standard bank fees (account fees, transaction fees) = Usually GST Free (financial services are input taxed)
   - Credit card fees/surcharges = CAN have GST (this is ACCEPTABLE)
   - If description contains "credit card fee", "cc fee", "surcharge", "credit card surcharge", "merchant fee" → GST inclusive is CORRECT
7. ALCOHOL PURCHASES (Dan Murphy's, BWS, Liquorland, etc.):
   - Should be coded to Entertainment, Client Gifts, or Gifts account
   - Should be GST FREE (entertainment/gifts with alcohol have FBT implications, input taxed)
   - If alcohol purchase is coded to other accounts (e.g., Office Supplies, General Expenses) → FLAG IT
   - If alcohol purchase has GST claimed → FLAG IT (should be GST Free)

WHAT TO REVIEW:

1. Account Coding Appropriateness (BE CRITICAL):
   - Is the transaction coded to the CORRECT account?
   - CRITICAL ERROR - EXPENSES CODED TO SALES:
     * ANY expense (flights, hotels, supplies, etc.) coded to Sales account → MUST FLAG
     * Qantas, Virgin, Jetstar flights in Sales → WRONG, should be Travel expenses
     * Office supplies, parking, meals in Sales → WRONG, should be appropriate expense account
     * EXCEPTION: Sales refunds/credit notes CAN be debited to Sales (look for "refund", "credit note", "reversal")
   - Common miscoding examples TO FLAG:
     * Parking/car expenses in Legal expenses → should be Motor Vehicle Expenses
     * Bank fees in Travel/Entertainment → should be Bank Fees
     * Meals/catering in Office Supplies → should be Meals & Entertainment
     * Travel expenses in Legal/Professional fees
     * Personal expenses in business accounts
     * Operating expenses in Capital accounts
   - ACCEPTABLE CODINGS (DO NOT FLAG):
     * Toner/ink cartridges in Printing & Stationery or Office Supplies → this is CORRECT
     * Sales refunds debited to Sales account → this is CORRECT
     * Alcohol purchases (Dan Murphy's, BWS, etc.) in Entertainment or Client Gifts → this is CORRECT (must be GST Free)
   - ALCOHOL PURCHASES - MUST FLAG IF:
     * Coded to wrong account (not Entertainment/Gifts) → FLAG
     * Has GST claimed → FLAG (should be GST Free due to FBT)
   - MATCH the description to the account name - if they don't align, FLAG IT

2. Transaction Reasonableness:
   - Are amounts reasonable for the description?
   - Are there obvious data entry errors (e.g., extra zeros)?
   - Round amounts might be estimates worth reviewing

3. Missing or Unclear Information:
   - Is the description adequate for audit purposes?
   - Are required references present?

4. Unusual Patterns:
   - Duplicate transactions
   - Unusual timing (e.g., expenses dated in future)
   - Contra entries without clear explanation

REVIEW INSTRUCTIONS:
- BE CRITICAL AND THOROUGH - Flag issues that need correction
- If "Account Coding Check" shows "SUSPICIOUS" → MUST FLAG IT with correct account suggestion
- Question transactions marked "BAS Excluded" or "GST Free" unless clearly appropriate
- Flag account coding mismatches (description doesn't match account name)
- Question normal business expenses/sales without GST
- If the description mentions parking/car/travel but it's in Legal expenses → FLAG IT
- If sales/purchases are marked BAS Excluded without clear reason → FLAG IT
- If stationery/supplies are marked GST Free without clear reason → FLAG IT
- If everything appears correct, respond: "OK - Transaction appears correctly recorded"

If you find issues, state CLEARLY:
1. What is incorrect (be specific about the error)
2. What it should be (correct account or GST treatment)
3. Why it matters for compliance/accuracy/BAS reporting

Your review:"""

    return prompt


def create_batch_gl_review_prompt(transactions: List[Dict[str, Any]], context: Dict[str, Any]) -> str:
    """
    Create a prompt for reviewing multiple GL transactions together
    Useful for identifying patterns
    """
    transaction_summary = "\n".join([
        f"{i+1}. {t.get('date', 'N/A')} | {t.get('account', 'N/A')[:25]} | "
        f"{t.get('description', 'N/A')[:40]} | ${t.get('gross', 0):,.2f} | "
        f"GST: {t.get('gst_rate_name', 'N/A')}"
        for i, t in enumerate(transactions)
    ])

    prompt = f"""Review these {len(transactions)} Australian General Ledger transactions as a batch:

TRANSACTIONS:
{transaction_summary}

Look for:
1. Patterns of potential miscoding (same error repeated)
2. Duplicate or related transactions
3. Unusual patterns requiring review
4. Systematic issues with GST treatment

IMPORTANT:
- DO NOT flag transactions where GST matches the GST Rate Name
- Only flag ACTUAL issues, not technically correct transactions
- Focus on coding appropriateness and reasonableness

For each transaction with genuine issues, respond:
Transaction #: [specific issue and recommendation]

If all transactions appear correct, respond: "All transactions appear correctly recorded"

Your review:"""

    return prompt


# Common expense categories for better validation
EXPENSE_CATEGORIES = {
    'bank_fees': {
        'keywords': ['bank fee', 'merchant fee', 'transaction fee', 'account fee', 'bank charges', 'credit card fee', 'cc fee', 'surcharge', 'credit card surcharge'],
        'typical_accounts': ['bank fees', 'bank charges', 'financial charges'],
        'gst_note': 'Credit card fees/surcharges can have GST; standard bank fees are usually GST-free'
    },
    'travel': {
        'keywords': ['flight', 'accommodation', 'hotel', 'taxi', 'uber', 'parking', 'toll', 'airfare'],
        'typical_accounts': ['travel', 'travel expenses']
    },
    'meals_entertainment': {
        'keywords': ['restaurant', 'catering', 'lunch', 'dinner', 'coffee', 'cafe', 'entertainment'],
        'typical_accounts': ['meals', 'entertainment', 'meals and entertainment']
    },
    'office_supplies': {
        'keywords': ['stationery', 'office supplies', 'printer', 'paper', 'pens', 'folders', 'toner', 'ink cartridge', 'cartridge'],
        'typical_accounts': ['office expenses', 'office supplies', 'stationery', 'printing & stationery', 'printing and stationery']
    },
    'software': {
        'keywords': ['subscription', 'saas', 'software', 'license', 'cloud', 'microsoft', 'adobe', 'xero'],
        'typical_accounts': ['software', 'subscriptions', 'computer expenses', 'technology']
    },
    'professional_fees': {
        'keywords': ['accounting', 'legal', 'consulting', 'professional services', 'advisor', 'lawyer', 'accountant'],
        'typical_accounts': ['professional fees', 'consulting', 'accounting fees', 'legal expenses']
    },
    'utilities': {
        'keywords': ['electricity', 'power', 'gas', 'water', 'internet', 'phone', 'mobile', 'telstra', 'vodafone'],
        'typical_accounts': ['utilities', 'telephone', 'internet', 'power']
    },
    'insurance': {
        'keywords': ['insurance', 'premium', 'policy', 'cover'],
        'typical_accounts': ['insurance']
    },
    'rent': {
        'keywords': ['rent', 'lease', 'property management'],
        'typical_accounts': ['rent', 'lease expenses']
    },
    'alcohol_liquor': {
        'keywords': ['dan murphy', 'dan murphys', "dan murphy's", 'bws', 'liquorland', 'liquor land', 'first choice liquor', 'vintage cellars', 'wine', 'beer', 'spirits', 'alcohol', 'champagne', 'liquor'],
        'typical_accounts': ['entertainment', 'client gifts', 'gifts', 'meals and entertainment', 'meals & entertainment'],
        'gst_note': 'Alcohol purchases should be GST Free due to FBT implications'
    },
}
