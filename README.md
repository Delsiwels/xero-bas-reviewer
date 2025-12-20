# Xero BAS Reviewer

AI-powered tool to review Xero Business Activity Statement (BAS) transactions and flag GST/account coding issues using DeepSeek API.

## Features

- Parse Xero Activity Statement Excel exports
- AI-powered review of GST codes and account coding
- Identify common BAS compliance issues:
  - GST code mismatches
  - Incorrect account classifications
  - Missing GST codes
  - BAS box mapping errors
  - Unusual amounts requiring review
- Generate formatted Excel reports with flagged items
- Color-coded severity levels (High, Medium, Low, Info)

## Installation

1. Clone or download this repository

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Set up your DeepSeek API key:
```bash
cp .env.example .env
```

4. Edit `.env` and add your DeepSeek API key:
```
DEEPSEEK_API_KEY=your_api_key_here
```

## Usage

### Step 1: Export Activity Statement from Xero

1. Log in to Xero
2. Go to Reports → Activity Statement
3. Select the period you want to review
4. Export as Excel (.xls or .xlsx)

### Step 2: Run the Reviewer

```bash
python reviewer.py "path/to/your/Activity Statement.xls"
```

Example:
```bash
python reviewer.py "Demo Company AU - Activity Statement.xls"
```

### Step 3: Review the Results

The tool will:
1. Parse all transactions from your Excel file
2. Send each transaction to DeepSeek AI for review
3. Flag any issues found
4. Generate a detailed Excel report

The output report will be saved as:
```
[Original Filename]_REVIEW_[Timestamp].xlsx
```

For example:
```
Demo Company AU - Activity Statement_REVIEW_20251215_143022.xlsx
```

## Report Structure

The generated Excel report contains two sheets:

### 1. Summary Sheet
- Review metadata (date, company, period)
- Transaction counts
- Financial summary (sales, purchases, GST)
- Issues breakdown by severity

### 2. Flagged Items Sheet
- Row-by-row listing of flagged transactions
- Severity indicators (color-coded)
- Issue types identified
- AI-generated comments and recommendations

## What It Checks

### GST Code Validation
- Correct GST rate (10% for standard GST)
- Appropriate GST codes for transaction types
- Common codes: GST, FRE (GST Free), INP (Input Taxed), CAP (Capital), BAS (BAS Excluded), EXP (Exports)

### Account Coding
- Expenses coded to correct accounts
- Common errors detected:
  - Bank fees miscoded as Travel/Entertainment
  - Meals/catering in Office Supplies
  - Personal expenses in business accounts
  - Capital purchases in Operating Expenses

### BAS Box Mapping
- G1: Total Sales (including GST)
- G2: Export Sales
- G3: Other GST-free Sales
- G10: Capital Purchases
- G11: Non-capital Purchases
- Validates transactions map to correct boxes

### Amount Validation
- GST calculations (amount × 10%)
- Unusual amounts flagged for review
- Round amounts that may indicate estimates

## Configuration

You can customize the behavior by editing `.env`:

```bash
# DeepSeek API Configuration
DEEPSEEK_API_KEY=your_key_here
DEEPSEEK_API_URL=https://api.deepseek.com/v1/chat/completions
DEEPSEEK_MODEL=deepseek-chat

# Processing Configuration
BATCH_SIZE=10          # Transactions per batch
MAX_RETRIES=3          # API retry attempts
TIMEOUT_SECONDS=30     # API timeout
```

## AI Prompt Customization

To customize validation rules or add business-specific checks, edit `prompts.py`:

- `create_review_prompt()` - Main transaction review prompt
- `VALIDATION_RULES` - GST codes, account patterns, BAS boxes

## Troubleshooting

### "Missing optional dependency 'xlrd'"
```bash
pip install xlrd openpyxl
```

### "DEEPSEEK_API_KEY not found"
Make sure you:
1. Created `.env` file (copy from `.env.example`)
2. Added your actual API key
3. `.env` is in the same directory as the scripts

### API Rate Limiting
The tool includes automatic retry with exponential backoff. If you hit rate limits frequently:
- Reduce `BATCH_SIZE` in `.env`
- Add delays between batches

### Empty Report / No Issues Found
This could mean:
- All transactions are correctly coded (great!)
- The AI model is being too lenient
- Adjust the prompts in `prompts.py` to be more strict

## File Structure

```
xero-bas-reviewer/
├── reviewer.py              # Main review engine
├── excel_parser.py          # Xero Excel file parser
├── deepseek_client.py       # DeepSeek API client
├── prompts.py               # AI prompts and validation rules
├── output_generator.py      # Excel report generator
├── requirements.txt         # Python dependencies
├── .env.example            # Environment variables template
├── .env                    # Your API keys (not in git)
└── README.md              # This file
```

## Example Output

```
================================================================================
XERO BAS REVIEWER
================================================================================

Parsing Excel file: Demo Company AU - Activity Statement.xls
✓ Found 102 transactions
  Company: Demo Company (AU)
  Period: For the period 1 April 2025 to 30 June 2025

  Sales: $51,849.50
  Purchases: $42,366.21
  GST Collected: $4,713.59
  GST Paid: $3,851.47
  Net GST: $862.12

================================================================================
REVIEWING TRANSACTIONS WITH AI
================================================================================

Batch 1/11 (Transactions 1-10)
  🟡 Row 47: Mobil
  🔴 Row 49: Expense claim for Odette Grainger

Batch 2/11 (Transactions 11-20)
  🟢 Row 54: Central Copiers - Photocopier repair & drum replacement

...

================================================================================
REVIEW COMPLETE
================================================================================

Total transactions reviewed: 102
Flagged items: 12

Severity breakdown:
  🔴 HIGH: 3
  🟡 MEDIUM: 6
  🟢 LOW: 3

✓ Review report saved to: Demo Company AU - Activity Statement_REVIEW_20251215_143022.xlsx

Done!
```

## Security Notes

- Never commit `.env` file to version control
- Keep your DeepSeek API key secure
- Review AI suggestions before making changes in Xero
- The tool provides recommendations only - always verify with a qualified accountant

## Limitations

- This tool provides AI-powered suggestions, not definitive accounting advice
- Always consult with a qualified accountant for final BAS lodgement
- AI may occasionally miss issues or flag false positives
- Review all flagged items manually before making corrections

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review the DeepSeek API documentation
3. Verify your Excel file matches Xero's Activity Statement format

## License

MIT License - feel free to modify and customize for your needs.

---

**Disclaimer**: This tool is for informational purposes only. Always consult with a qualified accountant or tax professional before lodging your BAS with the ATO.
