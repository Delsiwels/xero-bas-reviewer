# Quick Start Guide

## Setup (5 minutes)

### 1. Install Dependencies
```bash
cd /Users/noradelsierra/xero-bas-reviewer
pip3 install -r requirements.txt
```

### 2. Add Your DeepSeek API Key
Edit the `.env` file and replace `your_deepseek_api_key_here` with your actual API key:

```bash
# Open .env in your text editor
# Change this line:
DEEPSEEK_API_KEY=your_deepseek_api_key_here

# To (with your actual key):
DEEPSEEK_API_KEY=sk-abc123...
```

### 3. Export Activity Statement from Xero
1. Log in to Xero
2. Go to **Reports** → **Activity Statement**
3. Select period (e.g., Q1, Q2, etc.)
4. Click **Export** → **Excel**
5. Save the file

## Usage

### Basic Usage
```bash
python3 reviewer.py "path/to/Activity Statement.xls"
```

### Example with your demo file
```bash
python3 reviewer.py "/Users/noradelsierra/Downloads/Demo Company AU - Activity Statement.xls"
```

## What Happens

1. **Parser reads the Excel file**
   - Extracts all transactions
   - Identifies GST codes, accounts, amounts
   - Calculates BAS box mappings

2. **AI reviews each transaction**
   - Checks GST code accuracy
   - Validates account coding
   - Flags potential issues

3. **Report is generated**
   - Excel file with Summary and Flagged Items sheets
   - Color-coded by severity
   - AI comments for each issue

## Output

You'll get a file like:
```
Demo Company AU - Activity Statement_REVIEW_20251215_143022.xlsx
```

With two sheets:
- **Summary**: Overall stats, financial summary, issue counts
- **Flagged Items**: Row-by-row flagged transactions with AI comments

## What It Checks

✓ **GST Code Validation**
  - Correct 10% GST rate
  - Appropriate codes (GST, FRE, CAP, BAS, EXP, INP)
  - Match with account types

✓ **Account Coding**
  - Bank fees not in Travel
  - Meals not in Office Supplies
  - Capital items not in Operating Expenses
  - Personal expenses flagged

✓ **BAS Box Mapping**
  - G1: Total Sales
  - G2: Exports
  - G3: GST-free sales
  - G10: Capital purchases
  - G11: Non-capital purchases

✓ **Amount Validation**
  - GST calculations
  - Unusual amounts
  - Round numbers

## Test Without API

To see what data gets sent to the AI (without making API calls):
```bash
python3 test_without_api.py
```

## Common Issues

**Error: DEEPSEEK_API_KEY not found**
- Make sure you edited `.env` with your actual API key

**Error: File not found**
- Use the full path to your Excel file
- Put quotes around filenames with spaces

**No issues found**
- Great! Your BAS is clean
- Or the AI is being lenient (adjust prompts.py if needed)

## Tips

- Review in batches: The tool processes 10 transactions at a time
- Check high severity items first (red in the report)
- Always verify AI suggestions with an accountant
- Keep the original file - the tool only reads, never modifies

## Need Help?

See full documentation in `README.md`
