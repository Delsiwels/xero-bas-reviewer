"""
Generate LARGE test datasets for BAS Reviewer stress testing
- 9 industry files with 500+ transactions each
- 1 mega file with 5000+ transactions
"""

import pandas as pd
from datetime import datetime, timedelta
import random

def save_to_excel(df, filename, company_name, period):
    """Save DataFrame to Excel with Xero-style formatting"""
    with pd.ExcelWriter(filename, engine='openpyxl') as writer:
        header_df = pd.DataFrame({
            'Date': ['General Ledger Detail', company_name, period, ''],
            'Account Code': ['', '', '', ''],
            'Account': ['', '', '', ''],
            'Description': ['', '', '', ''],
            'Reference': ['', '', '', ''],
            'Contact': ['', '', '', ''],
            'Gross': ['', '', '', ''],
            'GST': ['', '', '', ''],
            'Net': ['', '', '', ''],
            'GST Rate Name': ['', '', '', ''],
            'Source': ['', '', '', '']
        })
        header_df.to_excel(writer, sheet_name='General Ledger Detail',
                          index=False, header=False, startrow=0)
        df.to_excel(writer, sheet_name='General Ledger Detail',
                   index=False, startrow=5)
    print(f"Saved: {filename}")


# Transaction templates with error types
EXPENSE_TEMPLATES = [
    # CORRECT transactions
    {'code': '400', 'account': 'Office Supplies', 'desc': 'Officeworks - Stationery', 'contact': 'Officeworks', 'has_gst': True, 'error': None},
    {'code': '404', 'account': 'Telephone & Internet', 'desc': 'Telstra Business Plan', 'contact': 'Telstra', 'has_gst': True, 'error': None},
    {'code': '412', 'account': 'Motor Vehicle Expenses', 'desc': 'BP Fuel', 'contact': 'BP', 'has_gst': True, 'error': None},
    {'code': '425', 'account': 'Rent', 'desc': 'Commercial office rent', 'contact': 'Landlord', 'has_gst': True, 'error': None},
    {'code': '440', 'account': 'Accounting Fees', 'desc': 'BAS preparation', 'contact': 'Accountant', 'has_gst': True, 'error': None},
    {'code': '428', 'account': 'Cleaning', 'desc': 'Office cleaning', 'contact': 'CleanCo', 'has_gst': True, 'error': None},
    {'code': '410', 'account': 'Advertising', 'desc': 'Google Ads campaign', 'contact': 'Google AU', 'has_gst': True, 'error': None},
    {'code': '460', 'account': 'Postage', 'desc': 'Australia Post', 'contact': 'AusPost', 'has_gst': True, 'error': None},
    {'code': '429', 'account': 'Repairs & Maintenance', 'desc': 'Plumber callout', 'contact': 'Plumber', 'has_gst': True, 'error': None},
    {'code': '411', 'account': 'Printing', 'desc': 'Business cards', 'contact': 'Snap Printing', 'has_gst': True, 'error': None},

    # ERROR: Entertainment/Alcohol
    {'code': '420', 'account': 'Entertainment', 'desc': 'Dan Murphys - Wine for clients', 'contact': 'Dan Murphys', 'has_gst': True, 'error': 'alcohol'},
    {'code': '420', 'account': 'Entertainment', 'desc': 'BWS - Beer for office', 'contact': 'BWS', 'has_gst': True, 'error': 'alcohol'},
    {'code': '420', 'account': 'Entertainment', 'desc': 'Restaurant - client dinner with drinks', 'contact': 'Restaurant', 'has_gst': True, 'error': 'entertainment'},
    {'code': '420', 'account': 'Entertainment', 'desc': 'Liquorland - Champagne', 'contact': 'Liquorland', 'has_gst': True, 'error': 'alcohol'},

    # ERROR: Personal expenses
    {'code': '404', 'account': 'Telephone & Internet', 'desc': 'Telstra personal mobile', 'contact': 'Telstra', 'has_gst': True, 'error': 'personal'},
    {'code': '412', 'account': 'Motor Vehicle Expenses', 'desc': 'Personal car fuel - holiday', 'contact': 'Shell', 'has_gst': True, 'error': 'personal'},
    {'code': '400', 'account': 'Office Supplies', 'desc': 'JB Hi-Fi - Personal laptop', 'contact': 'JB Hi-Fi', 'has_gst': True, 'error': 'personal'},
    {'code': '445', 'account': 'Software', 'desc': 'Netflix personal subscription', 'contact': 'Netflix', 'has_gst': True, 'error': 'personal'},

    # ERROR: Input-taxed (financial)
    {'code': '461', 'account': 'Bank Fees', 'desc': 'ANZ account fees', 'contact': 'ANZ', 'has_gst': True, 'error': 'input_taxed'},
    {'code': '461', 'account': 'Bank Fees', 'desc': 'Westpac merchant fees', 'contact': 'Westpac', 'has_gst': True, 'error': 'input_taxed'},
    {'code': '480', 'account': 'Interest Expense', 'desc': 'Business loan interest', 'contact': 'NAB', 'has_gst': True, 'error': 'input_taxed'},
    {'code': '470', 'account': 'Insurance', 'desc': 'Life insurance premium', 'contact': 'AIA', 'has_gst': True, 'error': 'input_taxed'},

    # ERROR: Overseas subscriptions
    {'code': '445', 'account': 'Software', 'desc': 'Adobe Creative Cloud - USA', 'contact': 'Adobe Inc', 'has_gst': True, 'error': 'overseas'},
    {'code': '445', 'account': 'Software', 'desc': 'Microsoft 365 - Ireland', 'contact': 'Microsoft', 'has_gst': True, 'error': 'overseas'},
    {'code': '445', 'account': 'Software', 'desc': 'Slack subscription - USA', 'contact': 'Slack', 'has_gst': True, 'error': 'overseas'},
    {'code': '445', 'account': 'Software', 'desc': 'Zoom Pro - USA', 'contact': 'Zoom', 'has_gst': True, 'error': 'overseas'},
    {'code': '445', 'account': 'Software', 'desc': 'GitHub subscription', 'contact': 'GitHub', 'has_gst': True, 'error': 'overseas'},
    {'code': '445', 'account': 'Software', 'desc': 'AWS hosting', 'contact': 'Amazon', 'has_gst': True, 'error': 'overseas'},
    {'code': '445', 'account': 'Software', 'desc': 'Shopify monthly', 'contact': 'Shopify', 'has_gst': True, 'error': 'overseas'},
    {'code': '461', 'account': 'Bank Fees', 'desc': 'PayPal transaction fees', 'contact': 'PayPal', 'has_gst': True, 'error': 'overseas'},

    # ERROR: Government charges
    {'code': '490', 'account': 'Government Charges', 'desc': 'ASIC annual fee', 'contact': 'ASIC', 'has_gst': True, 'error': 'govt'},
    {'code': '490', 'account': 'Government Charges', 'desc': 'Council rates', 'contact': 'Council', 'has_gst': True, 'error': 'govt'},
    {'code': '490', 'account': 'Government Charges', 'desc': 'Land tax', 'contact': 'Revenue Office', 'has_gst': True, 'error': 'govt'},
    {'code': '490', 'account': 'Government Charges', 'desc': 'Building permit fee', 'contact': 'Council', 'has_gst': True, 'error': 'govt'},

    # ERROR: Capital items expensed
    {'code': '400', 'account': 'Office Supplies', 'desc': 'Dell Computer workstation', 'contact': 'Dell', 'has_gst': True, 'error': 'capital', 'min_amount': 2000},
    {'code': '400', 'account': 'Office Supplies', 'desc': 'Apple MacBook Pro', 'contact': 'Apple', 'has_gst': True, 'error': 'capital', 'min_amount': 3000},
    {'code': '429', 'account': 'Repairs & Maintenance', 'desc': 'New air conditioning system', 'contact': 'AirCon Co', 'has_gst': True, 'error': 'capital', 'min_amount': 5000},
    {'code': '520', 'account': 'Tools & Equipment', 'desc': 'Power tools set', 'contact': 'Total Tools', 'has_gst': True, 'error': 'capital', 'min_amount': 1500},

    # ERROR: Wages with GST
    {'code': '477', 'account': 'Wages & Salaries', 'desc': 'Staff wages', 'contact': 'Payroll', 'has_gst': True, 'error': 'wages'},
    {'code': '478', 'account': 'Superannuation', 'desc': 'Super contribution', 'contact': 'Super Fund', 'has_gst': True, 'error': 'wages'},

    # ERROR: Donations
    {'code': '495', 'account': 'Donations', 'desc': 'Donation to Red Cross', 'contact': 'Red Cross', 'has_gst': True, 'error': 'donation'},
    {'code': '495', 'account': 'Donations', 'desc': 'Charity sponsorship', 'contact': 'Charity', 'has_gst': True, 'error': 'donation'},

    # ERROR: Fines
    {'code': '492', 'account': 'Fines & Penalties', 'desc': 'Parking fine', 'contact': 'Council', 'has_gst': True, 'error': 'fines'},
    {'code': '492', 'account': 'Fines & Penalties', 'desc': 'ATO late lodgement penalty', 'contact': 'ATO', 'has_gst': True, 'error': 'fines'},

    # ERROR: Residential rent
    {'code': '425', 'account': 'Rent', 'desc': 'Residential rent - staff housing', 'contact': 'Landlord', 'has_gst': True, 'error': 'residential'},

    # ERROR: International travel
    {'code': '430', 'account': 'Travel', 'desc': 'Qantas flight to Singapore', 'contact': 'Qantas', 'has_gst': True, 'error': 'intl_travel'},
    {'code': '430', 'account': 'Travel', 'desc': 'Overseas hotel accommodation', 'contact': 'Hotel', 'has_gst': True, 'error': 'intl_travel'},

    # ERROR: Owner drawings
    {'code': '400', 'account': 'Office Supplies', 'desc': 'Cash withdrawal - owner drawings', 'contact': 'Bank', 'has_gst': True, 'error': 'drawings'},

    # ERROR: Workers comp (stamp duty, not GST)
    {'code': '470', 'account': 'Insurance', 'desc': 'Workers compensation insurance', 'contact': 'WorkCover', 'has_gst': True, 'error': 'insurance_stamp'},
]

INCOME_TEMPLATES = [
    # CORRECT
    {'code': '200', 'account': 'Sales', 'desc': 'Consulting services', 'contact': 'Client', 'has_gst': True, 'error': None},
    {'code': '200', 'account': 'Sales', 'desc': 'Product sales', 'contact': 'Customer', 'has_gst': True, 'error': None},
    {'code': '200', 'account': 'Sales', 'desc': 'Service revenue', 'contact': 'Client', 'has_gst': True, 'error': None},

    # ERROR: Export with GST
    {'code': '200', 'account': 'Sales', 'desc': 'Export sale to NZ', 'contact': 'NZ Company', 'has_gst': True, 'error': 'export'},
    {'code': '200', 'account': 'Sales', 'desc': 'US customer order', 'contact': 'US Corp', 'has_gst': True, 'error': 'export'},

    # ERROR: GST-free income with GST
    {'code': '210', 'account': 'Other Income', 'desc': 'Grant received', 'contact': 'Government', 'has_gst': True, 'error': 'grant'},
]


def generate_random_amount(min_amt=50, max_amt=5000, is_capital=False):
    """Generate realistic transaction amount"""
    if is_capital:
        return round(random.uniform(1500, 50000), 2)
    return round(random.uniform(min_amt, max_amt), 2)


def generate_large_dataset(num_transactions=500, company_name="Test Company"):
    """Generate a large dataset with realistic distribution of errors"""
    transactions = []
    base_date = datetime(2024, 7, 1)  # Start of FY2025

    # Distribution: 70% correct, 30% errors
    error_rate = 0.30

    for i in range(num_transactions):
        # Random date within the quarter (90 days)
        days_offset = random.randint(0, 180)  # 6 months of data
        txn_date = base_date + timedelta(days=days_offset)

        # 85% expenses, 15% income
        if random.random() < 0.85:
            # Expense
            if random.random() < error_rate:
                # Pick an error transaction
                template = random.choice([t for t in EXPENSE_TEMPLATES if t['error'] is not None])
            else:
                # Pick a correct transaction
                template = random.choice([t for t in EXPENSE_TEMPLATES if t['error'] is None])

            is_capital = template.get('error') == 'capital'
            min_amt = template.get('min_amount', 50)
            gross = generate_random_amount(min_amt, 5000 if not is_capital else 50000, is_capital)

            if template['has_gst']:
                gst = round(gross / 11, 2)
                net = round(gross - gst, 2)
                gst_rate = 'GST on Expenses'
            else:
                gst = 0
                net = gross
                gst_rate = 'GST Free'

        else:
            # Income
            if random.random() < error_rate * 0.5:  # Less income errors
                template = random.choice([t for t in INCOME_TEMPLATES if t['error'] is not None])
            else:
                template = random.choice([t for t in INCOME_TEMPLATES if t['error'] is None])

            gross = -generate_random_amount(500, 20000)  # Negative for income

            if template['has_gst']:
                gst = round(gross / 11, 2)
                net = round(gross - gst, 2)
                gst_rate = 'GST on Income'
            else:
                gst = 0
                net = gross
                gst_rate = 'GST Free'

        # Add variation to descriptions
        desc_variations = ['', ' - November', ' - Monthly', ' - Q2', f' #{random.randint(1000,9999)}']
        desc = template['desc'] + random.choice(desc_variations)

        transactions.append({
            'Date': txn_date,
            'Account Code': template['code'],
            'Account': template['account'],
            'Description': desc,
            'Gross': gross,
            'GST': gst,
            'Net': net,
            'GST Rate Name': gst_rate,
            'Source': random.choice(['Bill', 'Spend Money', 'Invoice', 'Receive Money']),
            'Reference': f'REF-{i+1:05d}',
            'Contact': template['contact']
        })

    df = pd.DataFrame(transactions)
    columns = ['Date', 'Account Code', 'Account', 'Description', 'Reference',
               'Contact', 'Gross', 'GST', 'Net', 'GST Rate Name', 'Source']
    return df[columns].sort_values('Date').reset_index(drop=True)


if __name__ == '__main__':
    output_dir = '/Users/noradelsierra/xero-bas-reviewer/test_data/'
    period = 'From 1 July 2024 to 31 December 2024'

    # Generate industry-specific large files (500+ each)
    industries = [
        ('Construction', 'BuildRight Construction Pty Ltd', 550),
        ('Retail', 'Fashion Forward Retail Pty Ltd', 600),
        ('Hospitality', 'Urban Bites Cafe Pty Ltd', 700),
        ('Medical', 'HealthFirst Medical Centre', 500),
        ('RealEstate', 'Premier Property Group', 450),
        ('Transport', 'Swift Logistics Pty Ltd', 650),
        ('Legal', 'Harrison & Partners Lawyers', 500),
        ('Agriculture', 'Sunnyvale Pastoral Co', 400),
        ('IT', 'CloudTech Solutions Pty Ltd', 550),
    ]

    print("="*60)
    print("GENERATING LARGE TEST DATASETS")
    print("="*60)

    for name, company, count in industries:
        print(f"\nGenerating {name} ({count} transactions)...")
        df = generate_large_dataset(count, company)

        excel_file = f'{output_dir}Large_GL_{name}_{count}txn.xlsx'
        save_to_excel(df, excel_file, company, period)

        csv_file = f'{output_dir}Large_GL_{name}_{count}txn.csv'
        df.to_csv(csv_file, index=False)

        # Count errors
        error_count = len(df[df['Description'].str.contains('personal|Dan Murphy|BWS|PayPal|ASIC|Workers comp|donation|fine|overseas|Singapore|drawings|MacBook|Dell Computer', case=False, na=False)])
        print(f"  Saved: {excel_file}")
        print(f"  ~{error_count} potential errors")

    # Generate MEGA file (5000+ transactions)
    print("\n" + "="*60)
    print("GENERATING MEGA FILE (5000+ transactions)")
    print("="*60)

    mega_company = "MegaCorp Holdings Pty Ltd"
    mega_count = 5500

    print(f"\nGenerating mega file ({mega_count} transactions)...")
    df_mega = generate_large_dataset(mega_count, mega_company)

    mega_excel = f'{output_dir}MEGA_GL_5500txn.xlsx'
    save_to_excel(df_mega, mega_excel, mega_company, period)

    mega_csv = f'{output_dir}MEGA_GL_5500txn.csv'
    df_mega.to_csv(mega_csv, index=False)

    print(f"  Saved: {mega_excel}")

    print("\n" + "="*60)
    print("ALL FILES GENERATED!")
    print("="*60)
    print(f"\nLocation: {output_dir}")
    print("\nFiles created:")
    for name, company, count in industries:
        print(f"  - Large_GL_{name}_{count}txn.xlsx")
    print(f"  - MEGA_GL_5500txn.xlsx (stress test)")
    print("\nTotal transactions across all files:", sum(c for _,_,c in industries) + mega_count)
