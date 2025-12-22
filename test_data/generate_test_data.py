"""
Generate dummy Xero General Ledger Detail report for testing BAS Reviewer
Includes intentional GST errors across various scenarios
"""

import pandas as pd
from datetime import datetime, timedelta
import random

# Create test data with intentional errors
def generate_test_data():
    """Generate a Xero-style General Ledger Detail report with GST errors"""

    transactions = []

    # Helper to add transaction
    def add_txn(date, account_code, account_name, description, gross, gst, net,
                gst_rate="GST on Expenses", source="Bill", contact="", reference=""):
        transactions.append({
            'Date': date,
            'Account Code': account_code,
            'Account': account_name,
            'Description': description,
            'Gross': gross,
            'GST': gst,
            'Net': net,
            'GST Rate Name': gst_rate,
            'Source': source,
            'Reference': reference,
            'Contact': contact
        })

    # Base date for Q2 FY2025 (Oct-Dec 2024)
    base_date = datetime(2024, 10, 1)

    # ============ CORRECT TRANSACTIONS ============

    # Normal business expenses - correctly coded
    add_txn(base_date + timedelta(days=1), '400', 'Office Supplies',
            'Officeworks - Printer paper and ink', 165.00, 15.00, 150.00,
            'GST on Expenses', 'Bill', 'Officeworks', 'INV-001')

    add_txn(base_date + timedelta(days=3), '404', 'Telephone & Internet',
            'Telstra Business Monthly Plan', 132.00, 12.00, 120.00,
            'GST on Expenses', 'Bill', 'Telstra', 'INV-002')

    add_txn(base_date + timedelta(days=5), '412', 'Motor Vehicle Expenses',
            'BP Fuel - Company car', 88.00, 8.00, 80.00,
            'GST on Expenses', 'Spend Money', 'BP', 'REF-001')

    add_txn(base_date + timedelta(days=7), '200', 'Sales',
            'Consulting Services - ABC Corp', -2200.00, -200.00, -2000.00,
            'GST on Income', 'Invoice', 'ABC Corp', 'INV-1001')

    # ============ ERROR 1: ENTERTAINMENT/ALCOHOL - GST NOT CLAIMABLE ============

    add_txn(base_date + timedelta(days=10), '420', 'Entertainment',
            'Client dinner at The Rocks Restaurant - wine and meals',
            550.00, 50.00, 500.00,  # ERROR: Should be GST Free (no claim on entertainment)
            'GST on Expenses', 'Bill', 'The Rocks Restaurant', 'INV-003')

    add_txn(base_date + timedelta(days=15), '420', 'Entertainment',
            'Dan Murphys - Wine for client gifts',
            330.00, 30.00, 300.00,  # ERROR: Alcohol - GST not claimable
            'GST on Expenses', 'Spend Money', 'Dan Murphys', 'REF-002')

    add_txn(base_date + timedelta(days=20), '420', 'Entertainment',
            'BWS - Beer for office party',
            165.00, 15.00, 150.00,  # ERROR: Alcohol entertainment
            'GST on Expenses', 'Spend Money', 'BWS', 'REF-003')

    # ============ ERROR 2: PERSONAL EXPENSES IN BUSINESS ACCOUNT ============

    add_txn(base_date + timedelta(days=12), '404', 'Telephone & Internet',
            'Telstra personal mobile - John Smith personal',
            99.00, 9.00, 90.00,  # ERROR: Personal expense
            'GST on Expenses', 'Bill', 'Telstra', 'INV-004')

    add_txn(base_date + timedelta(days=18), '412', 'Motor Vehicle Expenses',
            'Shell fuel - personal car holiday trip',
            132.00, 12.00, 120.00,  # ERROR: Personal expense
            'GST on Expenses', 'Spend Money', 'Shell', 'REF-004')

    add_txn(base_date + timedelta(days=25), '400', 'Office Supplies',
            'JB Hi-Fi - Personal laptop for home use',
            1650.00, 150.00, 1500.00,  # ERROR: Personal expense
            'GST on Expenses', 'Bill', 'JB Hi-Fi', 'INV-005')

    # ============ ERROR 3: INPUT-TAXED SUPPLIES (FINANCIAL) - NO GST CLAIM ============

    add_txn(base_date + timedelta(days=8), '461', 'Bank Fees',
            'ANZ Bank - Monthly account fees',
            55.00, 5.00, 50.00,  # ERROR: Bank fees are input-taxed, no GST
            'GST on Expenses', 'Spend Money', 'ANZ Bank', 'REF-005')

    add_txn(base_date + timedelta(days=14), '461', 'Bank Fees',
            'Westpac - Merchant facility fees',
            110.00, 10.00, 100.00,  # ERROR: Financial service, input-taxed
            'GST on Expenses', 'Bill', 'Westpac', 'INV-006')

    add_txn(base_date + timedelta(days=22), '480', 'Interest Expense',
            'NAB Business Loan - Interest payment',
            550.00, 50.00, 500.00,  # ERROR: Interest is input-taxed
            'GST on Expenses', 'Bill', 'NAB', 'INV-007')

    # ============ ERROR 4: OVERSEAS SUBSCRIPTIONS - REVERSE CHARGE ============

    add_txn(base_date + timedelta(days=6), '445', 'Software & Subscriptions',
            'Adobe Creative Cloud Monthly - USA',
            79.99, 7.27, 72.72,  # ERROR: Overseas supplier, should be GST-free or reverse charge
            'GST on Expenses', 'Bill', 'Adobe Inc', 'INV-008')

    add_txn(base_date + timedelta(days=11), '445', 'Software & Subscriptions',
            'Microsoft 365 Business - Ireland',
            33.00, 3.00, 30.00,  # ERROR: Overseas supplier
            'GST on Expenses', 'Bill', 'Microsoft Ireland', 'INV-009')

    add_txn(base_date + timedelta(days=16), '445', 'Software & Subscriptions',
            'Slack subscription - USA',
            22.00, 2.00, 20.00,  # ERROR: Overseas supplier
            'GST on Expenses', 'Bill', 'Slack Technologies', 'INV-010')

    add_txn(base_date + timedelta(days=21), '445', 'Software & Subscriptions',
            'Zoom Pro Monthly - USA',
            25.99, 2.36, 23.63,  # ERROR: Overseas supplier
            'GST on Expenses', 'Bill', 'Zoom Video', 'INV-011')

    # ============ ERROR 5: GOVERNMENT CHARGES - NO GST ============

    add_txn(base_date + timedelta(days=9), '490', 'Government Charges',
            'ASIC Annual Company Registration Fee',
            287.00, 26.09, 260.91,  # ERROR: ASIC fees have no GST
            'GST on Expenses', 'Spend Money', 'ASIC', 'REF-006')

    add_txn(base_date + timedelta(days=17), '490', 'Government Charges',
            'Council Rates - Business premises',
            1100.00, 100.00, 1000.00,  # ERROR: Council rates have no GST
            'GST on Expenses', 'Bill', 'Brisbane City Council', 'INV-012')

    add_txn(base_date + timedelta(days=24), '490', 'Government Charges',
            'Land tax assessment',
            2200.00, 200.00, 2000.00,  # ERROR: Land tax has no GST
            'GST on Expenses', 'Bill', 'QLD Revenue Office', 'INV-013')

    # ============ ERROR 6: CAPITAL ITEMS EXPENSED ============

    add_txn(base_date + timedelta(days=4), '400', 'Office Supplies',
            'Dell Computer - New desktop workstation',
            2750.00, 250.00, 2500.00,  # ERROR: Should be capitalized as asset
            'GST on Expenses', 'Bill', 'Dell Australia', 'INV-014')

    add_txn(base_date + timedelta(days=13), '400', 'Office Supplies',
            'Apple MacBook Pro 16" M3',
            4400.00, 400.00, 4000.00,  # ERROR: Should be capitalized
            'GST on Expenses', 'Bill', 'Apple Store', 'INV-015')

    add_txn(base_date + timedelta(days=19), '429', 'Repairs & Maintenance',
            'New air conditioning system installed',
            8800.00, 800.00, 8000.00,  # ERROR: Capital improvement, not repair
            'GST on Expenses', 'Bill', 'Cool Air Services', 'INV-016')

    # ============ ERROR 7: WAGES/SALARY WITH GST ============

    add_txn(base_date + timedelta(days=30), '477', 'Wages & Salaries',
            'Staff wages - November 2024',
            5500.00, 500.00, 5000.00,  # ERROR: Wages have no GST
            'GST on Expenses', 'Spend Money', 'Payroll', 'PAY-001')

    add_txn(base_date + timedelta(days=30), '478', 'Superannuation',
            'Super contribution - November 2024',
            550.00, 50.00, 500.00,  # ERROR: Super has no GST
            'GST on Expenses', 'Spend Money', 'AustralianSuper', 'SUP-001')

    # ============ ERROR 8: INSURANCE - SOME GST-FREE ============

    add_txn(base_date + timedelta(days=2), '470', 'Insurance',
            'Workers Compensation Insurance Premium',
            1320.00, 120.00, 1200.00,  # ERROR: Workers comp often has stamp duty, not GST
            'GST on Expenses', 'Bill', 'WorkCover QLD', 'INV-017')

    add_txn(base_date + timedelta(days=23), '470', 'Insurance',
            'Life Insurance - Key Person Cover',
            880.00, 80.00, 800.00,  # ERROR: Life insurance is input-taxed
            'GST on Expenses', 'Bill', 'AIA Australia', 'INV-018')

    # ============ ERROR 9: DONATIONS - NO GST ============

    add_txn(base_date + timedelta(days=26), '495', 'Donations',
            'Donation to Red Cross Australia',
            550.00, 50.00, 500.00,  # ERROR: Donations have no GST
            'GST on Expenses', 'Spend Money', 'Red Cross', 'DON-001')

    add_txn(base_date + timedelta(days=28), '495', 'Donations',
            'Charity sponsorship - Local footy club',
            1100.00, 100.00, 1000.00,  # ERROR: Sponsorship/donation no GST
            'GST on Expenses', 'Spend Money', 'Toowong FC', 'DON-002')

    # ============ ERROR 10: GST CALCULATION ERRORS ============

    add_txn(base_date + timedelta(days=27), '400', 'Office Supplies',
            'Bunnings - Office furniture',
            500.00, 50.00, 450.00,  # ERROR: GST should be 45.45 (500/11), not 50
            'GST on Expenses', 'Spend Money', 'Bunnings', 'REF-007')

    add_txn(base_date + timedelta(days=29), '412', 'Motor Vehicle Expenses',
            'Repco - Car parts',
            220.00, 20.00, 200.00,  # ERROR: GST should be 20 (220/11=20), this is actually correct
            'GST on Expenses', 'Spend Money', 'Repco', 'REF-008')

    # ============ ERROR 11: FINES/PENALTIES - NO GST ============

    add_txn(base_date + timedelta(days=31), '492', 'Fines & Penalties',
            'Parking fine - Company vehicle',
            165.00, 15.00, 150.00,  # ERROR: Fines have no GST
            'GST on Expenses', 'Spend Money', 'Brisbane City Council', 'FINE-001')

    add_txn(base_date + timedelta(days=32), '492', 'Fines & Penalties',
            'ATO Late lodgement penalty',
            330.00, 30.00, 300.00,  # ERROR: ATO penalties have no GST
            'GST on Expenses', 'Spend Money', 'ATO', 'FINE-002')

    # ============ ERROR 12: RESIDENTIAL RENT - INPUT TAXED ============

    add_txn(base_date + timedelta(days=33), '425', 'Rent',
            'Residential property rent - staff accommodation',
            2200.00, 200.00, 2000.00,  # ERROR: Residential rent is input-taxed
            'GST on Expenses', 'Bill', 'ABC Property Management', 'INV-019')

    # ============ ERROR 13: TRAVEL - INTERNATIONAL GST-FREE ============

    add_txn(base_date + timedelta(days=34), '430', 'Travel - International',
            'Qantas flight to Singapore - business trip',
            1650.00, 150.00, 1500.00,  # ERROR: International flights are GST-free
            'GST on Expenses', 'Bill', 'Qantas', 'INV-020')

    add_txn(base_date + timedelta(days=35), '430', 'Travel - International',
            'Singapore hotel accommodation',
            990.00, 90.00, 900.00,  # ERROR: Overseas accommodation is GST-free
            'GST on Expenses', 'Bill', 'Marina Bay Sands', 'INV-021')

    # ============ ERROR 14: DRAWINGS CODED WRONG ============

    add_txn(base_date + timedelta(days=36), '400', 'Office Supplies',
            'Cash withdrawal - owner drawings',
            1000.00, 90.91, 909.09,  # ERROR: Should be in Drawings account, BAS Excluded
            'GST on Expenses', 'Spend Money', 'ANZ Bank', 'WD-001')

    # ============ MORE CORRECT TRANSACTIONS (to have a mix) ============

    add_txn(base_date + timedelta(days=37), '425', 'Rent',
            'Commercial office rent - November',
            3300.00, 300.00, 3000.00,  # CORRECT: Commercial rent has GST
            'GST on Expenses', 'Bill', 'CBD Properties', 'INV-022')

    add_txn(base_date + timedelta(days=38), '440', 'Accounting Fees',
            'BDO - Quarterly BAS preparation',
            880.00, 80.00, 800.00,  # CORRECT
            'GST on Expenses', 'Bill', 'BDO Australia', 'INV-023')

    add_txn(base_date + timedelta(days=39), '441', 'Legal Fees',
            'Holding Redlich - Contract review',
            1650.00, 150.00, 1500.00,  # CORRECT
            'GST on Expenses', 'Bill', 'Holding Redlich', 'INV-024')

    add_txn(base_date + timedelta(days=40), '200', 'Sales',
            'Product sales - XYZ Pty Ltd',
            -5500.00, -500.00, -5000.00,  # CORRECT
            'GST on Income', 'Invoice', 'XYZ Pty Ltd', 'INV-1002')

    add_txn(base_date + timedelta(days=41), '200', 'Sales',
            'Service revenue - Monthly retainer',
            -1100.00, -100.00, -1000.00,  # CORRECT
            'GST on Income', 'Invoice', 'Retainer Client', 'INV-1003')

    add_txn(base_date + timedelta(days=42), '410', 'Advertising & Marketing',
            'Google Ads - November campaign',
            550.00, 50.00, 500.00,  # Note: Google AU charges GST now
            'GST on Expenses', 'Bill', 'Google Australia', 'INV-025')

    add_txn(base_date + timedelta(days=43), '411', 'Printing & Stationery',
            'Snap Printing - Business cards',
            220.00, 20.00, 200.00,  # CORRECT
            'GST on Expenses', 'Bill', 'Snap Printing', 'INV-026')

    add_txn(base_date + timedelta(days=44), '460', 'Postage & Freight',
            'Australia Post - Parcel delivery',
            44.00, 4.00, 40.00,  # CORRECT
            'GST on Expenses', 'Spend Money', 'Australia Post', 'REF-009')

    add_txn(base_date + timedelta(days=45), '428', 'Cleaning',
            'CleanCo - Office cleaning November',
            440.00, 40.00, 400.00,  # CORRECT
            'GST on Expenses', 'Bill', 'CleanCo', 'INV-027')

    # ============ ERROR 15: PAYPAL FEES - NO GST (overseas) ============

    add_txn(base_date + timedelta(days=46), '461', 'Bank Fees',
            'PayPal transaction fees',
            55.00, 5.00, 50.00,  # ERROR: PayPal (overseas) has no GST
            'GST on Expenses', 'Spend Money', 'PayPal', 'PP-001')

    # ============ ERROR 16: MEDICAL/HEALTH - INPUT TAXED ============

    add_txn(base_date + timedelta(days=47), '479', 'Staff Amenities',
            'First aid supplies and health checks',
            330.00, 30.00, 300.00,  # Some medical supplies are GST-free
            'GST on Expenses', 'Bill', 'St John Ambulance', 'INV-028')

    # More legitimate transactions
    add_txn(base_date + timedelta(days=48), '429', 'Repairs & Maintenance',
            'Plumber - Fix office toilet',
            275.00, 25.00, 250.00,  # CORRECT
            'GST on Expenses', 'Bill', 'Jim\'s Plumbing', 'INV-029')

    add_txn(base_date + timedelta(days=49), '412', 'Motor Vehicle Expenses',
            'RACQ - Business vehicle registration',
            770.00, 70.00, 700.00,  # Part GST, part stamp duty
            'GST on Expenses', 'Bill', 'RACQ', 'INV-030')

    add_txn(base_date + timedelta(days=50), '445', 'Software & Subscriptions',
            'Xero subscription - Monthly',
            65.00, 5.91, 59.09,  # CORRECT - AU supplier
            'GST on Expenses', 'Bill', 'Xero', 'INV-031')

    # Create DataFrame
    df = pd.DataFrame(transactions)

    # Reorder columns to match Xero export format
    columns_order = ['Date', 'Account Code', 'Account', 'Description', 'Reference',
                     'Contact', 'Gross', 'GST', 'Net', 'GST Rate Name', 'Source']
    df = df[columns_order]

    return df


def save_to_excel(df, filename):
    """Save DataFrame to Excel with Xero-style formatting"""

    # Create Excel writer
    with pd.ExcelWriter(filename, engine='openpyxl') as writer:
        # Add header rows like Xero export
        header_df = pd.DataFrame({
            'Date': ['General Ledger Detail', 'Demo Company (AU)',
                    'From 1 October 2024 to 31 December 2024', ''],
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

        # Write header
        header_df.to_excel(writer, sheet_name='General Ledger Detail',
                          index=False, header=False, startrow=0)

        # Write data with headers
        df.to_excel(writer, sheet_name='General Ledger Detail',
                   index=False, startrow=5)

    print(f"Saved to {filename}")


if __name__ == '__main__':
    print("Generating test data with intentional GST errors...")
    df = generate_test_data()

    # Save to Excel
    save_to_excel(df, '/Users/noradelsierra/xero-bas-reviewer/test_data/Test_GL_Detail_Q2_FY2025.xlsx')

    # Also save a CSV for easy viewing
    df.to_csv('/Users/noradelsierra/xero-bas-reviewer/test_data/Test_GL_Detail_Q2_FY2025.csv', index=False)

    print(f"\nGenerated {len(df)} transactions")
    print("\nError types included:")
    print("1. Entertainment/Alcohol - GST claimed incorrectly")
    print("2. Personal expenses in business accounts")
    print("3. Input-taxed supplies (bank fees, interest)")
    print("4. Overseas subscriptions with GST")
    print("5. Government charges with GST")
    print("6. Capital items expensed")
    print("7. Wages/salary with GST")
    print("8. Insurance GST issues")
    print("9. Donations with GST")
    print("10. GST calculation errors")
    print("11. Fines/penalties with GST")
    print("12. Residential rent with GST")
    print("13. International travel with GST")
    print("14. Owner drawings coded incorrectly")
    print("15. PayPal fees with GST")
    print("16. Medical supplies GST issues")
