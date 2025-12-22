"""
Generate industry-specific Xero General Ledger Detail reports for testing BAS Reviewer
Each industry has realistic transactions with common GST errors for that sector
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


# ==================== CONSTRUCTION / TRADES ====================
def generate_construction_data():
    """Construction company with subcontractors, materials, equipment"""
    transactions = []
    base_date = datetime(2024, 10, 1)

    def add(days, code, account, desc, gross, gst, net, rate='GST on Expenses',
            source='Bill', contact='', ref=''):
        transactions.append({
            'Date': base_date + timedelta(days=days),
            'Account Code': code, 'Account': account, 'Description': desc,
            'Gross': gross, 'GST': gst, 'Net': net, 'GST Rate Name': rate,
            'Source': source, 'Reference': ref, 'Contact': contact
        })

    # CORRECT transactions
    add(1, '500', 'Materials', 'Bunnings - Timber and screws', 1650.00, 150.00, 1500.00,
        contact='Bunnings', ref='INV-001')
    add(3, '500', 'Materials', 'Reece Plumbing - Pipes and fittings', 880.00, 80.00, 800.00,
        contact='Reece', ref='INV-002')
    add(5, '200', 'Construction Revenue', 'Progress claim #3 - Smith Residence',
        -33000.00, -3000.00, -30000.00, 'GST on Income', 'Invoice', 'Smith Family', 'INV-1001')

    # ERROR: Subcontractor without ABN - should withhold tax
    add(7, '510', 'Subcontractors', 'Cash payment to labourer - no ABN provided',
        2200.00, 200.00, 2000.00, contact='John Cash Worker', ref='PAY-001')

    # ERROR: Tools/Equipment over $1000 expensed (should capitalize)
    add(9, '520', 'Tools & Equipment', 'Total Tools - Hilti Hammer Drill',
        1980.00, 180.00, 1800.00, contact='Total Tools', ref='INV-003')
    add(11, '520', 'Tools & Equipment', 'Sydney Tools - Makita Table Saw',
        2750.00, 250.00, 2500.00, contact='Sydney Tools', ref='INV-004')

    # ERROR: Private use vehicle expenses
    add(13, '530', 'Vehicle Expenses', 'Fuel - Ute used 50% private (full claim)',
        330.00, 30.00, 300.00, 'Spend Money', 'BP', ref='REF-001')

    # ERROR: Entertainment for staff (Friday beers)
    add(15, '540', 'Staff Amenities', 'Dan Murphys - Friday drinks for crew',
        275.00, 25.00, 250.00, contact='Dan Murphys', ref='REF-002')

    # ERROR: Safety gear for worker's personal use at home
    add(17, '550', 'Safety Equipment', 'RSEA - Personal boots for worker (not site use)',
        330.00, 30.00, 300.00, contact='RSEA Safety', ref='INV-005')

    # ERROR: Building permit fees (no GST)
    add(19, '560', 'Permits & Licenses', 'Council building permit fee',
        1650.00, 150.00, 1500.00, contact='Brisbane City Council', ref='PERMIT-001')

    # ERROR: QBCC License renewal (no GST on govt)
    add(21, '560', 'Permits & Licenses', 'QBCC Builder license renewal',
        1452.00, 132.00, 1320.00, contact='QBCC', ref='LIC-001')

    # ERROR: Workers comp insurance (stamp duty, not GST)
    add(23, '570', 'Insurance', 'iCare Workers Compensation premium',
        4400.00, 400.00, 4000.00, contact='iCare NSW', ref='INV-006')

    # ERROR: Home building insurance (input-taxed component)
    add(25, '570', 'Insurance', 'CGU - Construction All Risk policy',
        2200.00, 200.00, 2000.00, contact='CGU Insurance', ref='INV-007')

    # CORRECT: Hire equipment
    add(27, '580', 'Equipment Hire', 'Kennards Hire - Excavator 3 days',
        1320.00, 120.00, 1200.00, contact='Kennards', ref='INV-008')

    # ERROR: Penalty for late completion (no GST)
    add(29, '590', 'Other Expenses', 'Liquidated damages - Project delay penalty',
        5500.00, 500.00, 5000.00, contact='Developer Co', ref='PEN-001')

    # ERROR: Overseas steel supplier (no AU GST)
    add(31, '500', 'Materials', 'China Steel Direct - Structural steel',
        11000.00, 1000.00, 10000.00, contact='China Steel Direct', ref='IMP-001')

    # CORRECT transactions
    add(33, '510', 'Subcontractors', 'ABC Electrical - Rough in wiring',
        3850.00, 350.00, 3500.00, contact='ABC Electrical', ref='INV-009')
    add(35, '510', 'Subcontractors', 'Pro Plumbing - Bathroom fitout',
        4400.00, 400.00, 4000.00, contact='Pro Plumbing', ref='INV-010')
    add(37, '200', 'Construction Revenue', 'Final payment - Jones Renovation',
        -22000.00, -2000.00, -20000.00, 'GST on Income', 'Invoice', 'Jones', 'INV-1002')

    # ERROR: Donation to local footy club
    add(39, '595', 'Donations & Sponsorship', 'Sponsorship - Local junior footy',
        550.00, 50.00, 500.00, contact='Southside FC', ref='DON-001')

    # ERROR: Fine for unsafe worksite
    add(41, '590', 'Other Expenses', 'SafeWork NSW - Worksite safety fine',
        3300.00, 300.00, 3000.00, contact='SafeWork NSW', ref='FINE-001')

    df = pd.DataFrame(transactions)
    columns = ['Date', 'Account Code', 'Account', 'Description', 'Reference',
               'Contact', 'Gross', 'GST', 'Net', 'GST Rate Name', 'Source']
    return df[columns]


# ==================== RETAIL / E-COMMERCE ====================
def generate_retail_data():
    """Retail store with inventory, POS, online sales"""
    transactions = []
    base_date = datetime(2024, 10, 1)

    def add(days, code, account, desc, gross, gst, net, rate='GST on Expenses',
            source='Bill', contact='', ref=''):
        transactions.append({
            'Date': base_date + timedelta(days=days),
            'Account Code': code, 'Account': account, 'Description': desc,
            'Gross': gross, 'GST': gst, 'Net': net, 'GST Rate Name': rate,
            'Source': source, 'Reference': ref, 'Contact': contact
        })

    # CORRECT: Inventory purchases
    add(1, '500', 'Inventory Purchases', 'Wholesale supplier - Clothing stock',
        11000.00, 1000.00, 10000.00, contact='Fashion Wholesale', ref='PO-001')
    add(3, '500', 'Inventory Purchases', 'Accessories supplier - Jewellery',
        3300.00, 300.00, 3000.00, contact='Accessory World', ref='PO-002')

    # CORRECT: Sales
    add(5, '200', 'Sales Revenue', 'Daily POS sales - Week 1',
        -8800.00, -800.00, -8000.00, 'GST on Income', 'Invoice', 'Cash Sales', 'POS-W1')
    add(12, '200', 'Sales Revenue', 'Daily POS sales - Week 2',
        -9350.00, -850.00, -8500.00, 'GST on Income', 'Invoice', 'Cash Sales', 'POS-W2')

    # ERROR: Shopify fees (overseas - no GST)
    add(7, '610', 'Merchant Fees', 'Shopify monthly subscription - Canada',
        79.00, 7.18, 71.82, contact='Shopify', ref='SHOP-001')

    # ERROR: PayPal fees (overseas - no GST)
    add(9, '610', 'Merchant Fees', 'PayPal transaction fees',
        165.00, 15.00, 150.00, contact='PayPal', ref='PP-001')

    # CORRECT: Stripe fees (AU entity)
    add(11, '610', 'Merchant Fees', 'Stripe AU processing fees',
        220.00, 20.00, 200.00, contact='Stripe AU', ref='STR-001')

    # ERROR: Gift cards sold (no GST until redemption)
    add(13, '200', 'Sales Revenue', 'Gift card sales - November',
        -1100.00, -100.00, -1000.00, 'GST on Income', 'Invoice', 'Various', 'GC-NOV')

    # ERROR: Staff purchases at cost (FBT issue, personal benefit)
    add(15, '620', 'Staff Discounts', 'Staff purchase - Designer handbag at cost',
        550.00, 50.00, 500.00, contact='Employee Sarah', ref='STAFF-001')

    # ERROR: Store fitout (should be capitalized)
    add(17, '630', 'Shop Expenses', 'New shelving and display units',
        8800.00, 800.00, 8000.00, contact='Retail Fitouts', ref='INV-001')

    # ERROR: Overseas inventory (import - customs, no supplier GST)
    add(19, '500', 'Inventory Purchases', 'Alibaba supplier - Phone cases bulk',
        5500.00, 500.00, 5000.00, contact='Shenzhen Trading', ref='IMP-001')

    # ERROR: Mannequins expensed (asset > $1000)
    add(21, '630', 'Shop Expenses', 'Display mannequins x 6',
        1980.00, 180.00, 1800.00, contact='Retail Display Co', ref='INV-002')

    # ERROR: eBay fees (GST only on AU portion)
    add(23, '610', 'Merchant Fees', 'eBay seller fees',
        440.00, 40.00, 400.00, contact='eBay', ref='EBAY-001')

    # ERROR: Amazon AU referral fees
    add(25, '610', 'Merchant Fees', 'Amazon AU referral fees',
        330.00, 30.00, 300.00, contact='Amazon AU', ref='AMZ-001')

    # ERROR: Influencer payment (should be contractor, need ABN)
    add(27, '640', 'Marketing', 'Instagram influencer - Product promotion',
        1100.00, 100.00, 1000.00, contact='@fashionista_au', ref='INF-001')

    # CORRECT: Local advertising
    add(29, '640', 'Marketing', 'Facebook Ads - November campaign',
        550.00, 50.00, 500.00, contact='Meta AU', ref='FB-001')

    # ERROR: Charity raffle prizes (donation, no GST)
    add(31, '650', 'Donations', 'Donation - Products for charity auction',
        330.00, 30.00, 300.00, contact='Cancer Council', ref='DON-001')

    # ERROR: Theft/shrinkage written off with GST
    add(33, '660', 'Stock Adjustments', 'Inventory shrinkage - shoplifting',
        770.00, 70.00, 700.00, contact='Internal', ref='ADJ-001')

    # CORRECT: Packaging supplies
    add(35, '670', 'Packaging', 'Boxes, tissue paper, bags',
        440.00, 40.00, 400.00, contact='PackQuip', ref='INV-003')

    # ERROR: Export sale with GST (should be GST-free)
    add(37, '200', 'Sales Revenue', 'Export order - NZ customer',
        -2200.00, -200.00, -2000.00, 'GST on Income', 'Invoice', 'NZ Fashion Ltd', 'EXP-001')

    # CORRECT: Rent
    add(39, '680', 'Rent', 'Shop rent - November',
        4400.00, 400.00, 4000.00, contact='Westfield', ref='RENT-NOV')

    # ERROR: Security deposit (not expense, should be asset)
    add(41, '680', 'Rent', 'Bond/security deposit - new location',
        8800.00, 800.00, 8000.00, contact='New Landlord', ref='BOND-001')

    df = pd.DataFrame(transactions)
    columns = ['Date', 'Account Code', 'Account', 'Description', 'Reference',
               'Contact', 'Gross', 'GST', 'Net', 'GST Rate Name', 'Source']
    return df[columns]


# ==================== HOSPITALITY (RESTAURANT/CAFE) ====================
def generate_hospitality_data():
    """Restaurant/Cafe with food, beverages, staff meals"""
    transactions = []
    base_date = datetime(2024, 10, 1)

    def add(days, code, account, desc, gross, gst, net, rate='GST on Expenses',
            source='Bill', contact='', ref=''):
        transactions.append({
            'Date': base_date + timedelta(days=days),
            'Account Code': code, 'Account': account, 'Description': desc,
            'Gross': gross, 'GST': gst, 'Net': net, 'GST Rate Name': rate,
            'Source': source, 'Reference': ref, 'Contact': contact
        })

    # CORRECT: Food supplies (GST-free fresh food vs processed)
    add(1, '700', 'Food Supplies', 'Fresh produce - Vegetables and fruit',
        1100.00, 0.00, 1100.00, 'GST Free', 'Bill', 'Fresh Direct', 'INV-001')
    add(3, '700', 'Food Supplies', 'Meat and seafood - Fresh',
        2200.00, 0.00, 2200.00, 'GST Free', 'Bill', 'Meat Wholesaler', 'INV-002')

    # CORRECT: Processed food (has GST)
    add(5, '700', 'Food Supplies', 'Sauces, condiments, processed items',
        550.00, 50.00, 500.00, contact='Bidfood', ref='INV-003')

    # ERROR: Fresh food coded with GST
    add(7, '700', 'Food Supplies', 'Harris Farm - Fresh salad ingredients',
        330.00, 30.00, 300.00, contact='Harris Farm', ref='INV-004')

    # ERROR: Milk coded with GST (fresh milk is GST-free)
    add(9, '710', 'Beverages', 'Fresh milk for coffee',
        220.00, 20.00, 200.00, contact='Dairy Farmers', ref='INV-005')

    # CORRECT: Soft drinks and juices (processed - GST applies)
    add(11, '710', 'Beverages', 'Coca-Cola, juices, soft drinks',
        660.00, 60.00, 600.00, contact='CCA', ref='INV-006')

    # CORRECT: Alcohol purchases
    add(13, '720', 'Alcohol - Bar', 'Wine and spirits for bar',
        3300.00, 300.00, 3000.00, contact='ALM', ref='INV-007')
    add(15, '720', 'Alcohol - Bar', 'Beer kegs - Carlton Draught',
        1100.00, 100.00, 1000.00, contact='CUB', ref='INV-008')

    # CORRECT: Sales
    add(17, '200', 'Food Sales', 'Daily takings - Week 1',
        -15400.00, -1400.00, -14000.00, 'GST on Income', 'Invoice', 'POS', 'SALES-W1')
    add(24, '200', 'Food Sales', 'Daily takings - Week 2',
        -16500.00, -1500.00, -15000.00, 'GST on Income', 'Invoice', 'POS', 'SALES-W2')

    # ERROR: Staff meals (FBT exempt but often miscoded)
    add(19, '730', 'Staff Meals', 'Staff meals - claiming full GST',
        550.00, 50.00, 500.00, contact='Internal', ref='STF-001')

    # ERROR: Owner meals coded as business expense
    add(21, '700', 'Food Supplies', 'Owner family dinner - personal',
        220.00, 20.00, 200.00, contact='Internal', ref='OWN-001')

    # ERROR: Coffee machine (should be capitalized)
    add(23, '740', 'Kitchen Equipment', 'La Marzocco Espresso Machine',
        16500.00, 1500.00, 15000.00, contact='Coffee Equipment Co', ref='INV-009')

    # ERROR: Commercial refrigerator expensed
    add(25, '740', 'Kitchen Equipment', 'Walk-in cool room installation',
        22000.00, 2000.00, 20000.00, contact='Refrigeration Services', ref='INV-010')

    # ERROR: Health inspection fees (no GST - govt)
    add(27, '750', 'Licenses & Permits', 'Food safety inspection fee',
        385.00, 35.00, 350.00, contact='Council', ref='INSP-001')

    # ERROR: Liquor license (govt fee - no GST)
    add(29, '750', 'Licenses & Permits', 'Liquor license renewal',
        1100.00, 100.00, 1000.00, contact='Liquor & Gaming NSW', ref='LIC-001')

    # ERROR: Music license (overseas - APRA some parts)
    add(31, '760', 'Entertainment', 'Spotify Business subscription',
        33.00, 3.00, 30.00, contact='Spotify', ref='MUS-001')

    # CORRECT: Cleaning supplies
    add(33, '770', 'Cleaning', 'Commercial cleaning supplies',
        330.00, 30.00, 300.00, contact='CleanCo', ref='INV-011')

    # ERROR: Uber Eats commission (platform fees)
    add(35, '780', 'Delivery Fees', 'Uber Eats commission - November',
        1650.00, 150.00, 1500.00, contact='Uber Eats', ref='UE-NOV')

    # ERROR: DoorDash fees
    add(37, '780', 'Delivery Fees', 'DoorDash commission',
        990.00, 90.00, 900.00, contact='DoorDash', ref='DD-NOV')

    # ERROR: Tips paid out (not expense, liability)
    add(39, '790', 'Wages', 'Tips paid to staff',
        880.00, 80.00, 800.00, contact='Staff', ref='TIPS-001')

    # ERROR: Wages with GST
    add(41, '790', 'Wages', 'Casual staff wages - November',
        8800.00, 800.00, 8000.00, contact='Payroll', ref='PAY-NOV')

    # ERROR: Superannuation with GST
    add(43, '791', 'Superannuation', 'Super contributions',
        836.00, 76.00, 760.00, contact='REST Super', ref='SUP-NOV')

    # CORRECT: Accounting fees
    add(45, '800', 'Professional Fees', 'Monthly bookkeeping',
        550.00, 50.00, 500.00, contact='BAS Agent', ref='ACC-NOV')

    # ERROR: Food donation (no GST on donation)
    add(47, '810', 'Donations', 'Food donation to OzHarvest',
        440.00, 40.00, 400.00, contact='OzHarvest', ref='DON-001')

    df = pd.DataFrame(transactions)
    columns = ['Date', 'Account Code', 'Account', 'Description', 'Reference',
               'Contact', 'Gross', 'GST', 'Net', 'GST Rate Name', 'Source']
    return df[columns]


# ==================== MEDICAL / HEALTHCARE ====================
def generate_medical_data():
    """Medical practice with GST-free health services"""
    transactions = []
    base_date = datetime(2024, 10, 1)

    def add(days, code, account, desc, gross, gst, net, rate='GST on Expenses',
            source='Bill', contact='', ref=''):
        transactions.append({
            'Date': base_date + timedelta(days=days),
            'Account Code': code, 'Account': account, 'Description': desc,
            'Gross': gross, 'GST': gst, 'Net': net, 'GST Rate Name': rate,
            'Source': source, 'Reference': ref, 'Contact': contact
        })

    # CORRECT: Medical revenue (GST-free)
    add(1, '200', 'Medical Consultations', 'Patient consultations - Week 1',
        -8500.00, 0.00, -8500.00, 'GST Free', 'Invoice', 'Patients', 'MED-W1')
    add(8, '200', 'Medical Consultations', 'Patient consultations - Week 2',
        -9200.00, 0.00, -9200.00, 'GST Free', 'Invoice', 'Patients', 'MED-W2')

    # ERROR: Medical consultation coded with GST
    add(15, '200', 'Medical Consultations', 'Specialist referral consultations',
        -3300.00, -300.00, -3000.00, 'GST on Income', 'Invoice', 'Patients', 'SPEC-001')

    # CORRECT: Non-medical services (cosmetic - taxable)
    add(3, '210', 'Cosmetic Services', 'Botox treatments',
        -2200.00, -200.00, -2000.00, 'GST on Income', 'Invoice', 'Patients', 'COS-001')

    # ERROR: Cosmetic coded as GST-free
    add(5, '210', 'Cosmetic Services', 'Dermal fillers',
        -1650.00, 0.00, -1650.00, 'GST Free', 'Invoice', 'Patients', 'COS-002')

    # CORRECT: Medical supplies (GST-free)
    add(7, '300', 'Medical Supplies', 'Syringes, bandages, medical consumables',
        1100.00, 0.00, 1100.00, 'GST Free', 'Bill', 'Medical Supplies Co', 'INV-001')

    # ERROR: Medical supplies coded with GST
    add(9, '300', 'Medical Supplies', 'Surgical gloves and masks',
        330.00, 30.00, 300.00, contact='Medshop', ref='INV-002')

    # ERROR: Prescription medicines (GST-free) coded with GST
    add(11, '310', 'Pharmaceuticals', 'Prescription medications for practice',
        880.00, 80.00, 800.00, contact='Pharmacy Wholesaler', ref='INV-003')

    # CORRECT: Office supplies (taxable)
    add(13, '400', 'Office Supplies', 'Printer paper, pens, folders',
        165.00, 15.00, 150.00, contact='Officeworks', ref='INV-004')

    # ERROR: Medical equipment expensed (should capitalize)
    add(17, '320', 'Medical Equipment', 'ECG Machine',
        8800.00, 800.00, 8000.00, contact='Medical Devices AU', ref='INV-005')

    # ERROR: Ultrasound machine expensed
    add(19, '320', 'Medical Equipment', 'Portable Ultrasound',
        33000.00, 3000.00, 30000.00, contact='GE Healthcare', ref='INV-006')

    # ERROR: AHPRA registration (no GST - govt)
    add(21, '410', 'Professional Registration', 'AHPRA Medical Registration',
        892.00, 81.09, 810.91, contact='AHPRA', ref='REG-001')

    # ERROR: Medical indemnity insurance (input-taxed)
    add(23, '420', 'Insurance', 'Medical indemnity insurance',
        5500.00, 500.00, 5000.00, contact='MDA National', ref='INS-001')

    # ERROR: Life insurance for key person
    add(25, '420', 'Insurance', 'Income protection insurance - Dr Smith',
        2200.00, 200.00, 2000.00, contact='TAL', ref='INS-002')

    # CORRECT: Practice rent
    add(27, '430', 'Rent', 'Medical suite rent - November',
        5500.00, 500.00, 5000.00, contact='Medical Centre', ref='RENT-NOV')

    # ERROR: Residential rent for locum (input-taxed)
    add(29, '430', 'Rent', 'Apartment for visiting specialist',
        2200.00, 200.00, 2000.00, contact='Airbnb Host', ref='LOCUM-001')

    # ERROR: CPD course (educational - often GST-free)
    add(31, '440', 'Training & CPD', 'Medical conference registration',
        1650.00, 150.00, 1500.00, contact='RACGP', ref='CPD-001')

    # ERROR: Medicare rebate coded wrong
    add(33, '220', 'Medicare Rebates', 'Medicare bulk billing receipts',
        -4400.00, -400.00, -4000.00, 'GST on Income', 'Receive Money', 'Medicare', 'MBS-001')

    # CORRECT: Pathology services (taxable)
    add(35, '500', 'Pathology Costs', 'External pathology tests',
        550.00, 50.00, 500.00, contact='QML Pathology', ref='PATH-001')

    # ERROR: Charitable donation
    add(37, '450', 'Donations', 'Donation to Heart Foundation',
        550.00, 50.00, 500.00, contact='Heart Foundation', ref='DON-001')

    # CORRECT: Cleaning services
    add(39, '460', 'Cleaning', 'Medical practice cleaning',
        440.00, 40.00, 400.00, contact='HealthClean', ref='CLN-NOV')

    # ERROR: Wages with GST
    add(41, '470', 'Wages', 'Receptionist wages',
        4400.00, 400.00, 4000.00, contact='Payroll', ref='PAY-NOV')

    df = pd.DataFrame(transactions)
    columns = ['Date', 'Account Code', 'Account', 'Description', 'Reference',
               'Contact', 'Gross', 'GST', 'Net', 'GST Rate Name', 'Source']
    return df[columns]


# ==================== REAL ESTATE ====================
def generate_real_estate_data():
    """Real estate agency with commissions, property management"""
    transactions = []
    base_date = datetime(2024, 10, 1)

    def add(days, code, account, desc, gross, gst, net, rate='GST on Expenses',
            source='Bill', contact='', ref=''):
        transactions.append({
            'Date': base_date + timedelta(days=days),
            'Account Code': code, 'Account': account, 'Description': desc,
            'Gross': gross, 'GST': gst, 'Net': net, 'GST Rate Name': rate,
            'Source': source, 'Reference': ref, 'Contact': contact
        })

    # CORRECT: Sales commissions (taxable)
    add(1, '200', 'Sales Commission', 'Commission - 42 Smith St sale',
        -22000.00, -2000.00, -20000.00, 'GST on Income', 'Invoice', 'Vendor', 'COM-001')
    add(5, '200', 'Sales Commission', 'Commission - Unit 5/10 Beach Rd',
        -16500.00, -1500.00, -15000.00, 'GST on Income', 'Invoice', 'Vendor', 'COM-002')

    # CORRECT: Property management fees
    add(3, '210', 'Property Management', 'Management fees - November',
        -4400.00, -400.00, -4000.00, 'GST on Income', 'Invoice', 'Landlords', 'PM-NOV')

    # ERROR: Residential rent collected (input-taxed, not taxable)
    add(7, '220', 'Rent Collected', 'Tenant rent - 15 Park Ave (residential)',
        -2200.00, -200.00, -2000.00, 'GST on Income', 'Receive Money', 'Tenant', 'RENT-001')

    # ERROR: Residential letting fee with GST (should match property type)
    add(9, '230', 'Letting Fees', 'Letting fee - residential property',
        -1100.00, -100.00, -1000.00, 'GST on Income', 'Invoice', 'Landlord', 'LET-001')

    # CORRECT: Commercial letting (taxable)
    add(11, '230', 'Letting Fees', 'Letting fee - commercial shop',
        -1650.00, -150.00, -1500.00, 'GST on Income', 'Invoice', 'Landlord', 'LET-002')

    # ERROR: Realestate.com.au listing (GST applies)
    add(13, '300', 'Advertising', 'REA listing upgrade',
        1320.00, 120.00, 1200.00, contact='REA Group', ref='REA-001')

    # ERROR: Domain listing
    add(15, '300', 'Advertising', 'Domain premium listing',
        880.00, 80.00, 800.00, contact='Domain', ref='DOM-001')

    # ERROR: Overseas property portal (no GST)
    add(17, '300', 'Advertising', 'Juwai.com - Chinese buyer listing',
        550.00, 50.00, 500.00, contact='Juwai', ref='JUW-001')

    # ERROR: Agent license renewal (no GST - govt)
    add(19, '310', 'Licenses', 'Real Estate Agent license renewal',
        495.00, 45.00, 450.00, contact='Fair Trading NSW', ref='LIC-001')

    # ERROR: Professional indemnity (part input-taxed)
    add(21, '320', 'Insurance', 'PI Insurance - Real Estate',
        3300.00, 300.00, 3000.00, contact='Realcover', ref='INS-001')

    # CORRECT: Office rent
    add(23, '330', 'Rent', 'Office rent - November',
        3300.00, 300.00, 3000.00, contact='Landlord', ref='RENT-NOV')

    # ERROR: Home office (private residence)
    add(25, '330', 'Rent', 'Home office allowance - Principal',
        550.00, 50.00, 500.00, contact='Principal', ref='HO-001')

    # ERROR: Strata report fee (often GST-free component)
    add(27, '340', 'Property Reports', 'Strata inspection report',
        385.00, 35.00, 350.00, contact='Strata Reports', ref='STR-001')

    # CORRECT: Building inspection
    add(29, '340', 'Property Reports', 'Building and pest inspection',
        550.00, 50.00, 500.00, contact='Inspector Co', ref='BPI-001')

    # ERROR: Trust account interest (input-taxed)
    add(31, '400', 'Interest Income', 'Trust account interest',
        -110.00, -10.00, -100.00, 'GST on Income', 'Receive Money', 'Bank', 'INT-001')

    # ERROR: Bank fees (input-taxed)
    add(33, '350', 'Bank Fees', 'Trust account fees',
        55.00, 5.00, 50.00, contact='ANZ', ref='BNK-001')

    # ERROR: Auction costs paid on behalf (should be reimbursement)
    add(35, '300', 'Advertising', 'Auctioneer fee - passed to vendor',
        1650.00, 150.00, 1500.00, contact='Auctioneer', ref='AUC-001')

    # ERROR: Signboard expensed (could be asset if reusable)
    add(37, '300', 'Advertising', 'For Sale signboards x 10',
        1100.00, 100.00, 1000.00, contact='Signage Co', ref='SIGN-001')

    # CORRECT: Car expenses
    add(39, '360', 'Motor Vehicle', 'Fuel for property inspections',
        220.00, 20.00, 200.00, 'Spend Money', 'BP', ref='FUEL-001')

    # ERROR: Personal car expenses
    add(41, '360', 'Motor Vehicle', 'Personal car service',
        550.00, 50.00, 500.00, contact='Mechanic', ref='CAR-001')

    # ERROR: FIRB application fee (no GST)
    add(43, '370', 'Government Fees', 'FIRB application - foreign buyer',
        14300.00, 1300.00, 13000.00, contact='ATO FIRB', ref='FIRB-001')

    df = pd.DataFrame(transactions)
    columns = ['Date', 'Account Code', 'Account', 'Description', 'Reference',
               'Contact', 'Gross', 'GST', 'Net', 'GST Rate Name', 'Source']
    return df[columns]


# ==================== TRANSPORT / LOGISTICS ====================
def generate_transport_data():
    """Trucking/courier company"""
    transactions = []
    base_date = datetime(2024, 10, 1)

    def add(days, code, account, desc, gross, gst, net, rate='GST on Expenses',
            source='Bill', contact='', ref=''):
        transactions.append({
            'Date': base_date + timedelta(days=days),
            'Account Code': code, 'Account': account, 'Description': desc,
            'Gross': gross, 'GST': gst, 'Net': net, 'GST Rate Name': rate,
            'Source': source, 'Reference': ref, 'Contact': contact
        })

    # CORRECT: Freight revenue
    add(1, '200', 'Freight Revenue', 'Delivery services - Week 1',
        -11000.00, -1000.00, -10000.00, 'GST on Income', 'Invoice', 'Various', 'FRT-W1')
    add(8, '200', 'Freight Revenue', 'Delivery services - Week 2',
        -12100.00, -1100.00, -11000.00, 'GST on Income', 'Invoice', 'Various', 'FRT-W2')

    # ERROR: International freight (export - GST-free)
    add(3, '200', 'Freight Revenue', 'Export freight to NZ',
        -3300.00, -300.00, -3000.00, 'GST on Income', 'Invoice', 'NZ Import Co', 'EXP-001')

    # CORRECT: Fuel purchases
    add(5, '300', 'Fuel', 'Diesel - Fleet refuel',
        5500.00, 500.00, 5000.00, contact='BP Fleet', ref='FUEL-001')
    add(12, '300', 'Fuel', 'Diesel - November week 2',
        4950.00, 450.00, 4500.00, contact='Caltex', ref='FUEL-002')

    # ERROR: Fuel tax credit not considered (reduces GST claim)
    add(19, '300', 'Fuel', 'Diesel for heavy vehicles - FTC eligible',
        6600.00, 600.00, 6000.00, contact='Shell', ref='FUEL-003')

    # ERROR: Rego fees (stamp duty component, not all GST)
    add(7, '310', 'Registration', 'Truck registration renewal',
        2200.00, 200.00, 2000.00, contact='RMS NSW', ref='REGO-001')

    # ERROR: Heavy vehicle charges (no GST)
    add(9, '310', 'Registration', 'NHVR registration charges',
        1650.00, 150.00, 1500.00, contact='NHVR', ref='NHVR-001')

    # ERROR: Road tolls (some no GST)
    add(11, '320', 'Tolls', 'Linkt toll charges - November',
        880.00, 80.00, 800.00, contact='Linkt', ref='TOLL-001')

    # CORRECT: Truck repairs
    add(13, '330', 'Repairs & Maintenance', 'Truck service - Isuzu',
        1320.00, 120.00, 1200.00, contact='Isuzu Trucks', ref='REP-001')

    # ERROR: New truck expensed (should be asset)
    add(15, '330', 'Repairs & Maintenance', 'New delivery van purchase',
        44000.00, 4000.00, 40000.00, contact='Dealer', ref='VEH-001')

    # ERROR: Insurance - CTP (stamp duty, not GST)
    add(17, '340', 'Insurance', 'CTP Green Slip',
        1100.00, 100.00, 1000.00, contact='NRMA', ref='CTP-001')

    # CORRECT: Comprehensive insurance
    add(21, '340', 'Insurance', 'Fleet comprehensive insurance',
        3300.00, 300.00, 3000.00, contact='NTI', ref='INS-001')

    # ERROR: Parking fines (no GST)
    add(23, '350', 'Fines', 'Parking infringement - Driver',
        275.00, 25.00, 250.00, contact='Council', ref='FINE-001')

    # ERROR: Speeding fine
    add(25, '350', 'Fines', 'Speeding fine - Company vehicle',
        495.00, 45.00, 450.00, contact='Revenue NSW', ref='FINE-002')

    # ERROR: Driver wages with GST
    add(27, '360', 'Wages', 'Driver wages - November',
        11000.00, 1000.00, 10000.00, contact='Payroll', ref='PAY-NOV')

    # ERROR: Subcontractor without ABN
    add(29, '370', 'Subcontractors', 'Casual driver - no ABN',
        1650.00, 150.00, 1500.00, contact='John Driver', ref='SUB-001')

    # CORRECT: Licensed subcontractor
    add(31, '370', 'Subcontractors', 'ABC Couriers - overflow work',
        2200.00, 200.00, 2000.00, contact='ABC Couriers', ref='SUB-002')

    # ERROR: GPS tracking (overseas provider)
    add(33, '380', 'Technology', 'Fleet GPS subscription - USA',
        165.00, 15.00, 150.00, contact='Samsara', ref='GPS-001')

    # CORRECT: Local software
    add(35, '380', 'Technology', 'Dispatch software - AU',
        330.00, 30.00, 300.00, contact='DeliverEase', ref='SOFT-001')

    # ERROR: Work boots for driver (personal)
    add(37, '390', 'Uniforms', 'Steel cap boots - taken home',
        220.00, 20.00, 200.00, contact='RSEA', ref='UNI-001')

    # CORRECT: Company uniforms
    add(39, '390', 'Uniforms', 'Branded polo shirts',
        440.00, 40.00, 400.00, contact='Embroidery Co', ref='UNI-002')

    # ERROR: Pallet storage overseas
    add(41, '400', 'Storage', 'Auckland warehouse storage',
        1100.00, 100.00, 1000.00, contact='NZ Logistics', ref='STOR-001')

    df = pd.DataFrame(transactions)
    columns = ['Date', 'Account Code', 'Account', 'Description', 'Reference',
               'Contact', 'Gross', 'GST', 'Net', 'GST Rate Name', 'Source']
    return df[columns]


# ==================== PROFESSIONAL SERVICES (LAW FIRM) ====================
def generate_legal_data():
    """Law firm with trust accounts, disbursements"""
    transactions = []
    base_date = datetime(2024, 10, 1)

    def add(days, code, account, desc, gross, gst, net, rate='GST on Expenses',
            source='Bill', contact='', ref=''):
        transactions.append({
            'Date': base_date + timedelta(days=days),
            'Account Code': code, 'Account': account, 'Description': desc,
            'Gross': gross, 'GST': gst, 'Net': net, 'GST Rate Name': rate,
            'Source': source, 'Reference': ref, 'Contact': contact
        })

    # CORRECT: Legal fees
    add(1, '200', 'Legal Fees', 'Conveyancing - 42 Smith St',
        -3300.00, -300.00, -3000.00, 'GST on Income', 'Invoice', 'Client A', 'INV-001')
    add(3, '200', 'Legal Fees', 'Commercial litigation - ABC Corp',
        -11000.00, -1000.00, -10000.00, 'GST on Income', 'Invoice', 'ABC Corp', 'INV-002')
    add(5, '200', 'Legal Fees', 'Family law matter - Smith',
        -5500.00, -500.00, -5000.00, 'GST on Income', 'Invoice', 'Client B', 'INV-003')

    # ERROR: Disbursements recovery (should match underlying GST)
    add(7, '210', 'Disbursements Recovered', 'Court filing fees recovered',
        -550.00, -50.00, -500.00, 'GST on Income', 'Invoice', 'Client', 'DIS-001')

    # ERROR: Barristers fee (if barrister not registered)
    add(9, '300', 'Barristers Fees', 'Counsel brief fee - no GST charged',
        5500.00, 500.00, 5000.00, contact='Barrister Jones', ref='BAR-001')

    # CORRECT: Search fees (court searches have GST)
    add(11, '310', 'Search Fees', 'ASIC company search',
        44.00, 4.00, 40.00, contact='ASIC', ref='SCH-001')

    # ERROR: Court filing fees (no GST - govt)
    add(13, '320', 'Court Fees', 'Federal Court filing fee',
        880.00, 80.00, 800.00, contact='Federal Court', ref='CRT-001')

    # ERROR: Sheriff fees (no GST)
    add(15, '320', 'Court Fees', 'Sheriff service of documents',
        165.00, 15.00, 150.00, contact='NSW Sheriff', ref='SHF-001')

    # ERROR: PEXA fees (property settlement)
    add(17, '330', 'Settlement Fees', 'PEXA settlement fee',
        132.00, 12.00, 120.00, contact='PEXA', ref='PEX-001')

    # ERROR: Land titles search (govt - no GST)
    add(19, '310', 'Search Fees', 'Land title search NSW LRS',
        33.00, 3.00, 30.00, contact='NSW LRS', ref='LRS-001')

    # ERROR: Practicing certificate (no GST - professional body)
    add(21, '340', 'Professional Fees', 'Law Society practicing certificate',
        1320.00, 120.00, 1200.00, contact='Law Society NSW', ref='LSN-001')

    # ERROR: Professional indemnity (input-taxed)
    add(23, '350', 'Insurance', 'Professional indemnity insurance',
        8800.00, 800.00, 8000.00, contact='LawCover', ref='INS-001')

    # CORRECT: Office rent
    add(25, '360', 'Rent', 'Office rent - November',
        6600.00, 600.00, 6000.00, contact='Landlord', ref='RENT-NOV')

    # ERROR: Library subscription (may be GST-free education)
    add(27, '370', 'Subscriptions', 'LexisNexis subscription',
        1100.00, 100.00, 1000.00, contact='LexisNexis', ref='LEX-001')

    # ERROR: Trust account interest (input-taxed)
    add(29, '400', 'Interest', 'Trust account interest received',
        -220.00, -20.00, -200.00, 'GST on Income', 'Receive Money', 'Bank', 'INT-001')

    # ERROR: Bank fees (input-taxed)
    add(31, '380', 'Bank Fees', 'Trust account fees',
        77.00, 7.00, 70.00, contact='NAB', ref='BNK-001')

    # ERROR: CPD course (education - often GST-free)
    add(33, '390', 'Training', 'CLE seminar registration',
        550.00, 50.00, 500.00, contact='Law Society', ref='CPD-001')

    # ERROR: Overseas legal research service
    add(35, '370', 'Subscriptions', 'Westlaw International - USA',
        330.00, 30.00, 300.00, contact='Thomson Reuters', ref='WLW-001')

    # ERROR: Expert witness fee (may not be registered)
    add(37, '310', 'Expert Fees', 'Medical expert report',
        2200.00, 200.00, 2000.00, contact='Dr Expert', ref='EXP-001')

    # ERROR: Donation to legal aid
    add(39, '410', 'Donations', 'Donation to Legal Aid NSW',
        1100.00, 100.00, 1000.00, contact='Legal Aid', ref='DON-001')

    # ERROR: Wages with GST
    add(41, '420', 'Wages', 'Paralegal wages - November',
        5500.00, 500.00, 5000.00, contact='Payroll', ref='PAY-NOV')

    # CORRECT: Courier services
    add(43, '430', 'Couriers', 'Document courier - urgent',
        55.00, 5.00, 50.00, contact='StarTrack', ref='COR-001')

    # ERROR: Stamp duty paid (no GST on duty)
    add(45, '440', 'Stamp Duty', 'Transfer stamp duty - paid for client',
        22000.00, 2000.00, 20000.00, contact='Revenue NSW', ref='STD-001')

    df = pd.DataFrame(transactions)
    columns = ['Date', 'Account Code', 'Account', 'Description', 'Reference',
               'Contact', 'Gross', 'GST', 'Net', 'GST Rate Name', 'Source']
    return df[columns]


# ==================== AGRICULTURE / FARMING ====================
def generate_agriculture_data():
    """Farm business with livestock, produce, equipment"""
    transactions = []
    base_date = datetime(2024, 10, 1)

    def add(days, code, account, desc, gross, gst, net, rate='GST on Expenses',
            source='Bill', contact='', ref=''):
        transactions.append({
            'Date': base_date + timedelta(days=days),
            'Account Code': code, 'Account': account, 'Description': desc,
            'Gross': gross, 'GST': gst, 'Net': net, 'GST Rate Name': rate,
            'Source': source, 'Reference': ref, 'Contact': contact
        })

    # ERROR: Livestock sale coded GST-free (live animals are TAXABLE)
    add(1, '200', 'Livestock Sales', 'Sale of cattle - 20 head',
        -44000.00, 0.00, -44000.00, 'GST Free', 'Invoice', 'Meat Works', 'LVS-001')

    # CORRECT: Grain sales (GST-free - unprocessed food)
    add(3, '210', 'Grain Sales', 'Wheat harvest sale',
        -55000.00, 0.00, -55000.00, 'GST Free', 'Invoice', 'GrainCorp', 'GRN-001')

    # CORRECT: Wool sales (GST-free - raw material)
    add(5, '220', 'Wool Sales', 'Wool clip - November',
        -22000.00, 0.00, -22000.00, 'GST Free', 'Invoice', 'Elders', 'WOL-001')

    # ERROR: Processed meat sales (should have GST)
    add(7, '230', 'Processed Sales', 'Farm shop - sausages and mince',
        -1100.00, 0.00, -1100.00, 'GST Free', 'Invoice', 'Farm Shop', 'PRO-001')

    # CORRECT: Livestock purchases
    add(9, '300', 'Livestock Purchases', 'Breeding cattle - 10 heifers',
        22000.00, 2000.00, 20000.00, contact='Stud Farm', ref='LVP-001')

    # ERROR: Feed purchases coded with GST (stockfeed often GST-free)
    add(11, '310', 'Feed & Fodder', 'Hay and silage',
        5500.00, 500.00, 5000.00, contact='Fodder King', ref='FEE-001')

    # CORRECT: Processed stockfeed (has GST)
    add(13, '310', 'Feed & Fodder', 'Pelletised stockfeed',
        2200.00, 200.00, 2000.00, contact='Ridley', ref='FEE-002')

    # ERROR: Fertiliser (often GST-free for farming)
    add(15, '320', 'Fertiliser', 'Urea and superphosphate',
        8800.00, 800.00, 8000.00, contact='Incitec Pivot', ref='FER-001')

    # ERROR: Seeds (primary production inputs - GST-free)
    add(17, '330', 'Seeds', 'Wheat seed for planting',
        3300.00, 300.00, 3000.00, contact='Seed Supplier', ref='SED-001')

    # CORRECT: Diesel (with fuel tax credit consideration)
    add(19, '340', 'Fuel', 'Diesel for farm machinery',
        4400.00, 400.00, 4000.00, contact='BP Rural', ref='FUL-001')

    # ERROR: Tractor purchase expensed
    add(21, '350', 'Repairs & Maintenance', 'New John Deere tractor',
        110000.00, 10000.00, 100000.00, contact='JD Dealer', ref='TRC-001')

    # CORRECT: Machinery repairs
    add(23, '350', 'Repairs & Maintenance', 'Header repairs',
        2200.00, 200.00, 2000.00, contact='Farm Mech', ref='REP-001')

    # ERROR: Water charges (some no GST)
    add(25, '360', 'Water', 'Irrigation water charges',
        3300.00, 300.00, 3000.00, contact='SunWater', ref='WAT-001')

    # ERROR: Rates (no GST)
    add(27, '370', 'Council Rates', 'Rural property rates',
        2200.00, 200.00, 2000.00, contact='Council', ref='RAT-001')

    # ERROR: Land tax (no GST)
    add(29, '370', 'Council Rates', 'Land tax assessment',
        4400.00, 400.00, 4000.00, contact='OSR QLD', ref='LTX-001')

    # ERROR: Shearing costs (contractor - check ABN)
    add(31, '380', 'Shearing', 'Shearing contractor - no invoice',
        3300.00, 300.00, 3000.00, contact='Shearer', ref='SHR-001')

    # CORRECT: Vet expenses
    add(33, '390', 'Veterinary', 'Cattle vet visit and vaccines',
        1100.00, 100.00, 1000.00, contact='Rural Vet', ref='VET-001')

    # ERROR: Drought relief grant (govt - no GST)
    add(35, '240', 'Grants', 'Drought assistance grant',
        -11000.00, -1000.00, -10000.00, 'GST on Income', 'Receive Money', 'Govt', 'GRT-001')

    # ERROR: Farm management deposit refund
    add(37, '250', 'FMD Income', 'Farm management deposit withdrawal',
        -22000.00, -2000.00, -20000.00, 'GST on Income', 'Receive Money', 'Bank', 'FMD-001')

    # ERROR: Personal drawings coded wrong
    add(39, '340', 'Fuel', 'Family car fuel - personal',
        220.00, 20.00, 200.00, contact='BP', ref='PERS-001')

    # ERROR: Home electricity (private portion)
    add(41, '400', 'Electricity', 'Farmhouse electricity - 100% claimed',
        660.00, 60.00, 600.00, contact='Origin', ref='ELC-001')

    # CORRECT: Fencing materials
    add(43, '410', 'Fencing', 'Fencing wire and posts',
        1650.00, 150.00, 1500.00, contact='Landmark', ref='FNC-001')

    # ERROR: Carbon credit sale (complex GST treatment)
    add(45, '260', 'Carbon Credits', 'ACCU sale',
        -5500.00, -500.00, -5000.00, 'GST on Income', 'Invoice', 'Carbon Market', 'ACU-001')

    df = pd.DataFrame(transactions)
    columns = ['Date', 'Account Code', 'Account', 'Description', 'Reference',
               'Contact', 'Gross', 'GST', 'Net', 'GST Rate Name', 'Source']
    return df[columns]


# ==================== IT / SOFTWARE COMPANY ====================
def generate_it_data():
    """IT/Software company with SaaS revenue, contractors"""
    transactions = []
    base_date = datetime(2024, 10, 1)

    def add(days, code, account, desc, gross, gst, net, rate='GST on Expenses',
            source='Bill', contact='', ref=''):
        transactions.append({
            'Date': base_date + timedelta(days=days),
            'Account Code': code, 'Account': account, 'Description': desc,
            'Gross': gross, 'GST': gst, 'Net': net, 'GST Rate Name': rate,
            'Source': source, 'Reference': ref, 'Contact': contact
        })

    # CORRECT: SaaS revenue (AU customers)
    add(1, '200', 'SaaS Revenue', 'Monthly subscriptions - AU customers',
        -22000.00, -2000.00, -20000.00, 'GST on Income', 'Invoice', 'Various', 'SAAS-001')

    # ERROR: SaaS revenue overseas (should be GST-free export)
    add(3, '200', 'SaaS Revenue', 'US customer subscriptions',
        -11000.00, -1000.00, -10000.00, 'GST on Income', 'Invoice', 'US Clients', 'SAAS-002')

    # ERROR: NZ customer subscriptions (export - GST-free)
    add(5, '200', 'SaaS Revenue', 'NZ customer subscriptions',
        -5500.00, -500.00, -5000.00, 'GST on Income', 'Invoice', 'NZ Clients', 'SAAS-003')

    # CORRECT: Consulting revenue
    add(7, '210', 'Consulting', 'Development consulting - ABC Corp',
        -8800.00, -800.00, -8000.00, 'GST on Income', 'Invoice', 'ABC Corp', 'CON-001')

    # ERROR: AWS hosting (overseas - no GST)
    add(9, '300', 'Hosting', 'AWS hosting - November',
        2200.00, 200.00, 2000.00, contact='Amazon Web Services', ref='AWS-001')

    # ERROR: Azure (overseas)
    add(11, '300', 'Hosting', 'Microsoft Azure',
        1650.00, 150.00, 1500.00, contact='Microsoft', ref='AZU-001')

    # ERROR: Google Cloud (overseas)
    add(13, '300', 'Hosting', 'Google Cloud Platform',
        880.00, 80.00, 800.00, contact='Google', ref='GCP-001')

    # ERROR: GitHub (overseas)
    add(15, '310', 'Software', 'GitHub Team subscription',
        132.00, 12.00, 120.00, contact='GitHub', ref='GIT-001')

    # ERROR: Atlassian (overseas)
    add(17, '310', 'Software', 'Jira and Confluence',
        220.00, 20.00, 200.00, contact='Atlassian', ref='ATL-001')

    # ERROR: Slack (overseas)
    add(19, '310', 'Software', 'Slack Business+',
        165.00, 15.00, 150.00, contact='Slack', ref='SLK-001')

    # CORRECT: Xero (AU)
    add(21, '310', 'Software', 'Xero subscription',
        77.00, 7.00, 70.00, contact='Xero', ref='XRO-001')

    # ERROR: Figma (overseas)
    add(23, '310', 'Software', 'Figma design subscription',
        55.00, 5.00, 50.00, contact='Figma', ref='FIG-001')

    # ERROR: ChatGPT/OpenAI (overseas)
    add(25, '310', 'Software', 'OpenAI API usage',
        330.00, 30.00, 300.00, contact='OpenAI', ref='OAI-001')

    # ERROR: Overseas contractor (no AU GST)
    add(27, '320', 'Contractors', 'Developer in Philippines',
        4400.00, 400.00, 4000.00, contact='Freelancer', ref='CTR-001')

    # CORRECT: AU contractor
    add(29, '320', 'Contractors', 'Senior developer - AU',
        8800.00, 800.00, 8000.00, contact='DevCo', ref='CTR-002')

    # ERROR: Hardware expensed (should capitalize > $1000)
    add(31, '330', 'Computer Equipment', 'MacBook Pro M3 Max',
        5500.00, 500.00, 5000.00, contact='Apple', ref='HW-001')

    # ERROR: Monitor expensed
    add(33, '330', 'Computer Equipment', 'Studio Display',
        2420.00, 220.00, 2200.00, contact='Apple', ref='HW-002')

    # CORRECT: Small equipment
    add(35, '330', 'Computer Equipment', 'Keyboards and mice',
        440.00, 40.00, 400.00, contact='JB Hi-Fi', ref='HW-003')

    # ERROR: Stripe fees (US - no GST) vs Stripe AU
    add(37, '340', 'Payment Processing', 'Stripe US fees',
        660.00, 60.00, 600.00, contact='Stripe', ref='PAY-001')

    # ERROR: Wages with GST
    add(39, '350', 'Wages', 'Developer salaries',
        33000.00, 3000.00, 30000.00, contact='Payroll', ref='PAY-NOV')

    # ERROR: Share-based compensation with GST
    add(41, '360', 'Share Compensation', 'Employee share options',
        5500.00, 500.00, 5000.00, contact='Internal', ref='ESOP-001')

    # CORRECT: Office rent
    add(43, '370', 'Rent', 'Co-working space',
        1650.00, 150.00, 1500.00, contact='WeWork', ref='RENT-NOV')

    # ERROR: Remote work stipend (FBT issue)
    add(45, '380', 'Staff Benefits', 'Home office allowance',
        550.00, 50.00, 500.00, contact='Employees', ref='WFH-001')

    # ERROR: Domain registration overseas
    add(47, '390', 'Domains', 'Domain renewals - GoDaddy',
        110.00, 10.00, 100.00, contact='GoDaddy', ref='DOM-001')

    df = pd.DataFrame(transactions)
    columns = ['Date', 'Account Code', 'Account', 'Description', 'Reference',
               'Contact', 'Gross', 'GST', 'Net', 'GST Rate Name', 'Source']
    return df[columns]


# ==================== GENERATE ALL FILES ====================
if __name__ == '__main__':
    output_dir = '/Users/noradelsierra/xero-bas-reviewer/test_data/'

    industries = [
        ('Construction', generate_construction_data, 'BuildRight Construction Pty Ltd'),
        ('Retail', generate_retail_data, 'Fashion Forward Retail Pty Ltd'),
        ('Hospitality', generate_hospitality_data, 'Urban Bites Cafe Pty Ltd'),
        ('Medical', generate_medical_data, 'HealthFirst Medical Centre'),
        ('RealEstate', generate_real_estate_data, 'Premier Property Group'),
        ('Transport', generate_transport_data, 'Swift Logistics Pty Ltd'),
        ('Legal', generate_legal_data, 'Harrison & Partners Lawyers'),
        ('Agriculture', generate_agriculture_data, 'Sunnyvale Pastoral Co'),
        ('IT', generate_it_data, 'CloudTech Solutions Pty Ltd'),
    ]

    period = 'From 1 October 2024 to 31 December 2024'

    for name, generator, company in industries:
        print(f"\nGenerating {name} data...")
        df = generator()

        # Save Excel
        excel_file = f'{output_dir}Test_GL_{name}_Q2_FY2025.xlsx'
        save_to_excel(df, excel_file, company, period)

        # Save CSV
        csv_file = f'{output_dir}Test_GL_{name}_Q2_FY2025.csv'
        df.to_csv(csv_file, index=False)

        print(f"  {len(df)} transactions")

    print("\n" + "="*60)
    print("GENERATED TEST FILES:")
    print("="*60)
    for name, _, company in industries:
        print(f"  - Test_GL_{name}_Q2_FY2025.xlsx ({company})")
    print("\nAll files saved to:", output_dir)
