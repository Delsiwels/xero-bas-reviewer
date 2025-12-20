"""
BAS Reviewer GUI - Standalone application for reviewing Xero General Ledger transactions
"""
import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext
import threading
from datetime import datetime

# Add current directory to path for imports
if getattr(sys, 'frozen', False):
    # Running as compiled executable
    application_path = os.path.dirname(sys.executable)
else:
    # Running as script
    application_path = os.path.dirname(os.path.abspath(__file__))

os.chdir(application_path)
sys.path.insert(0, application_path)

from gl_parser import GeneralLedgerParser
from deepseek_client import DeepSeekClient
from output_generator import OutputGenerator


class BASReviewerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Xero BAS Reviewer")
        self.root.geometry("700x550")
        self.root.resizable(True, True)

        # Variables
        self.file_path = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")
        self.progress_var = tk.DoubleVar(value=0)
        self.max_transactions = tk.StringVar(value="")

        self.setup_ui()

    def setup_ui(self):
        # Main frame with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)

        # Title
        title_label = ttk.Label(main_frame, text="Xero BAS Reviewer", font=('Helvetica', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 15))

        # File selection
        ttk.Label(main_frame, text="Excel File:").grid(row=1, column=0, sticky=tk.W, pady=5)

        file_frame = ttk.Frame(main_frame)
        file_frame.grid(row=1, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        file_frame.columnconfigure(0, weight=1)

        file_entry = ttk.Entry(file_frame, textvariable=self.file_path, width=50)
        file_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))

        browse_btn = ttk.Button(file_frame, text="Browse...", command=self.browse_file)
        browse_btn.grid(row=0, column=1)

        # Max transactions (optional)
        ttk.Label(main_frame, text="Max Transactions:").grid(row=2, column=0, sticky=tk.W, pady=5)
        max_entry = ttk.Entry(main_frame, textvariable=self.max_transactions, width=10)
        max_entry.grid(row=2, column=1, sticky=tk.W, pady=5)
        ttk.Label(main_frame, text="(leave blank for all)", font=('Helvetica', 9)).grid(row=2, column=2, sticky=tk.W, pady=5)

        # Run button
        self.run_btn = ttk.Button(main_frame, text="Run Review", command=self.run_review, style='Accent.TButton')
        self.run_btn.grid(row=3, column=0, columnspan=3, pady=15)

        # Progress bar
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100, length=400)
        self.progress_bar.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)

        # Status label
        status_label = ttk.Label(main_frame, textvariable=self.status_var, font=('Helvetica', 10))
        status_label.grid(row=5, column=0, columnspan=3, pady=5)

        # Log output
        ttk.Label(main_frame, text="Review Log:").grid(row=6, column=0, sticky=tk.W, pady=(10, 5))

        self.log_text = scrolledtext.ScrolledText(main_frame, height=15, width=80, font=('Courier', 9))
        self.log_text.grid(row=7, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        main_frame.rowconfigure(7, weight=1)

        # Output file label
        self.output_label = ttk.Label(main_frame, text="", font=('Helvetica', 10, 'bold'), foreground='green')
        self.output_label.grid(row=8, column=0, columnspan=3, pady=10)

    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Select Xero General Ledger Excel File",
            filetypes=[
                ("Excel files", "*.xlsx *.xls"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self.file_path.set(filename)
            self.log(f"Selected file: {filename}")

    def log(self, message):
        """Add message to log output"""
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    def run_review(self):
        """Run the review in a separate thread"""
        if not self.file_path.get():
            messagebox.showerror("Error", "Please select an Excel file first.")
            return

        if not os.path.exists(self.file_path.get()):
            messagebox.showerror("Error", f"File not found: {self.file_path.get()}")
            return

        # Disable button during processing
        self.run_btn.config(state='disabled')
        self.log_text.delete(1.0, tk.END)
        self.output_label.config(text="")

        # Run in separate thread to keep UI responsive
        thread = threading.Thread(target=self.do_review)
        thread.daemon = True
        thread.start()

    def do_review(self):
        """Perform the actual review"""
        try:
            excel_file = self.file_path.get()
            max_trans = None
            if self.max_transactions.get().strip():
                try:
                    max_trans = int(self.max_transactions.get().strip())
                except ValueError:
                    self.log("Warning: Invalid max transactions value, reviewing all transactions")

            self.status_var.set("Parsing Excel file...")
            self.progress_var.set(5)
            self.log("=" * 60)
            self.log("XERO BAS REVIEWER")
            self.log("=" * 60)
            self.log(f"\nParsing Excel file: {os.path.basename(excel_file)}")

            # Parse the Excel file
            parser = GeneralLedgerParser(excel_file)
            parsed_data = parser.parse()

            self.log(f"Found {parsed_data['total_transactions']} transactions")
            self.log(f"Company: {parsed_data['metadata'].get('company_name', 'Unknown')}")
            self.log(f"Period: {parsed_data['metadata'].get('period', 'Unknown')}")

            # Get summary
            summary = parser.get_summary()
            self.log(f"\nIncome: ${summary['total_income']:,.2f}")
            self.log(f"Expenses: ${summary['total_expenses']:,.2f}")
            self.log(f"GST Collected: ${summary['total_gst_collected']:,.2f}")
            self.log(f"GST Paid: ${summary['total_gst_paid']:,.2f}")
            self.log(f"Net GST: ${summary['net_gst']:,.2f}")

            self.progress_var.set(10)

            # Initialize AI client
            self.status_var.set("Initializing AI client...")
            ai_client = DeepSeekClient()

            # Determine which transactions to review
            transactions = parsed_data['transactions']
            if max_trans:
                transactions = transactions[:max_trans]
                self.log(f"\nReviewing first {max_trans} of {parsed_data['total_transactions']} transactions")
            else:
                self.log(f"\nReviewing all {len(transactions)} transactions")

            self.log("\n" + "=" * 60)
            self.log("REVIEWING TRANSACTIONS WITH AI")
            self.log("=" * 60)

            flagged_items = []
            total = len(transactions)

            for i, transaction in enumerate(transactions, 1):
                progress = 10 + (i / total * 80)
                self.progress_var.set(progress)
                self.status_var.set(f"Reviewing transaction {i}/{total}...")

                self.log(f"\nTransaction {i}/{total}: Row {transaction['row_number']} - {transaction['description'][:50]}")

                # Build context
                context = {
                    'company': parsed_data['metadata'].get('company_name', ''),
                    'period': parsed_data['metadata'].get('period', ''),
                }

                # Import prompt function
                from gl_prompts import create_gl_review_prompt

                # Create prompt
                prompt = create_gl_review_prompt(transaction, context)

                # Call AI
                messages = [
                    {
                        'role': 'system',
                        'content': 'You are an expert Australian tax accountant conducting a thorough BAS review. Be CRITICAL and flag account coding errors and incorrect GST treatment. Question transactions marked BAS Excluded or GST Free for normal business items.'
                    },
                    {
                        'role': 'user',
                        'content': prompt
                    }
                ]

                response = ai_client.chat_completion(messages)

                if response:
                    # Check if transaction was flagged
                    response_lower = response.lower()
                    has_issues = not ('ok -' in response_lower or 'appears correct' in response_lower or 'no issues' in response_lower)

                    if has_issues:
                        # Determine severity
                        if any(word in response_lower for word in ['critical', 'must', 'incorrect', 'error']):
                            severity = 'high'
                        elif any(word in response_lower for word in ['should', 'review', 'check', 'unusual']):
                            severity = 'medium'
                        else:
                            severity = 'low'

                        severity_icons = {'high': '[HIGH]', 'medium': '[MEDIUM]', 'low': '[LOW]'}
                        icon = severity_icons.get(severity, '[?]')
                        self.log(f"  {icon} Issue found")

                        flagged_items.append({
                            'row_number': transaction['row_number'],
                            'date': transaction['date'],
                            'account': f"{transaction['account_code']} - {transaction['account']}",
                            'description': transaction['description'],
                            'gross': transaction['gross'],
                            'gst': transaction['gst'],
                            'net': transaction['net'],
                            'gst_rate_name': transaction['gst_rate_name'],
                            'severity': severity,
                            'comments': response,
                            'has_issues': True
                        })
                    else:
                        self.log(f"  [OK] No issues")

            self.progress_var.set(90)
            self.status_var.set("Generating report...")

            self.log("\n" + "=" * 60)
            self.log("REVIEW COMPLETE")
            self.log("=" * 60)
            self.log(f"\nTotal transactions reviewed: {len(transactions)}")
            self.log(f"Flagged items: {len(flagged_items)}")

            if len(flagged_items) > 0:
                severity_counts = {'high': 0, 'medium': 0, 'low': 0}
                for item in flagged_items:
                    severity_counts[item['severity']] = severity_counts.get(item['severity'], 0) + 1

                self.log(f"\nSeverity breakdown:")
                for severity, count in severity_counts.items():
                    if count > 0:
                        self.log(f"  {severity.upper()}: {count}")

            # Generate report
            results = {
                'metadata': parsed_data['metadata'],
                'summary': summary,
                'total_reviewed': len(transactions),
                'flagged_count': len(flagged_items),
                'flagged_items': flagged_items,
                'review_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            output_gen = OutputGenerator(results, excel_file)
            output_file = output_gen.generate_excel_report()

            # Move output file to Downloads folder
            downloads_folder = os.path.expanduser("~/Downloads")
            output_filename = os.path.basename(output_file)
            output_full_path = os.path.join(downloads_folder, output_filename)

            # Move the file to Downloads
            import shutil
            if os.path.exists(output_file):
                shutil.move(output_file, output_full_path)

            self.progress_var.set(100)
            self.status_var.set("Review complete!")
            self.log(f"\nReport saved to: {output_full_path}")

            self.output_label.config(text=f"Output: {output_file}")

            messagebox.showinfo("Review Complete",
                f"Review complete!\n\n"
                f"Transactions reviewed: {len(transactions)}\n"
                f"Issues found: {len(flagged_items)}\n\n"
                f"Report saved to:\n{output_full_path}")

        except Exception as e:
            self.log(f"\nERROR: {str(e)}")
            self.status_var.set("Error occurred")
            messagebox.showerror("Error", f"An error occurred:\n{str(e)}")

        finally:
            self.run_btn.config(state='normal')


def main():
    root = tk.Tk()
    app = BASReviewerApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()
