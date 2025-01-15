import re
import imaplib
import email
from email.header import decode_header
import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog
import os
from tkinter import ttk


def is_phishing(email_content):
    phishing_keywords = [
        "urgent", "immediate action", "verify your account", "click here",
        "update your information", "security alert", "password reset",
        "account suspended", "confirm your identity"
    ]

    for keyword in phishing_keywords:
        if re.search(r'\b' + re.escape(keyword) + r'\b', email_content, re.IGNORECASE):
            return True
    return False


def fetch_emails(imap_server, email_user, email_pass, output_dir, progress_var, progress_bar, progress_label):
    try:
        # Connect to the IMAP server
        imap = imaplib.IMAP4_SSL(imap_server)
        # Login to your account
        imap.login(email_user, email_pass)
        # Select the mailbox you want to check
        imap.select("inbox")

        # Search for all emails in the inbox
        status, messages = imap.search(None, "ALL")
        email_ids = messages[0].split()
        total_emails = len(email_ids)

        safe_file_path = os.path.join(output_dir, "safe_emails.txt")
        phishing_file_path = os.path.join(output_dir, "phishing_emails.txt")

        with open(safe_file_path, "w", encoding="utf-8") as safe_file, open(phishing_file_path, "w", encoding="utf-8") as phishing_file:
            for idx, email_id in enumerate(email_ids):
                # Fetch the email by ID
                status, msg_data = imap.fetch(email_id, "(RFC822)")
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])
                        # Decode the email subject
                        subject, encoding = decode_header(msg["Subject"])[0]
                        if isinstance(subject, bytes):
                            subject = subject.decode(
                                encoding if encoding else "utf-8", errors='ignore')
                        # Decode the email sender
                        from_ = msg.get("From")
                        email_info = f"Subject: {subject}\nFrom: {from_}\n"

                        # If the email message is multipart
                        if msg.is_multipart():
                            for part in msg.walk():
                                # Extract content type of email
                                content_type = part.get_content_type()
                                content_disposition = str(
                                    part.get("Content-Disposition"))

                                try:
                                    # Get the email body
                                    body = part.get_payload(
                                        decode=True).decode(errors='ignore')
                                except:
                                    body = ""
                                if content_type == "text/plain" and "attachment" not in content_disposition:
                                    email_info += f"Body: {body}\n"
                                    # Check if the email content is phishing
                                    if is_phishing(body):
                                        phishing_file.write(
                                            email_info + "This email is likely a phishing attempt.\n\n")
                                    else:
                                        safe_file.write(
                                            email_info + "This email seems safe.\n\n")
                        else:
                            # Extract content type of email
                            content_type = msg.get_content_type()
                            # Get the email body
                            body = msg.get_payload(
                                decode=True).decode(errors='ignore')
                            if content_type == "text/plain":
                                email_info += f"Body: {body}\n"
                                # Check if the email content is phishing
                                if is_phishing(body):
                                    phishing_file.write(
                                        email_info + "This email is likely a phishing attempt.\n\n")
                                else:
                                    safe_file.write(
                                        email_info + "This email seems safe.\n\n")
                # Update progress bar and label
                progress = (idx + 1) / total_emails * 100
                progress_var.set(progress)
                progress_label.config(text=f"{progress:.2f}%")
                progress_bar.update()

        # Close the connection and logout
        imap.close()
        imap.logout()
        messagebox.showinfo(
            "Success", f"Email check completed. Results saved to {output_dir}.")
        print(f"Results saved to {output_dir}")
    except imaplib.IMAP4.error as e:
        messagebox.showerror(
            "Login Failed", f"The login credentials are incorrect or IMAP access is not enabled. Error: {e}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")


def start_phishing_detector():
    email_user = simpledialog.askstring("Email", "Enter your email:")
    email_pass = simpledialog.askstring(
        "Password", "Enter your password:", show='*')
    if email_user and email_pass:
        domain = email_user.split('@')[-1]
        imap_servers = {
            "gmail.com": "imap.gmail.com",
            "yahoo.com": "imap.mail.yahoo.com",
            "outlook.com": "imap-mail.outlook.com",
            "hotmail.com": "imap-mail.outlook.com",
            # Add more domains and their IMAP servers as needed
        }
        imap_server = imap_servers.get(domain)
        if not imap_server:
            imap_server = simpledialog.askstring(
                "IMAP Server", "Enter your IMAP server address:")
        output_dir = filedialog.askdirectory(title="Select Output Directory")
        if output_dir:
            progress_window = tk.Toplevel(root)
            progress_window.title("Processing Emails")
            progress_var = tk.DoubleVar()
            progress_bar = ttk.Progressbar(
                progress_window, variable=progress_var, maximum=100)
            progress_bar.pack(padx=20, pady=10)
            progress_label = tk.Label(progress_window, text="0%")
            progress_label.pack(pady=10)
            root.after(100, fetch_emails, imap_server, email_user, email_pass,
                       output_dir, progress_var, progress_bar, progress_label)


def stop_phishing_detector():
    root.quit()


# Create the main window
root = tk.Tk()
root.withdraw()  # Hide the main window

# Start the phishing detector
start_phishing_detector()

# Run the Tkinter event loop
root.mainloop()
