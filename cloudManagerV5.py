import os
import sys
import urllib
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import sqlite3
import pickle
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.http import MediaFileUpload
import threading
import queue
from http.server import HTTPServer, BaseHTTPRequestHandler
import webbrowser
from tkinterdnd2 import TkinterDnD, DND_FILES
from PIL import Image, ImageTk, ImageOps, ImageDraw
import customtkinter as ctk
import io
import tempfile
import subprocess
from googleapiclient.http import MediaIoBaseDownload
import platform
import time
import os
from dotenv import load_dotenv
# Allow HTTP for OAuth in development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
load_dotenv()
# Your SCOPES and CLIENT_CONFIG here...
SCOPES = ['https://www.googleapis.com/auth/drive.file']
CLIENT_CONFIG = os.getenv("CONFIG")

class OAuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.server.path = self.path
        self.wfile.write(b'Authentication successful! You can close this window now.')
        
    def log_message(self, format, *args):
        return  # Suppress console output

class ModernUI(ctk.CTkFrame):
    def __init__(self, master, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.configure(fg_color="#343431")  # Light background "#f5f5f5"
        self.continue_update = True

    def create_button(self, text, command, color="#4a86e8", height=30, font_size=16, 
                      text_color="white", hover_color="#3a76d8", border_width=0):
        return ctk.CTkButton(self, text=text, command=command, fg_color=color,
                             text_color=text_color, hover_color=hover_color,
                             height=height, corner_radius=10,
                             font=("Consolas", font_size), border_width=border_width)

    def create_label(self, text, font_size=16, text_color="#333333"): ##343432
        return ctk.CTkLabel(self, text=text, text_color=text_color, font=("Consolas", font_size))

    def create_entry(self, width=300, font_size =16, border_width = 1, placeholder_text=""):
        return ctk.CTkEntry(self, width=width, height=40, corner_radius=8, border_width=border_width,
                            font=("Consolas", font_size), placeholder_text=placeholder_text)

    # def create_listbox(self, width=500, height=18):
    #     return tk.Listbox(self, width=width, font=("Consolas", 12), relief=tk.FLAT, bd=0,
    #                       highlightthickness=0, selectbackground="#e1e1e1", selectforeground="#333333",
    #                       height=height)
    def create_listbox(self, width=500, height=18):
        return tk.Listbox(
            self, 
            width=width, 
            height=height, 
            font=("Consolas", 12, "bold"),  # Bold font for better visibility
            relief=tk.FLAT, 
            bd=0,
            highlightthickness=0, 
            selectbackground= "#cfe2f3",  # Softer blue for selection background 
            selectforeground= "#1a1a1a",  # Darker text color for contrast 
            bg="#282c34",  # Light background color for a clean look
            fg="white",  # Standard text color
            activestyle='none',  # Removes underline effect on active item
        )

    
    def destroy_widgets(self, frame):
        self.destroy_widgets_helper(frame)

    def destroy_widgets_helper(self, frame):
        for widget in frame.winfo_children():
            print(f"Destroying {widget}")
            if widget.winfo_children():
                self.destroy_widgets_helper(widget)
            else:
                widget.destroy()
       
class CloudManager:
    def __init__(self, master):
        self.master = master
        self.master.title("CloudSync")
        self.master.geometry("800x600")
        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")
        self.continue_update = True

        self.creds = None
        self.service = None
        self.email = None

        self.setup_database()
        self.setup_ui()

        self.queue = queue.Queue()
        self.master.after(100, self.process_queue)

    def destroy_widgets(self, frame):
        self.destroy_widgets_helper(frame)

    def destroy_widgets_helper(self, frame):
        for widget in frame.winfo_children():
            print(f"Destroying {widget}")
            if widget.winfo_children():
                self.destroy_widgets_helper(widget)
            else:
                widget.destroy()
    
    def setup_database(self):
        self.conn = sqlite3.connect('cloudmanager.db')
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users
            (email TEXT PRIMARY KEY, token BLOB)
        ''')
        self.conn.commit()

    def setup_ui(self):
        self.main_frame = ModernUI(self.master)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)
        self.show_login_page()

    def show_login_page(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

        # Load and display logo
        logo = Image.open("logo4.png")  # Ensure you have a logo.png file
        mask = Image.new("L", logo.size, 0)
        draw = ImageDraw.Draw(mask)
        draw.ellipse((0, 0, logo.width, logo.height), fill=350)
        logo.putalpha(mask)
        
        logo = logo.resize((150, 130), Image.LANCZOS)
        logo = ImageTk.PhotoImage(logo)
        
        logo_label = tk.Label(self.main_frame, image=logo, bg=self.main_frame.cget("fg_color"))
        logo_label.image = logo
        logo_label.pack(pady=30)
        
        welcome_label = self.main_frame.create_label("Welcome to CloudSync", text_color="white")
        welcome_label.pack(pady=10)
        welcome_label.configure(font=("Consolas", 24, "bold"))
        
        email_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent", border_color="#cccccc")
        email_frame.pack(pady=20)

        email_label = self.main_frame.create_label("Email:", text_color="white")
        email_label.pack(in_=email_frame, side=tk.LEFT, padx=(0, 10))

        self.email_entry = self.main_frame.create_entry(width=300)
        self.email_entry.pack(in_=email_frame, side=tk.LEFT)

        auth_button = self.main_frame.create_button("Authenticate", self.start_authentication, 
                                                    color="#212121", text_color="white", hover_color="#343431", border_width=1)
        auth_button.pack(pady=10)
    
    # def show_login_page(self):
    #     # Clear existing widgets in the main frame
    #     for widget in self.main_frame.winfo_children():
    #         widget.destroy()

    #     # Load and display logo
    #     logo = Image.open("logo3.jpg")  # Ensure you have a logo.jpg file
    #     logo = logo.resize((800, 600), Image.LANCZOS)  # Resize the logo to fit the entire page
    #     logo = ImageTk.PhotoImage(logo)

    #     # Create a label for the logo
    #     logo_label = tk.Label(self.main_frame, image=logo)
    #     logo_label.image = logo  # Keep a reference to avoid garbage collection
    #     logo_label.place(relx=0.5, rely=0.5, anchor=tk.CENTER)  # Center the logo

    #     # Create a frame on top of the logo to hold the login form
    #     form_frame = ctk.CTkFrame(self.main_frame, fg_color="White", corner_radius=10)
    #     form_frame.place(relx=0.5, rely=0.35, anchor=tk.CENTER)  # Adjust rely to position the frame higher on the logo

    #     # Add login form elements to the form frame
    #     welcome_label = ctk.CTkLabel(form_frame, text="Welcome to CloudSync", font=("Consolas", 24, "bold"))
    #     welcome_label.pack(pady=(40, 30))

    #     email_label = ctk.CTkLabel(form_frame, text="Email:", font=("Consolas", 18))
    #     email_label.pack()

    #     self.email_entry = ctk.CTkEntry(form_frame, width=300, corner_radius=10, font=("Consolas", 14),
    #                                     border_width=0.5, placeholder_text="Enter your email...")
    #     self.email_entry.pack()

    #     auth_button = ctk.CTkButton(form_frame, text="Authenticate", font=("Consolas", 16, "bold"), command=self.start_authentication)
    #     auth_button.pack(pady=20)
        
    #     # Optionally, add a footer or additional links
    #     footer_label = ctk.CTkLabel(form_frame, text="", font=("Arial", 10), text_color="#aaaaaa")
    #     footer_label.pack(pady=(10, 10))
        
    #     footer_label = ctk.CTkLabel(form_frame, text="", font=("Arial", 10), text_color="#aaaaaa")
    #     footer_label.pack(pady=(10, 10))
        
    #     footer_label = ctk.CTkLabel(form_frame, text="", font=("Consolas", 12), text_color="#aaaaaa")
    #     footer_label.pack(pady=(10, 0))

    
    def show_home_page(self):
        # Destroy all widgets in the main frame
        for widget in self.main_frame.winfo_children():
            widget.destroy()
        
        # Clear existing widgets
        self.destroy_widgets(self.main_frame)

        # Create top bar and content frame
        top_bar = ctk.CTkFrame(self.main_frame, height=60, corner_radius=0, fg_color="transparent") #"#4a86e8"
        content_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")

        # Create widgets in top bar and content frame
        welcome_label = ctk.CTkLabel(top_bar, text=f"Welcome {self.email}", 
                                    text_color="white", font=("Consolas", 16))
        welcome_label.pack(side=tk.LEFT, padx=20)

        logout_button = ctk.CTkButton(top_bar, text="Logout", command=self.logout, 
                                    width=80, fg_color="#e1e1e1", text_color="#1e1e1e",
                                    hover_color="white", corner_radius=8, border_color="#cccccc",
                                    border_width=1, font=("Consolas", 15, "bold"))
        logout_button.pack(side=ctk.RIGHT, padx=20)
        
        # Search entry area
        search_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        search_frame.pack(fill=tk.X, pady=(20, 0))

        self.search_entry = self.main_frame.create_entry(width=250, placeholder_text="Search...")
        self.search_entry.pack(in_=search_frame, side=tk.RIGHT, pady=10)
        self.search_entry.bind("<KeyRelease>", self.search_files)

        list_label = self.main_frame.create_label("Uploaded Files", font_size=24, text_color="white")
        list_label.pack(in_=search_frame, side=tk.LEFT, pady=(20, 0))
        welcome_label.configure(font=("Consolas", 24, "bold"))

        self.file_listbox = self.main_frame.create_listbox(width=70)
        self.file_listbox.pack(in_=content_frame, fill=tk.BOTH, expand=True)

        scrollbar = ctk.CTkScrollbar(self.main_frame, command=self.file_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_listbox.configure(yscrollcommand=scrollbar.set)

        # Button area
        button_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        button_frame.pack(fill=tk.X, pady=(10, 10))

        upload_button = self.main_frame.create_button("Upload File", self.upload_file)
        upload_button.pack(in_=button_frame, side=tk.LEFT, padx=(0, 10), expand=True)

        open_button = self.main_frame.create_button("Open", self.open_file, color="#28a745")
        open_button.pack(in_=button_frame, side=tk.LEFT, expand=True)

        delete_button = self.main_frame.create_button("Delete", self.delete_file, color="#dc3545")
        delete_button.pack(in_=button_frame, side=tk.LEFT, padx=(10, 0), expand=True)
        
        # Pack top bar and content frame
        top_bar.pack(fill=tk.X, pady=(0, 20))
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20)
        
        self.status_label = self.main_frame.create_label("")
        self.status_label.pack(pady=10)
        self.list_files()
    
    def search_files(self, event):
        search_term = self.search_entry.get()
        if search_term:
            self.file_listbox.delete(0, tk.END)
            for file_name, file_id in self.file_ids.items():
                if search_term.lower() in file_name.lower():
                    self.file_listbox.insert(tk.END, file_name)
        else:
            self.list_files()
    
    def start_authentication(self):
        self.email = self.email_entry.get()
        if not self.email or not "@" in self.email:
            messagebox.showerror("Error", "Invalid email address")
            return

        for widget in self.main_frame.winfo_children():
            widget.destroy()
        
        self.show_progress_bar()
        self.auth_thread = threading.Thread(target=self.authenticate_thread, daemon=True)
        self.auth_thread.start()
        self.cancel_button.configure(command=self.cancel_authentication)
        
    def show_progress_bar(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

        self.auth_stopped = threading.Event()
        self.progress = ttk.Progressbar(self.main_frame, orient=tk.HORIZONTAL, length=200, mode='indeterminate')
        self.progress.pack(pady=20)
        self.progress.start()

        self.auth_label = ctk.CTkLabel(self.main_frame, text="Authenticating...")
        self.auth_label.pack(pady=10)

        self.cancel_button = ctk.CTkButton(self.main_frame, text="Cancel", command=self.cancel_authentication)
        self.cancel_button.pack(pady=10)

        self.main_frame.update_idletasks()
        
    def cancel_authentication(self):
        self.auth_stopped.set()
        self.progress.stop()
        self.progress.destroy()
        self.auth_label.destroy()
        self.cancel_button.destroy()
        self.show_login_page()
    
    def authenticate_thread(self):
        try:
            self.auth_stopped = threading.Event()
            self.queue.put(('check_token', self.email))
            while not self.auth_stopped.is_set():
                time.sleep(0.1)  # Add a short delay to avoid busy waiting
                if self.queue.empty():
                    continue
                task, result = self.queue.get()
                if task == 'authenticated':
                    self.authenticated = True
                    self.auth_stopped.set()
                    break
                elif task == 'error':
                    self.handle_error("Failed to authenticate", result)
                    self.auth_stopped.set()
                    self.show_home_page()
                    break
        except Exception as e:
            self.handle_error("Failed to authenticate", e)
    
    def process_queue(self):
        try:
            action, data = self.queue.get(0)
            if action == 'check_token':
                self.check_token(data)
            elif action == 'save_token':
                self.save_token(data)
            elif action == 'show_home':
                if self.progress.winfo_exists():
                    self.progress.stop()
                self.progress.destroy()
                self.show_home_page()
        except queue.Empty:
            pass
        self.master.after(100, self.process_queue)

    def check_token(self, email):
        try:
            self.cursor.execute("SELECT token FROM users WHERE email = ?", (email,))
            result = self.cursor.fetchone()

            if result:
                token = pickle.loads(result[0])
                self.creds = token
                if not self.creds or not self.creds.valid:
                    if self.creds and self.creds.expired and self.creds.refresh_token:
                        self.creds.refresh(Request())
                    else:
                        self.master.after(0, self.run_oauth_flow)
                        return
            else:
                self.master.after(0, self.run_oauth_flow)
                return

            self.queue.put(('save_token', self.creds))
            self.service = build('drive', 'v3', credentials=self.creds)
            self.queue.put(('show_home', None))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to authenticate: {str(e)}")
    
    def run_oauth_flow(self):
        thread = threading.Thread(target=self._run_oauth_flow)
        thread.start()

    def _run_oauth_flow(self):
        try:
            flow = Flow.from_client_config(CLIENT_CONFIG, SCOPES)
            flow.redirect_uri = "http://localhost:8080/"

            auth_url, _ = flow.authorization_url(prompt='consent')

            webbrowser.open(auth_url)

            server = HTTPServer(('localhost', 8080), OAuthHandler)
            thread = threading.Thread(target=server.handle_request)
            thread.start()
            thread.join()

            authorization_response = urllib.parse.unquote(server.path)
            flow.fetch_token(authorization_response=authorization_response)

            self.creds = flow.credentials
            self.queue.put(('save_token', self.creds))
            self.service = build('drive', 'v3', credentials=self.creds)
            self.queue.put(('show_home', None))

            messagebox.showinfo("Authorization Complete", "You have successfully authorized the application.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to authenticate: {str(e)}")
    
    def save_token(self, creds):
        token_pickle = pickle.dumps(creds)
        self.cursor.execute("INSERT OR REPLACE INTO users (email, token) VALUES (?, ?)",
                            (self.email, token_pickle))
        self.conn.commit()

    def list_files(self):
        if not self.service:
            messagebox.showerror("Error", "Not authenticated")
            return

        try:
            results = self.service.files().list(
                pageSize=50, fields="nextPageToken, files(id, name, mimeType, modifiedTime, size)").execute()
            items = results.get('files', [])

            self.file_listbox.delete(0, tk.END)
            self.file_ids = {}
            if not items:
                self.file_listbox.insert(tk.END, "No files found.")
            else:
                for item in items:
                    file_type = "" if item['mimeType'] != 'application/vnd.google-apps.folder' else ""
                    size = self.format_size(int(item.get('size', 0)))
                    file_name = f"{file_type} {item['name']} ({size}) - Modified: {item['modifiedTime'][:10]}"
                    self.file_listbox.insert(tk.END, file_name)
                    self.file_ids[file_name] = item['id']
        except Exception as e:
            self.handle_error("Failed to list files", e)

    def open_file(self):
        if not self.service:
            messagebox.showerror("Error", "Not authenticated")
            return

        selection = self.file_listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "Please select a file to open")
            return

        file_index = selection[0]
        file_name = self.file_listbox.get(file_index)
        file_id = self.file_ids.get(file_name)

        if not file_id:
            messagebox.showerror("Error", "Failed to get file ID")
            return

        try:
            # Get the file metadata
            file_metadata = self.service.files().get(fileId=file_id).execute()

            # Download the file
            request = self.service.files().get_media(fileId=file_id)
            fh = io.BytesIO()
            downloader = MediaIoBaseDownload(fh, request)
            done = False
            while not done:
                status, done = downloader.next_chunk()
                print(f"Download {int(status.progress() * 100)}%.")

            # Save the file to a temporary location
            temp_file_path = os.path.join(tempfile.gettempdir(), file_metadata['name'])
            with open(temp_file_path, 'wb') as f:
                f.write(fh.getvalue())

            # Open the file using the default application
            self.open_file_with_default_app(temp_file_path)

        except Exception as e:
            self.handle_error("Failed to open file", e)

    def open_file_with_default_app(self, file_path):
        try:
            if platform.system() == 'Darwin':       # macOS
                subprocess.call(('open', file_path))
            elif platform.system() == 'Windows':    # Windows
                os.startfile(file_path)
            else:                                   # linux variants
                subprocess.call(('xdg-open', file_path))
        except Exception as e:
            self.handle_error(f"Failed to open file: {file_path}", e)
    
    def format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0

    def handle_error(self, message, exception):
        error_message = f"{message}: {str(exception)}"
        self.status_label.configure(text=error_message, text_color="#d9534f")
        print(f"Error occurred: {error_message}")  # Log the error

    def upload_file(self):
        if not self.service:
            messagebox.showerror("Error", "Not authenticated")
            return

        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                self.progress = ttk.Progressbar(self.main_frame, orient=tk.HORIZONTAL, length=200, mode='indeterminate')
                self.progress.pack(pady=20)
                self.progress.start()

                file_name = os.path.basename(file_path)
                file_metadata = {'name': file_name}
                media = MediaFileUpload(file_path, resumable=True)
                file = self.service.files().create(body=file_metadata, media_body=media, fields='id').execute()
                self.progress.stop()
                self.progress.destroy()

                messagebox.showinfo("Success", "File uploaded successfully!")
                self.status_label.configure(text=f"File uploaded: {file.get('id')}")
                self.list_files()
            except Exception as e:
                self.progress.stop()
                self.progress.destroy()
                messagebox.showerror("Error", f"Failed to upload file: {str(e)}")

    def drop_files(self, event):
        if not self.service:
            messagebox.showerror("Error", "Not authenticated")
            return
        
        files = event.data.split()
        for file_path in files:
            self.upload_single_file(file_path)

    def delete_file(self):
        if not self.service:
            messagebox.showerror("Error", "Not authenticated")
            return

        try:
            selection = self.file_listbox.curselection()
            if not selection:
                messagebox.showerror("Error", "Please select a file to delete")
                return

            file_index = selection[0]
            file_name = self.file_listbox.get(file_index)
            file_id = self.file_ids.get(file_name)

            if file_id:
                if messagebox.askyesno("Delete File", f"Are you sure you want to delete '{file_name}'?"):
                    self.service.files().delete(fileId=file_id).execute()
                    del self.file_ids[file_name]
                    self.file_listbox.delete(file_index)
                    messagebox.showinfo("Success", "File deleted successfully!")
                else:
                    messagebox.showinfo("Cancelled", "File deletion cancelled.")
            else:
                messagebox.showerror("Error", "Failed to delete file")
        except Exception as e:
            self.handle_error("Failed to delete file", e)

    def get_file_id(self, file_name):
        try:
            results = self.service.files().list(
                pageSize=50, fields="nextPageToken, files(id, name)").execute()
            items = results.get('files', [])

            for item in items:
                if item['name'] == file_name.split(" ")[1]:
                    return item['id']
        except Exception as e:
            self.handle_error("Failed to get file ID", e)
        return None
    
    def logout(self):
        if messagebox.askyesno("Logout", "Are you sure you want to log out?"):
            self.creds = None
            self.service = None
            self.email = None
            self.auth_stopped.set()
            self.show_login_page()

    def handle_error(self, message, exception):
        error_message = f"{message}: {str(exception)}"
        messagebox.showerror("Error", error_message)
        print(f"Error occurred: {error_message}")  # Log the error

if __name__ == "__main__":
    root = TkinterDnD.Tk()
    root.resizable(False, False)
    logo = ImageTk.PhotoImage(Image.open('logo3.jpg'))  # Replace 'logo.png' with the path to your logo file
    root.iconphoto(True, logo)
    app = CloudManager(root)
    root.mainloop()