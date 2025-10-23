import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
import re
import os
import urllib.request
import tempfile

IMAGE_URL = "https://sl.bing.net/i4MpjEwBOdE"
LOCAL_IMAGE_NAME = "scanner_banner_img"

class CLexicalAnalyzer:
   
    OPERATORS = {
        '+', '-', '*', '/', '%', '=', '==', '!=', '<', '>', '<=', '>=',
        '&&', '||', '!', '&', '|', '^', '~', '<<', '>>'
    }
    
    SEPARATORS = {'(', ')', '{', '}', '[', ']', ';', ',', '.'}
    PRIMITIVE_FUNCTIONS = {
        'printf', 'scanf', 'puts', 'gets', 'fopen', 'fclose', 'fread',
        'fwrite', 'fprintf', 'fscanf', 'fgets', 'fputs', 'malloc',
        'calloc', 'realloc', 'free', 'exit', 'abort', 'assert'
    }
    KEYWORDS = {
        'auto', 'break', 'case', 'char', 'const', 'continue', 'default',
        'do', 'double', 'else', 'enum', 'extern', 'float', 'for', 'goto',
        'if', 'int', 'long', 'register', 'return', 'short', 'signed',
        'sizeof', 'static', 'struct', 'switch', 'typedef', 'union',
        'unsigned', 'void', 'volatile', 'while'
    }
    
    PREPROCESSOR_DIRECTIVES = {'#include', '#define', '#if', '#else', '#endif', '#ifdef', '#ifndef'}
    SPECIAL_SYMBOLS = {'#'}

    def analyze(self, code):
        code, comments = self.remove_comments(code)
        tokens = []
        current_token = ''
        i = 0
        n = len(code)
        while i < n:
            ch = code[i]
            if ch.isspace():
                if current_token:
                    tokens.append(self.classify_token(current_token))
                    current_token = ''
                i += 1
                continue
            if ch == '"':
                if current_token:
                    tokens.append(self.classify_token(current_token))
                    current_token = ''
                literal = '"'
                i += 1
                while i < n and code[i] != '"':
                    if code[i] == '\\' and i + 1 < n:
                        literal += code[i] + code[i + 1]
                        i += 2
                        continue
                    literal += code[i]
                    i += 1
                literal += '"'
                tokens.append(('STRING_LITERAL', literal))
                i += 1
                continue
            if ch == "'":
                if current_token:
                    tokens.append(self.classify_token(current_token))
                    current_token = ''
                literal = "'"
                i += 1
                while i < n and code[i] != "'":
                    if code[i] == '\\' and i + 1 < n:
                        literal += code[i] + code[i + 1]
                        i += 2
                        continue
                    literal += code[i]
                    i += 1
                literal += "'"
                tokens.append(('CHAR_LITERAL', literal))
                i += 1
                continue
            if ch in '+-*/%=!<>&|^~':
                if current_token:
                    tokens.append(self.classify_token(current_token))
                    current_token = ''
                op = ch
                if i + 1 < n:
                    double = ch + code[i + 1]
                    if double in self.OPERATORS:
                        op = double
                        i += 1
                tokens.append(('OPERATOR', op))
                i += 1
                continue
            if ch in self.SEPARATORS:
                if current_token:
                    tokens.append(self.classify_token(current_token))
                    current_token = ''
                tokens.append(('SEPARATOR', ch))
                i += 1
                continue
            if ch.isalpha() or ch == '_':
                word = ''
                while i < n and (code[i].isalnum() or code[i] == '_'):
                    word += code[i]
                    i += 1
                if word in self.KEYWORDS:
                    tokens.append(('KEYWORD', word))
                elif word in self.PRIMITIVE_FUNCTIONS:
                    tokens.append(('PRIMITIVE_FUNCTION', word))
                else:
                    tokens.append(('IDENTIFIER', word))
                continue
            if ch == '#':
                directive = ''
                while i < n and not code[i].isspace():
                    directive += code[i]
                    i += 1
                if directive in self.PREPROCESSOR_DIRECTIVES:
                    tokens.append(('PREPROCESSOR_DIRECTIVE', directive))
                else:
                    tokens.append(('OTHER', directive))
                continue
            if ch in self.SPECIAL_SYMBOLS:
                if current_token:
                    tokens.append(self.classify_token(current_token))
                    current_token = ''
                tokens.append(('SPECIAL_SYMBOL', ch))
                i += 1
                continue
            if ch.isdigit():
                num = ''
                while i < n and (code[i].isdigit() or code[i] == '.'):
                    num += code[i]
                    i += 1
                if '.' in num:
                    tokens.append(('FLOAT', num))
                else:
                    tokens.append(('INTEGER', num))
                continue
            current_token += ch
            i += 1
        if current_token:
            tokens.append(self.classify_token(current_token))
        return tokens, comments

    def remove_comments(self, code):
        multiline = re.findall(r'/\*.*?\*/', code, flags=re.DOTALL)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        singleline = re.findall(r'//.*', code)
        code = re.sub(r'//.*', '', code)
        return code, multiline + singleline

    def classify_token(self, token):
        if token in self.KEYWORDS:
            return ('KEYWORD', token)
        if token in self.PRIMITIVE_FUNCTIONS:
            return ('PRIMITIVE_FUNCTION', token)
        if re.match(r'^[0-9]+(\.[0-9]+)?$', token):
            return ('FLOAT', token) if '.' in token else ('INTEGER', token)
        if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', token):
            return ('IDENTIFIER', token)
        return ('OTHER', token)

class ScannerGUI:
    def __init__(self, master):
        self.master = master
        master.title("C Scanner — Compile and Pray")
        self.banner_frame = tk.Frame(master)
        self.banner_frame.pack(fill="x", pady=(6, 4))
        self.banner_canvas = tk.Canvas(self.banner_frame, height=120)
        self.banner_canvas.pack(fill="x", expand=True)
        self.banner_img = None
        local_image_path = self._ensure_image_downloaded()
        self._load_banner_image(local_image_path)
        self.banner_canvas.create_text(10, 10, anchor="nw",
                                       text="💻 Compile and Pray",
                                       font=("Segoe UI", 20, "bold"),
                                       fill="white",
                                       tags="banner_text")
        self._position_banner_text()
        main_frame = tk.Frame(master)
        main_frame.pack(fill="both", expand=True, padx=8, pady=4)
        self.input_text = scrolledtext.ScrolledText(main_frame, width=80, height=12)
        self.input_text.pack(side="left", fill="both", expand=True)
        controls = tk.Frame(main_frame)
        controls.pack(side="left", fill="y", padx=6)
        scan_btn = tk.Button(controls, text="Scan", width=14, command=self.scan_code)
        scan_btn.pack(pady=6)
        bottom = tk.Frame(master)
        bottom.pack(fill="both", expand=True, padx=8, pady=(4, 10))
        self.output_text = scrolledtext.ScrolledText(bottom, width=50, height=12)
        self.output_text.pack(side="left", fill="both", expand=True, padx=(0, 4))
        self.colored_output = scrolledtext.ScrolledText(bottom, width=50, height=12)
        self.colored_output.pack(side="left", fill="both", expand=True)
        self._configure_tags()
        self.status = tk.Label(master, text="Ready", anchor="w")
        self.status.pack(fill="x", padx=8, pady=(4, 6))
        self.master.bind("<Configure>", lambda e: self._position_banner_text())

    def _ensure_image_downloaded(self):
        try:
            tmpdir = tempfile.gettempdir()
            for ext in (".png", ".jpg", ".jpeg", ".gif", ".bmp", ""):
                local_name = LOCAL_IMAGE_NAME + ext
                local_path = os.path.join(tmpdir, local_name)
                if os.path.exists(local_path):
                    return local_path
            preferred = os.path.join(tmpdir, LOCAL_IMAGE_NAME + ".png")
            urllib.request.urlretrieve(IMAGE_URL, preferred)
            return preferred
        except Exception:
            return None

    def _load_banner_image(self, path):
        try:
            from PIL import Image, ImageTk
            if path and os.path.exists(path):
                try:
                    img = Image.open(path)
                    banner_h = 120
                    w, h = img.size
                    new_w = int((banner_h / h) * w)
                    img = img.resize((new_w, banner_h), Image.LANCZOS)
                    self.banner_img = ImageTk.PhotoImage(img)
                    self.banner_canvas.create_image(0, 0, anchor="nw", image=self.banner_img, tags="banner_img")
                    return
                except Exception:
                    pass
        except Exception:
            pass
        try:
            if path and os.path.exists(path):
                self.banner_img = tk.PhotoImage(file=path)
                img_h = self.banner_img.height()
                if img_h > 120:
                    factor = max(1, img_h // 120)
                    self.banner_img = self.banner_img.subsample(factor, factor)
                self.banner_canvas.create_image(0, 0, anchor="nw", image=self.banner_img, tags="banner_img")
                return
        except Exception:
            pass
        self.banner_canvas.create_rectangle(0, 0, 2000, 120, fill="#333333", outline="")

    def _position_banner_text(self):
        self.banner_canvas.delete("banner_text")
        self.banner_canvas.delete("banner_text_shadow")
        w = self.banner_canvas.winfo_width()
        h = self.banner_canvas.winfo_height()
        if w <= 1:
            return
        x = w // 2
        y = h // 2
        self.banner_canvas.create_text(x + 2, y + 2, text="💻 Compile and Pray",
                                       font=("Segoe UI", 20, "bold"), fill="#111111",
                                       tags="banner_text_shadow")
        self.banner_canvas.create_text(x, y, text="💻 Compile and Pray",
                                       font=("Segoe UI", 20, "bold"), fill="white",
                                       tags="banner_text")

    def _configure_tags(self):
        self.colored_output.tag_config("KEYWORD", foreground="blue")
        self.colored_output.tag_config("PRIMITIVE_FUNCTION", foreground="green")
        self.colored_output.tag_config("INTEGER", foreground="orange")
        self.colored_output.tag_config("FLOAT", foreground="orange")
        self.colored_output.tag_config("IDENTIFIER", foreground="black")
        self.colored_output.tag_config("OPERATOR", foreground="red")
        self.colored_output.tag_config("SEPARATOR", foreground="purple")
        self.colored_output.tag_config("STRING_LITERAL", foreground="brown")
        self.colored_output.tag_config("PREPROCESSOR_DIRECTIVE", foreground="magenta")
        self.colored_output.tag_config("SPECIAL_SYMBOL", foreground="cyan")
        self.colored_output.tag_config("OTHER", foreground="gray")

    def scan_code(self):
        code = self.input_text.get("1.0", "end-1c")
        if not code.strip():
            messagebox.showinfo("Info", "Please paste or type C code to scan.")
            return
        lexer = CLexicalAnalyzer()
        tokens, comments = lexer.analyze(code)
        self.output_text.delete("1.0", "end")
        self.colored_output.delete("1.0", "end")
        for ttype, val in tokens:
            self.output_text.insert("end", f"Token Type: {ttype}, Token Value: {val}\n")
        if comments:
            self.output_text.insert("end", "\nComments:\n")
            for c in comments:
                self.output_text.insert("end", c + "\n")
        for ttype, val in tokens:
            tag = ttype if ttype in ("KEYWORD", "PRIMITIVE_FUNCTION", "INTEGER", "FLOAT",
                                     "IDENTIFIER", "OPERATOR", "SEPARATOR", "STRING_LITERAL",
                                     "PREPROCESSOR_DIRECTIVE", "SPECIAL_SYMBOL") else "OTHER"
            self.colored_output.insert("end", val + " ", tag)
        self.status.config(text=f"Scan complete — {len(tokens)} tokens")

    def load_file(self):
        path = filedialog.askopenfilename(title="Open C file", filetypes=[("C files", "*.c;*.h"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.input_text.delete("1.0", "end")
            self.input_text.insert("1.0", content)
            self.status.config(text=f"Loaded: {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Can't open file: {e}")

    def clear_all(self):
        self.input_text.delete("1.0", "end")
        self.output_text.delete("1.0", "end")
        self.colored_output.delete("1.0", "end")
        self.status.config(text="Cleared")

    def copy_tokens(self):
        data = self.output_text.get("1.0", "end-1c")
        if not data.strip():
            messagebox.showinfo("Info", "No tokens to copy.")
            return
        self.master.clipboard_clear()
        self.master.clipboard_append(data)
        self.status.config(text="Tokens copied to clipboard")

def main():
    root = tk.Tk()
    root.geometry("1000x700")
    app = ScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
