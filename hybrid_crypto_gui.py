"""
HybridCrypto 图形化工具 v2.1 (带滚动条)
功能:
a) 生成/加载公钥私钥
b) 使用公钥加密文件或文本
c) 使用私钥解密文件或文本

依赖:
    pip install cryptography
"""

import os
import base64
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from hybrid_crypto import HybridCrypto


class HybridCryptoTool:
    def __init__(self, root):
        self.root = root
        self.root.title("HybridCrypto 加密工具 v2.1")
        self.root.geometry("800x650")
        self.root.resizable(True, True)
        
        # 设置主题色
        self.bg_color = "#f5f5f5"
        self.accent_color = "#2196F3"
        self.success_color = "#4CAF50"
        self.warning_color = "#FF9800"
        self.error_color = "#f44336"
        
        self.root.configure(bg=self.bg_color)
        
        self.crypto = HybridCrypto()
        self.default_private_key = "private.pem"
        self.default_public_key = "public.pem"
        
        self._init_ui()
        self._load_default_keys()
    
    def _init_ui(self):
        """初始化UI - 使用Canvas实现滚动"""
        # 创建Canvas和滚动条
        self.canvas = tk.Canvas(self.root, bg=self.bg_color, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg=self.bg_color)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        # 绑定鼠标滚轮
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        
        # 在可滚动框架中添加内容
        self._build_content(self.scrollable_frame)
    
    def _on_mousewheel(self, event):
        """鼠标滚轮滚动"""
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    
    def _build_content(self, parent):
        """构建所有UI内容"""
        # 标题
        title_label = tk.Label(parent, text="HybridCrypto 混合加密工具", 
                              font=("Microsoft YaHei", 20, "bold"),
                              bg=self.bg_color, fg="#333")
        title_label.pack(pady=15)
        
        # 密钥管理框架
        key_frame = tk.LabelFrame(parent, text="密钥管理", 
                                  font=("Microsoft YaHei", 11, "bold"),
                                  bg=self.bg_color, fg="#333",
                                  padx=15, pady=10)
        key_frame.pack(fill="x", padx=15, pady=5)
        
        # 密钥路径行
        key_row1 = tk.Frame(key_frame, bg=self.bg_color)
        key_row1.pack(fill="x", pady=5)
        
        tk.Label(key_row1, text="私钥:", font=("Microsoft YaHei", 10), 
                bg=self.bg_color, width=8, anchor="e").pack(side="left")
        self.private_key_var = tk.StringVar(value=self.default_private_key)
        tk.Entry(key_row1, textvariable=self.private_key_var, font=("Arial", 10), 
                width=45).pack(side="left", padx=5)
        tk.Button(key_row1, text="浏览", font=("Microsoft YaHei", 9),
                 command=lambda: self._browse_file(self.private_key_var),
                 bg="#e0e0e0", relief="flat").pack(side="left", padx=2)
        tk.Button(key_row1, text="加载", font=("Microsoft YaHei", 9),
                 command=self._load_private_key, bg=self.accent_color, fg="white",
                 relief="flat").pack(side="left", padx=2)
        
        key_row2 = tk.Frame(key_frame, bg=self.bg_color)
        key_row2.pack(fill="x", pady=5)
        
        tk.Label(key_row2, text="公钥:", font=("Microsoft YaHei", 10), 
                bg=self.bg_color, width=8, anchor="e").pack(side="left")
        self.public_key_var = tk.StringVar(value=self.default_public_key)
        tk.Entry(key_row2, textvariable=self.public_key_var, font=("Arial", 10), 
                width=45).pack(side="left", padx=5)
        tk.Button(key_row2, text="浏览", font=("Microsoft YaHei", 9),
                 command=lambda: self._browse_file(self.public_key_var),
                 bg="#e0e0e0", relief="flat").pack(side="left", padx=2)
        tk.Button(key_row2, text="加载", font=("Microsoft YaHei", 9),
                 command=self._load_public_key, bg=self.accent_color, fg="white",
                 relief="flat").pack(side="left", padx=2)
        
        key_row3 = tk.Frame(key_frame, bg=self.bg_color)
        key_row3.pack(fill="x", pady=8)
        
        tk.Button(key_row3, text="生成新密钥对", font=("Microsoft YaHei", 10),
                 command=self._generate_new_keys, bg=self.success_color, fg="white",
                 relief="flat", padx=15, pady=5).pack(side="left")
        
        self.status_text = tk.StringVar(value="未加载密钥")
        status_label = tk.Label(key_row3, textvariable=self.status_text, 
                               font=("Microsoft YaHei", 9), bg=self.bg_color, 
                               fg="#666")
        status_label.pack(side="left", padx=15)
        
        # 文本加解密框架
        text_frame = tk.LabelFrame(parent, text="文本加解密 (直接输入/输出)", 
                                   font=("Microsoft YaHei", 11, "bold"),
                                   bg=self.bg_color, fg="#333",
                                   padx=15, pady=10)
        text_frame.pack(fill="both", expand=True, padx=15, pady=5)
        
        # 输入区域
        tk.Label(text_frame, text="输入内容:", font=("Microsoft YaHei", 10), 
                bg=self.bg_color).pack(anchor="w", pady=(0,5))
        
        input_text_frame = tk.Frame(text_frame, bg="white", relief="solid", bd=1)
        input_text_frame.pack(fill="both", expand=True, pady=(0,10))
        
        self.input_text = tk.Text(input_text_frame, font=("Consolas", 10), 
                                  wrap="word", height=5, relief="flat",
                                  bg="white", padx=10, pady=10)
        self.input_text.pack(side="left", fill="both", expand=True)
        
        input_scroll = tk.Scrollbar(input_text_frame, command=self.input_text.yview)
        input_scroll.pack(side="right", fill="y")
        self.input_text.configure(yscrollcommand=input_scroll.set)
        
        # 按钮行
        btn_frame = tk.Frame(text_frame, bg=self.bg_color)
        btn_frame.pack(fill="x", pady=5)
        
        tk.Button(btn_frame, text="加密文本", font=("Microsoft YaHei", 10),
                 command=self._encrypt_text, bg=self.accent_color, fg="white",
                 relief="flat", padx=20, pady=8).pack(side="left", padx=5)
        
        tk.Button(btn_frame, text="解密文本", font=("Microsoft YaHei", 10),
                 command=self._decrypt_text, bg=self.warning_color, fg="white",
                 relief="flat", padx=20, pady=8).pack(side="left", padx=5)
        
        tk.Button(btn_frame, text="清空", font=("Microsoft YaHei", 10),
                 command=self._clear_text, bg="#9e9e9e", fg="white",
                 relief="flat", padx=20, pady=8).pack(side="left", padx=5)
        
        tk.Button(btn_frame, text="复制结果", font=("Microsoft YaHei", 10),
                 command=self._copy_result, bg="#673AB7", fg="white",
                 relief="flat", padx=20, pady=8).pack(side="right", padx=5)
        
        # 输出区域
        tk.Label(text_frame, text="输出结果:", font=("Microsoft YaHei", 10), 
                bg=self.bg_color).pack(anchor="w", pady=(10,5))
        
        output_text_frame = tk.Frame(text_frame, bg="white", relief="solid", bd=1)
        output_text_frame.pack(fill="both", expand=True, pady=(0,5))
        
        self.output_text = tk.Text(output_text_frame, font=("Consolas", 10), 
                                   wrap="word", height=5, relief="flat",
                                   bg="#fafafa", padx=10, pady=10)
        self.output_text.pack(side="left", fill="both", expand=True)
        
        output_scroll = tk.Scrollbar(output_text_frame, command=self.output_text.yview)
        output_scroll.pack(side="right", fill="y")
        self.output_text.configure(yscrollcommand=output_scroll.set)
        
        # 文件加解密框架
        file_frame = tk.LabelFrame(parent, text="文件加解密", 
                                  font=("Microsoft YaHei", 11, "bold"),
                                  bg=self.bg_color, fg="#333",
                                  padx=15, pady=10)
        file_frame.pack(fill="x", padx=15, pady=5)
        
        # 加密文件行
        encrypt_row = tk.Frame(file_frame, bg=self.bg_color)
        encrypt_row.pack(fill="x", pady=3)
        
        tk.Label(encrypt_row, text="加密:", font=("Microsoft YaHei", 10), 
                bg=self.bg_color, width=8, anchor="e").pack(side="left")
        self.encrypt_file_var = tk.StringVar()
        tk.Entry(encrypt_row, textvariable=self.encrypt_file_var, 
                font=("Arial", 10), width=40).pack(side="left", padx=5)
        tk.Button(encrypt_row, text="浏览", font=("Microsoft YaHei", 9),
                 command=lambda: self._browse_file(self.encrypt_file_var),
                 bg="#e0e0e0", relief="flat").pack(side="left", padx=2)
        tk.Button(encrypt_row, text="加密", font=("Microsoft YaHei", 9),
                 command=self._encrypt_file, bg=self.accent_color, fg="white",
                 relief="flat", padx=15).pack(side="left", padx=10)
        
        # 解密文件行
        decrypt_row = tk.Frame(file_frame, bg=self.bg_color)
        decrypt_row.pack(fill="x", pady=3)
        
        tk.Label(decrypt_row, text="解密:", font=("Microsoft YaHei", 10), 
                bg=self.bg_color, width=8, anchor="e").pack(side="left")
        self.decrypt_file_var = tk.StringVar()
        tk.Entry(decrypt_row, textvariable=self.decrypt_file_var, 
                font=("Arial", 10), width=40).pack(side="left", padx=5)
        tk.Button(decrypt_row, text="浏览", font=("Microsoft YaHei", 9),
                 command=lambda: self._browse_file(self.decrypt_file_var),
                 bg="#e0e0e0", relief="flat").pack(side="left", padx=2)
        tk.Button(decrypt_row, text="解密", font=("Microsoft YaHei", 9),
                 command=self._decrypt_file, bg=self.warning_color, fg="white",
                 relief="flat", padx=15).pack(side="left", padx=10)
        
        # 版权信息
        footer = tk.Label(parent, text="HybridCrypto v2.1 | RSA-2048 + AES-GCM", 
                         font=("Arial", 8), bg=self.bg_color, fg="#999")
        footer.pack(pady=15)
    
    def _browse_file(self, var):
        """浏览文件"""
        filename = filedialog.askopenfilename()
        if filename:
            var.set(filename)
    
    def _load_default_keys(self):
        """加载默认密钥"""
        if os.path.exists(self.default_private_key):
            if self.crypto.load_keys(private_key_path=self.default_private_key):
                self.status_text.set(f"已加载私钥")
        
        if os.path.exists(self.default_public_key):
            if self.crypto.load_keys(public_key_path=self.default_public_key):
                status = self.status_text.get()
                if "私钥" in status:
                    self.status_text.set("已加载公钥和私钥")
                else:
                    self.status_text.set("已加载公钥")
    
    def _load_private_key(self):
        """加载私钥"""
        path = self.private_key_var.get()
        if not path:
            messagebox.showwarning("警告", "请输入私钥路径")
            return
        
        if not os.path.exists(path):
            messagebox.showerror("错误", f"文件不存在: {path}")
            return
        
        if self.crypto.load_keys(private_key_path=path):
            self.status_text.set("私钥加载成功")
            messagebox.showinfo("成功", f"私钥加载成功")
        else:
            messagebox.showerror("错误", "私钥加载失败")
    
    def _load_public_key(self):
        """加载公钥"""
        path = self.public_key_var.get()
        if not path:
            messagebox.showwarning("警告", "请输入公钥路径")
            return
        
        if not os.path.exists(path):
            messagebox.showerror("错误", f"文件不存在: {path}")
            return
        
        if self.crypto.load_keys(public_key_path=path):
            status = self.status_text.get()
            if "私钥" in status:
                self.status_text.set("已加载公钥和私钥")
            else:
                self.status_text.set("公钥加载成功")
            messagebox.showinfo("成功", f"公钥加载成功")
        else:
            messagebox.showerror("错误", "公钥加载失败")
    
    def _generate_new_keys(self):
        """生成新密钥对"""
        private_path = filedialog.asksaveasfilename(
            title="保存私钥", defaultextension=".pem", 
            filetypes=[("PEM文件", "*.pem")])
        if not private_path:
            return
        
        public_path = filedialog.asksaveasfilename(
            title="保存公钥", defaultextension=".pem", 
            filetypes=[("PEM文件", "*.pem")])
        if not public_path:
            return
        
        self.crypto.generate_key_pair()
        self.crypto.save_keys(private_path, public_path)
        
        self.private_key_var.set(private_path)
        self.public_key_var.set(public_path)
        self.status_text.set("新密钥对生成成功")
        
        messagebox.showinfo("成功", f"密钥对已生成:\n私钥: {private_path}\n公钥: {public_path}")
    
    def _encrypt_text(self):
        """加密文本"""
        input_content = self.input_text.get("1.0", "end").strip()
        if not input_content:
            messagebox.showwarning("警告", "请输入要加密的内容")
            return
        
        if self.crypto._public_key is None:
            messagebox.showerror("错误", "请先加载公钥")
            return
        
        try:
            data = input_content.encode('utf-8')
            encrypted = self.crypto.encrypt_bytes(data)
            
            if encrypted is None:
                messagebox.showerror("失败", "加密失败")
                return
            
            b64_result = base64.b64encode(encrypted).decode('ascii')
            
            self.output_text.delete("1.0", "end")
            self.output_text.insert("1.0", b64_result)
            
            messagebox.showinfo("成功", "加密成功！结果已显示在输出框，可复制")
            
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")
    
    def _decrypt_text(self):
        """解密文本"""
        input_content = self.input_text.get("1.0", "end").strip()
        if not input_content:
            messagebox.showwarning("警告", "请输入要解密的内容")
            return
        
        if self.crypto._private_key is None:
            messagebox.showerror("错误", "请先加载私钥")
            return
        
        try:
            try:
                encrypted = base64.b64decode(input_content)
            except Exception:
                messagebox.showerror("错误", "输入内容不是有效的 Base64 编码")
                return
            
            crypto = HybridCrypto()
            crypto.load_keys(private_key_path=self.private_key_var.get())
            decrypted = crypto._decrypt(encrypted)
            
            if decrypted is None:
                messagebox.showerror("失败", "解密失败，请检查密钥是否正确")
                return
            
            text_content = decrypted.decode('utf-8')
            
            self.output_text.delete("1.0", "end")
            self.output_text.insert("1.0", text_content)
            
            messagebox.showinfo("成功", "解密成功！结果已显示在输出框，可复制")
            
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")
    
    def _clear_text(self):
        """清空文本"""
        self.input_text.delete("1.0", "end")
        self.output_text.delete("1.0", "end")
    
    def _copy_result(self):
        """复制结果"""
        content = self.output_text.get("1.0", "end").strip()
        if not content:
            messagebox.showwarning("警告", "没有可复制的内容")
            return
        
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        messagebox.showinfo("成功", "结果已复制到剪贴板")
    
    def _encrypt_file(self):
        """加密文件"""
        file_path = self.encrypt_file_var.get()
        if not file_path:
            messagebox.showwarning("警告", "请选择要加密的文件")
            return
        
        if not os.path.exists(file_path):
            messagebox.showerror("错误", f"文件不存在: {file_path}")
            return
        
        if self.crypto._public_key is None:
            messagebox.showerror("错误", "请先加载公钥")
            return
        
        if self.crypto.encrypt_file(file_path):
            messagebox.showinfo("成功", f"文件加密成功: {file_path}")
        else:
            messagebox.showerror("失败", "文件加密失败")
    
    def _decrypt_file(self):
        """解密文件"""
        file_path = self.decrypt_file_var.get()
        if not file_path:
            messagebox.showwarning("警告", "请选择要解密的文件")
            return
        
        if not os.path.exists(file_path):
            messagebox.showerror("错误", f"文件不存在: {file_path}")
            return
        
        if self.crypto._private_key is None:
            messagebox.showerror("错误", "请先加载私钥")
            return
        
        if not HybridCrypto.is_encrypt_file(file_path):
            messagebox.showwarning("警告", "该文件可能不是加密文件")
        
        save_path = filedialog.asksaveasfilename(
            title="保存解密文件", defaultextension=".txt", 
            filetypes=[("所有文件", "*.*")])
        if not save_path:
            return
        
        try:
            crypto = HybridCrypto()
            crypto.load_keys(private_key_path=self.private_key_var.get())
            
            with open(save_path, "wb") as out_file:
                if crypto.read_encrypt_file(file_path, self.private_key_var.get(), out_file):
                    messagebox.showinfo("成功", f"文件解密成功: {save_path}")
                else:
                    messagebox.showerror("失败", "文件解密失败")
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")


def main():
    root = tk.Tk()
    app = HybridCryptoTool(root)
    root.mainloop()


if __name__ == "__main__":
    main()
