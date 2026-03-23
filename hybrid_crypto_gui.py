"""
HybridCrypto 图形化工具
功能:
a) 生成/加载公钥私钥
b) 使用公钥加密文件
c) 使用私钥解密文件

依赖:
    pip install cryptography
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from hybrid_crypto import HybridCrypto


class HybridCryptoTool:
    def __init__(self, root):
        self.root = root
        self.root.title("HybridCrypto 加密工具")
        self.root.geometry("700x600")
        
        self.crypto = HybridCrypto()
        self.default_private_key = "private.pem"
        self.default_public_key = "public.pem"
        
        self._init_ui()
        self._load_default_keys()
    
    def _init_ui(self):
        """初始化UI"""
        # 标题
        title_label = tk.Label(self.root, text="混合加密工具", font=("Arial", 18, "bold"))
        title_label.pack(pady=10)
        
        # 密钥管理框架
        key_frame = ttk.LabelFrame(self.root, text="密钥管理", padding=10)
        key_frame.pack(fill="x", padx=10, pady=5)
        
        # 密钥路径
        ttk.Label(key_frame, text="私钥:").grid(row=0, column=0, sticky="w", pady=5)
        self.private_key_var = tk.StringVar(value=self.default_private_key)
        ttk.Entry(key_frame, textvariable=self.private_key_var, width=40).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(key_frame, text="浏览", command=lambda: self._browse_file(self.private_key_var)).grid(row=0, column=2, padx=5)
        ttk.Button(key_frame, text="加载", command=self._load_private_key).grid(row=0, column=3, padx=5)
        
        ttk.Label(key_frame, text="公钥:").grid(row=1, column=0, sticky="w", pady=5)
        self.public_key_var = tk.StringVar(value=self.default_public_key)
        ttk.Entry(key_frame, textvariable=self.public_key_var, width=40).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(key_frame, text="浏览", command=lambda: self._browse_file(self.public_key_var)).grid(row=1, column=2, padx=5)
        ttk.Button(key_frame, text="加载", command=self._load_public_key).grid(row=1, column=3, padx=5)
        
        # 生成新密钥
        ttk.Button(key_frame, text="生成新密钥对", command=self._generate_new_keys).grid(row=2, column=0, columnspan=2, pady=10)
        
        # 状态显示
        self.status_text = tk.StringVar(value="未加载密钥")
        ttk.Label(key_frame, textvariable=self.status_text, foreground="blue").grid(row=2, column=2, columnspan=2, sticky="w")
        
        # 加密框架
        encrypt_frame = ttk.LabelFrame(self.root, text="加密 (使用公钥)", padding=10)
        encrypt_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(encrypt_frame, text="选择文件:").grid(row=0, column=0, sticky="w", pady=5)
        self.encrypt_file_var = tk.StringVar()
        ttk.Entry(encrypt_frame, textvariable=self.encrypt_file_var, width=50).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(encrypt_frame, text="浏览", command=lambda: self._browse_file(self.encrypt_file_var)).grid(row=0, column=2, padx=5)
        
        ttk.Button(encrypt_frame, text="加密文件", command=self._encrypt_file).grid(row=1, column=0, pady=10)
        ttk.Button(encrypt_frame, text="加密并显示结果", command=self._encrypt_and_show).grid(row=1, column=1, pady=10)
        
        # 解密框架
        decrypt_frame = ttk.LabelFrame(self.root, text="解密 (使用私钥)", padding=10)
        decrypt_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(decrypt_frame, text="选择文件:").grid(row=0, column=0, sticky="w", pady=5)
        self.decrypt_file_var = tk.StringVar()
        ttk.Entry(decrypt_frame, textvariable=self.decrypt_file_var, width=50).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(decrypt_frame, text="浏览", command=lambda: self._browse_file(self.decrypt_file_var)).grid(row=0, column=2, padx=5)
        
        ttk.Button(decrypt_frame, text="解密文件", command=self._decrypt_file).grid(row=1, column=0, pady=10)
        ttk.Button(decrypt_frame, text="解密并显示结果", command=self._decrypt_and_show).grid(row=1, column=1, pady=10)
        
        # 结果显示框架
        result_frame = ttk.LabelFrame(self.root, text="结果/内容显示", padding=10)
        result_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, height=10, wrap="word")
        self.result_text.pack(fill="both", expand=True)
        
        # 清空结果显示
        ttk.Button(result_frame, text="清空", command=lambda: self.result_text.delete("1.0", "end")).pack(pady=5)
    
    def _browse_file(self, var):
        """浏览文件"""
        filename = filedialog.askopenfilename()
        if filename:
            var.set(filename)
    
    def _load_default_keys(self):
        """加载默认密钥"""
        # 加载私钥
        if os.path.exists(self.default_private_key):
            if self.crypto.load_keys(private_key_path=self.default_private_key):
                self.status_text.set(f"已加载私钥: {self.default_private_key}")
        
        # 加载公钥
        if os.path.exists(self.default_public_key):
            if self.crypto.load_keys(public_key_path=self.default_public_key):
                status = self.status_text.get()
                if "已加载私钥" in status:
                    self.status_text.set(status + ", 已加载公钥")
                else:
                    self.status_text.set(f"已加载公钥: {self.default_public_key}")
    
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
            self.status_text.set(f"私钥加载成功: {path}")
            messagebox.showinfo("成功", f"私钥加载成功: {path}")
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
                self.status_text.set(status + ", 公钥加载成功")
            else:
                self.status_text.set(f"公钥加载成功: {path}")
            messagebox.showinfo("成功", f"公钥加载成功: {path}")
        else:
            messagebox.showerror("错误", "公钥加载失败")
    
    def _generate_new_keys(self):
        """生成新密钥对"""
        private_path = filedialog.asksaveasfilename(title="保存私钥", defaultextension=".pem", filetypes=[("PEM文件", "*.pem")])
        if not private_path:
            return
        
        public_path = filedialog.asksaveasfilename(title="保存公钥", defaultextension=".pem", filetypes=[("PEM文件", "*.pem")])
        if not public_path:
            return
        
        # 生成密钥
        self.crypto.generate_key_pair()
        self.crypto.save_keys(private_path, public_path)
        
        # 更新界面
        self.private_key_var.set(private_path)
        self.public_key_var.set(public_path)
        self.status_text.set("新密钥对生成成功")
        
        messagebox.showinfo("成功", f"密钥对已生成并保存:\n私钥: {private_path}\n公钥: {public_path}")
    
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
        
        # 加密文件
        if self.crypto.encrypt_file(file_path):
            messagebox.showinfo("成功", f"文件加密成功: {file_path}")
            self.result_text.insert("end", f"加密成功: {file_path}\n")
        else:
            messagebox.showerror("失败", "文件加密失败")
    
    def _encrypt_and_show(self):
        """加密并显示结果"""
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
        
        try:
            # 读取原文件
            with open(file_path, "rb") as f:
                original_data = f.read()
            
            # 加密
            encrypted = self.crypto.encrypt_bytes(original_data)
            if encrypted is None:
                messagebox.showerror("失败", "加密失败")
                return
            
            # 显示加密结果(十六进制)
            hex_display = encrypted.hex()[:500]  # 限制显示长度
            if len(encrypted) > 500:
                hex_display += f"\n... (共 {len(encrypted)} 字节)"
            
            self.result_text.delete("1.0", "end")
            self.result_text.insert("end", f"=== 加密结果 ===\n")
            self.result_text.insert("end", f"原始文件: {file_path}\n")
            self.result_text.insert("end", f"原始大小: {len(original_data)} 字节\n")
            self.result_text.insert("end", f"加密后大小: {len(encrypted)} 字节\n\n")
            self.result_text.insert("end", f"加密数据(HEX):\n{hex_display}\n")
            
            messagebox.showinfo("成功", "加密成功，结果已显示")
            
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")
    
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
        
        # 检查是否为加密文件
        if not HybridCrypto.is_encrypt_file(file_path):
            messagebox.showwarning("警告", "该文件可能不是加密文件")
        
        # 保存解密文件
        save_path = filedialog.asksaveasfilename(title="保存解密文件", defaultextension=".txt", filetypes=[("所有文件", "*.*")])
        if not save_path:
            return
        
        try:
            # 解密到文件
            crypto = HybridCrypto()
            crypto.load_keys(private_key_path=self.private_key_var.get())
            
            with open(save_path, "wb") as out_file:
                if crypto.read_encrypt_file(file_path, self.private_key_var.get(), out_file):
                    messagebox.showinfo("成功", f"文件解密成功: {save_path}")
                    self.result_text.insert("end", f"解密成功: {save_path}\n")
                else:
                    messagebox.showerror("失败", "文件解密失败")
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")
    
    def _decrypt_and_show(self):
        """解密并显示结果"""
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
        
        try:
            # 解密
            decrypted = self.crypto.read_encrypt_file_to_bytes(file_path, self.private_key_var.get())
            
            if decrypted is None:
                messagebox.showerror("失败", "解密失败，请检查密钥是否正确")
                return
            
            # 尝试显示为文本
            try:
                text_content = decrypted.decode('utf-8')
                self.result_text.delete("1.0", "end")
                self.result_text.insert("end", f"=== 解密结果 ===\n")
                self.result_text.insert("end", f"加密文件: {file_path}\n")
                self.result_text.insert("end", f"解密后大小: {len(decrypted)} 字节\n\n")
                self.result_text.insert("end", f"文本内容:\n{text_content}\n")
            except UnicodeDecodeError:
                # 二进制文件
                hex_display = decrypted.hex()[:500]
                if len(decrypted) > 500:
                    hex_display += f"\n... (共 {len(decrypted)} 字节)"
                
                self.result_text.delete("1.0", "end")
                self.result_text.insert("end", f"=== 解密结果 ===\n")
                self.result_text.insert("end", f"加密文件: {file_path}\n")
                self.result_text.insert("end", f"解密后大小: {len(decrypted)} 字节\n")
                self.result_text.insert("end", f"(二进制内容，使用HEX显示)\n\n")
                self.result_text.insert("end", f"数据(HEX):\n{hex_display}\n")
            
            messagebox.showinfo("成功", "解密成功，结果已显示")
            
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")


def main():
    root = tk.Tk()
    app = HybridCryptoTool(root)
    root.mainloop()


if __name__ == "__main__":
    main()
