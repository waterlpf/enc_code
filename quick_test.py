'''
Author: pf.li pf.li@example.com
Date: 2026-03-21 11:00:48
LastEditors: pf.li pf.li@example.com
LastEditTime: 2026-03-23 10:44:25
FilePath: /enc/quick_test.py
Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
'''
from hybrid_crypto import HybridCrypto
import os

# 设置路径
enc_file = './test_message.enc'
key_file = './private.pem'

print("=== Python 解密 Java 加密文件测试 ===")
print()

# 1. 检查文件是否加密
print("1. 检查文件是否加密...")
is_enc = HybridCrypto.is_encrypt_file(enc_file)
print(f"   结果: {is_enc}")
print()

if not is_enc:
    print("文件不是加密格式!")
    exit(1)

# 2. 读取加密文件（字符串方式）
print("2. 读取加密文件（字符串方式）...")
crypto = HybridCrypto()
content = crypto.read_encrypt_file_to_string(enc_file, key_file)
if content:
    print(f"   成功! 内容长度: {len(content)} 字符")
    print(f"   内容预览:")
    print("   " + "-" * 40)
    preview = content[:200] if len(content) > 200 else content
    for line in preview.split('\n')[:5]:
        print(f"   {line}")
    if len(content) > 200:
        print("   ...")
    print("   " + "-" * 40)
else:
    print("   失败!")
print()

# 3. 读取加密文件（字节方式）
print("3. 读取加密文件（字节方式）...")
data = crypto.read_encrypt_file_to_bytes(enc_file, key_file)
if data:
    print(f"   成功! 数据大小: {len(data)} 字节")
else:
    print("   失败!")
print()

# 4. 读取加密文件（流方式）
print("4. 读取加密文件（流方式）...")
output_file = './python_decrypted.txt'
with open(output_file, 'wb') as f:
    success = crypto.read_encrypt_file(enc_file, key_file, f)
if success:
    print(f"   成功! 已保存到: {output_file}")
    print(f"   文件大小: {os.path.getsize(output_file)} 字节")
else:
    print("   失败!")
print()

print("=== 测试完成 ===")
