"""
hybrid_crypto.py 功能测试案例
测试内容:
a) 产生公钥私钥
b) 使用公钥进行加密
c) 使用私钥进行解密
"""

import os
import tempfile
from hybrid_crypto import HybridCrypto


def test_generate_and_save_keys():
    """测试 a) 产生公钥私钥"""
    print("=" * 50)
    print("测试 a) 产生公钥私钥")
    print("=" * 50)
    
    crypto = HybridCrypto()
    
    # 生成密钥对
    private_key, public_key = crypto.generate_key_pair()
    assert private_key is not None, "私钥生成失败"
    assert public_key is not None, "公钥生成失败"
    print(f"1. 密钥对生成成功")
    
    # 保存密钥到临时文件
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='_private.pem') as f:
        private_path = f.name
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='_public.pem') as f:
        public_path = f.name
    
    crypto.save_keys(private_path, public_path)
    
    # 验证文件存在
    assert os.path.exists(private_path), "私钥文件未创建"
    assert os.path.exists(public_path), "公钥文件未创建"
    print(f"2. 密钥文件已保存")
    
    # 验证 PEM 格式
    with open(private_path, 'rb') as f:
        private_pem = f.read()
    with open(public_path, 'rb') as f:
        public_pem = f.read()
    
    assert b'-----BEGIN PRIVATE KEY-----' in private_pem, "私钥 PEM 格式错误"
    assert b'-----BEGIN PUBLIC KEY-----' in public_pem, "公钥 PEM 格式错误"
    print(f"3. PEM 格式验证通过")
    
    # 清理
    os.remove(private_path)
    os.remove(public_path)
    print("测试通过!\n")
    return True


def test_encrypt_with_public_key():
    """测试 b) 使用公钥进行加密"""
    print("=" * 50)
    print("测试 b) 使用公钥进行加密")
    print("=" * 50)
    
    # 创建加密对象并生成密钥
    crypto = HybridCrypto()
    crypto.generate_key_pair()
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='_private.pem') as f:
        private_path = f.name
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='_public.pem') as f:
        public_path = f.name
    
    crypto.save_keys(private_path, public_path)
    
    # 使用公钥加密
    crypto2 = HybridCrypto()
    crypto2.load_keys(public_key_path=public_path)
    
    test_data = b"Hello World! Test encryption with public key."
    encrypted = crypto2.encrypt_bytes(test_data)
    
    assert encrypted is not None, "加密失败"
    assert len(encrypted) > len(test_data), "加密数据长度异常"
    
    # 验证加密文件格式
    assert encrypted[:7] == b"HANGSHU", "魔数不匹配"
    print(f"1. 字节加密成功, 原始长度: {len(test_data)}, 加密长度: {len(encrypted)}")
    
    # 测试文件加密
    test_content = "测试中文内容 Test Content 12345"
    test_file = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt')
    test_file.write(test_content)
    test_file.close()
    
    crypto2.encrypt_file(test_file.name)
    
    assert HybridCrypto.is_encrypt_file(test_file.name), "文件加密失败"
    print(f"2. 文件加密成功")
    
    # 清理
    os.remove(private_path)
    os.remove(public_path)
    os.remove(test_file.name)
    print("测试通过!\n")
    return True


def test_decrypt_with_private_key():
    """测试 c) 使用私钥进行解密"""
    print("=" * 50)
    print("测试 c) 使用私钥进行解密")
    print("=" * 50)
    
    # 创建加密对象并生成密钥
    crypto = HybridCrypto()
    crypto.generate_key_pair()
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='_private.pem') as f:
        private_path = f.name
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='_public.pem') as f:
        public_path = f.name
    
    crypto.save_keys(private_path, public_path)
    
    # 加密数据
    crypto2 = HybridCrypto()
    crypto2.load_keys(public_key_path=public_path)
    
    test_data = "测试中文解密 Test Decryption 98765"
    encrypted = crypto2.encrypt_bytes(test_data.encode('utf-8'))
    assert encrypted is not None, "加密失败"
    print(f"1. 数据加密成功")
    
    # 解密 - 加载私钥
    crypto3 = HybridCrypto()
    crypto3.load_keys(private_key_path=private_path)
    
    # 使用 read_encrypt_file_to_string 解密
    # 需要先写入加密文件
    test_file = tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.enc')
    test_file.write(encrypted)
    test_file.close()
    
    decrypted = crypto3.read_encrypt_file_to_string(test_file.name, private_path)
    
    assert decrypted == test_data, f"解密内容不匹配: {decrypted} != {test_data}"
    print(f"2. 文件解密成功, 内容一致")
    
    # 测试 decrypt_bytes 方法
    crypto4 = HybridCrypto()
    crypto4.load_keys(private_key_path=private_path)
    decrypted_bytes = crypto4.read_encrypt_file_to_bytes(test_file.name, private_path)
    assert decrypted_bytes.decode('utf-8') == test_data, "字节解密失败"
    print(f"3. 字节解密成功")
    
    # 清理
    os.remove(private_path)
    os.remove(public_path)
    os.remove(test_file.name)
    print("测试通过!\n")
    return True


def test_full_workflow():
    """完整流程测试"""
    print("=" * 50)
    print("完整流程测试: 加密 -> 解密")
    print("=" * 50)
    
    # 1. 生成密钥
    crypto = HybridCrypto()
    crypto.generate_key_pair()
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='_private.pem') as f:
        private_path = f.name
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='_public.pem') as f:
        public_path = f.name
    
    crypto.save_keys(private_path, public_path)
    print("1. 密钥生成完成")
    
    # 2. 加密文件
    crypto_enc = HybridCrypto()
    crypto_enc.load_keys(public_key_path=public_path)
    
    test_file = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt')
    test_content = "完整的测试内容 1234567890 ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    test_file.write(test_content)
    test_file.close()
    original_size = os.path.getsize(test_file.name)
    
    crypto_enc.encrypt_file(test_file.name)
    encrypted_size = os.path.getsize(test_file.name)
    print(f"2. 文件加密完成, 原始大小: {original_size}, 加密后: {encrypted_size}")
    
    # 3. 解密文件
    crypto_dec = HybridCrypto()
    decrypted_content = crypto_dec.read_encrypt_file_to_string(test_file.name, private_path)
    
    assert decrypted_content == test_content, "解密内容不匹配"
    print(f"3. 文件解密完成, 内容一致")
    
    # 4. 验证是加密文件
    assert HybridCrypto.is_encrypt_file(test_file.name), "加密文件验证失败"
    print(f"4. 加密文件验证通过")
    
    # 清理
    os.remove(private_path)
    os.remove(public_path)
    os.remove(test_file.name)
    print("\n完整流程测试通过!\n")
    return True


def main():
    """运行所有测试"""
    print("\n" + "=" * 50)
    print("HybridCrypto 测试套件")
    print("=" * 50 + "\n")
    
    all_passed = True
    
    try:
        test_generate_and_save_keys()
    except Exception as e:
        print(f"测试失败: {e}")
        all_passed = False
    
    try:
        test_encrypt_with_public_key()
    except Exception as e:
        print(f"测试失败: {e}")
        all_passed = False
    
    try:
        test_decrypt_with_private_key()
    except Exception as e:
        print(f"测试失败: {e}")
        all_passed = False
    
    try:
        test_full_workflow()
    except Exception as e:
        print(f"测试失败: {e}")
        all_passed = False
    
    print("=" * 50)
    if all_passed:
        print("所有测试通过!")
    else:
        print("部分测试失败!")
    print("=" * 50)


if __name__ == "__main__":
    main()
