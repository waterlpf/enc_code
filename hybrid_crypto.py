"""
混合加密文件管理器 - Python 实现
与 Java HybridFileManager 兼容

技术规范:
- RSA: 2048-bit, PKCS1Padding
- AES: 128-bit, GCM mode
- GCM Tag: 128-bit (16 bytes)
- IV: 96-bit (12 bytes)
- 密钥格式: PEM
- 字节序: 大端序 (Big-Endian)

文件格式:
[MAGIC(7): "HANGSHU"] [VERSION(4)] [encKeyLen(4)] [encKey(N)] [IV(12)] [dataLen(4)] [data(M)]

对外提供的方法:
1. 判断文件是否加密: is_encrypt_file(file_path)
2. 读取加密文件（返回流）: read_encrypt_file(input_path, private_key_path, output_stream)

依赖:
    pip install cryptography
"""

import os
import struct
import io
from typing import Optional, BinaryIO
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


class HybridCrypto:
    """混合加密文件管理器 - Python 实现"""

    # 常量定义
    MAGIC_HEADER = b"HANGSHU"
    MAGIC_SIZE = 7
    VERSION = 1
    AES_KEY_SIZE = 16  # 128-bit
    GCM_TAG_LENGTH = 16  # 128-bit
    IV_SIZE = 12  # 96-bit

    def __init__(self):
        self._private_key = None

    # ==================== 1. 判断文件是否加密 ====================

    @staticmethod
    def is_encrypt_file(file_path: str) -> bool:
        """
        检查文件是否为加密文件

        Args:
            file_path: 文件路径

        Returns:
            true 如果是加密文件
        """
        try:
            if not os.path.exists(file_path):
                return False

            file_size = os.path.getsize(file_path)
            if file_size < HybridCrypto.MAGIC_SIZE + 16:
                return False

            with open(file_path, "rb") as f:
                magic = f.read(HybridCrypto.MAGIC_SIZE)

            return magic == HybridCrypto.MAGIC_HEADER
        except Exception:
            return False

    # ==================== 2. 读取加密文件（返回流） ====================

    def read_encrypt_file(self, input_path: str, 
                          private_key_path: str,
                          output_stream: BinaryIO) -> bool:
        """
        读取加密文件（解密后输出到流）

        Args:
            input_path: 加密文件路径
            private_key_path: 私钥文件路径 (PEM格式)
            output_stream: 输出流 (如 open() 返回的文件对象或 io.BytesIO)

        Returns:
            是否成功
        """
        # 加载私钥
        if not self._load_private_key_from_pem(private_key_path):
            print(f"加载私钥失败: {private_key_path}")
            return False

        # 读取加密文件
        try:
            with open(input_path, "rb") as f:
                encrypted_data = f.read()
        except Exception as e:
            print(f"无法打开输入文件: {input_path}, 错误: {e}")
            return False

        # 解密数据
        decrypted_data = self._decrypt(encrypted_data)
        if decrypted_data is None:
            return False

        # 写入输出流
        try:
            output_stream.write(decrypted_data)
            return True
        except Exception as e:
            print(f"写入输出流失败: {e}")
            return False

    def read_encrypt_file_to_string(self, input_path: str, 
                                    private_key_path: str) -> Optional[str]:
        """
        读取加密文件（返回字符串）

        Args:
            input_path: 加密文件路径
            private_key_path: 私钥文件路径 (PEM格式)

        Returns:
            解密后的字符串，失败返回 None
        """
        # 加载私钥
        if not self._load_private_key_from_pem(private_key_path):
            print(f"加载私钥失败: {private_key_path}")
            return None

        # 读取加密文件
        try:
            with open(input_path, "rb") as f:
                encrypted_data = f.read()
        except Exception as e:
            print(f"无法打开输入文件: {input_path}, 错误: {e}")
            return None

        # 解密数据
        decrypted_data = self._decrypt(encrypted_data)
        if decrypted_data is None:
            return None

        # 转换为字符串
        try:
            return decrypted_data.decode('utf-8')
        except UnicodeDecodeError as e:
            print(f"解码失败: {e}")
            return None

    def read_encrypt_file_to_bytes(self, input_path: str, 
                                   private_key_path: str) -> Optional[bytes]:
        """
        读取加密文件到内存

        Args:
            input_path: 加密文件路径
            private_key_path: 私钥文件路径 (PEM格式)

        Returns:
            解密后的数据，失败返回 None
        """
        # 加载私钥
        if not self._load_private_key_from_pem(private_key_path):
            print(f"加载私钥失败: {private_key_path}")
            return None

        # 读取加密文件
        try:
            with open(input_path, "rb") as f:
                encrypted_data = f.read()
        except Exception as e:
            print(f"无法打开输入文件: {input_path}, 错误: {e}")
            return None

        # 解密数据
        return self._decrypt(encrypted_data)

    # ==================== 私有方法 ====================

    def _load_private_key_from_pem(self, pem_path: str) -> bool:
        """从 PEM 文件加载私钥"""
        try:
            with open(pem_path, "rb") as f:
                pem_data = f.read()
            self._private_key = serialization.load_pem_private_key(
                pem_data, password=None, backend=default_backend()
            )
            return True
        except Exception as e:
            print(f"加载私钥失败: {e}")
            return False

    def _decrypt(self, encrypted_data: bytes) -> Optional[bytes]:
        """解密数据"""
        if self._private_key is None:
            print("错误: 私钥未加载")
            return None

        try:
            offset = 0

            # 验证魔数
            if encrypted_data[offset:offset + self.MAGIC_SIZE] != self.MAGIC_HEADER:
                print("错误: 无效的加密数据格式 - 魔数不匹配")
                return None
            offset += self.MAGIC_SIZE

            # 读取版本号（大端序）
            version = struct.unpack(">I", encrypted_data[offset:offset + 4])[0]
            offset += 4
            if version != self.VERSION:
                print(f"错误: 不支持的文件版本: {version}")
                return None

            # 读取加密的 AES 密钥长度
            enc_key_len = struct.unpack(">I", encrypted_data[offset:offset + 4])[0]
            offset += 4

            # 读取加密的 AES 密钥
            encrypted_aes_key = encrypted_data[offset:offset + enc_key_len]
            offset += enc_key_len

            # 使用 RSA 私钥解密 AES 密钥
            aes_key = self._private_key.decrypt(
                encrypted_aes_key,
                padding.PKCS1v15()
            )

            # 读取 IV
            iv = encrypted_data[offset:offset + self.IV_SIZE]
            offset += self.IV_SIZE

            # 读取加密数据长度
            data_len = struct.unpack(">I", encrypted_data[offset:offset + 4])[0]
            offset += 4

            # 读取加密数据（包含 GCM tag）
            cipher_text = encrypted_data[offset:offset + data_len]

            # 使用 AES-GCM 解密
            # Python cryptography 库自动处理 GCM tag
            aesgcm = AESGCM(aes_key)
            decrypted_data = aesgcm.decrypt(iv, cipher_text, None)

            return decrypted_data

        except Exception as e:
            print(f"解密失败: {e}")
            return None


# ==================== 使用示例 ====================

def main():
    import sys

    if len(sys.argv) < 2:
        print("用法:")
        print(f"  python {sys.argv[0]} check <file>                    - 检查是否为加密文件")
        print(f"  python {sys.argv[0]} decrypt <in> <out> <key>        - 解密文件")
        sys.exit(1)

    command = sys.argv[1]

    if command == "check" and len(sys.argv) == 3:
        file_path = sys.argv[2]
        if HybridCrypto.is_encrypt_file(file_path):
            print(f"✓ 是加密文件: {file_path}")
        else:
            print(f"✗ 不是加密文件: {file_path}")
        sys.exit(0)

    elif command == "decrypt" and len(sys.argv) == 5:
        input_path = sys.argv[2]
        output_path = sys.argv[3]
        key_path = sys.argv[4]

        # 首先检查是否为加密文件
        if not HybridCrypto.is_encrypt_file(input_path):
            print("错误: 不是加密文件")
            sys.exit(1)

        crypto = HybridCrypto()
        
        try:
            with open(output_path, "wb") as out_file:
                if crypto.read_encrypt_file(input_path, key_path, out_file):
                    print(f"✓ 解密成功: {output_path}")
                    sys.exit(0)
                else:
                    print("✗ 解密失败")
                    sys.exit(1)
        except Exception as e:
            print(f"✗ 解密失败: {e}")
            sys.exit(1)

    else:
        print("参数错误")
        sys.exit(1)


if __name__ == "__main__":
    main()
