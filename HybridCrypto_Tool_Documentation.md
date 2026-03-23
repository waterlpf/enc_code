# HybridCrypto 加密工具使用说明

## 一、工具概述

HybridCrypto 是一款基于混合加密算法的文件加密解密工具，采用 RSA-2048 + AES-GCM 组合加密方案，与 Java 版 HybridFileManager 完全兼容。

### 技术规范

| 参数 | 值 |
|------|-----|
| RSA 密钥长度 | 2048-bit |
| RSA 填充方式 | PKCS1Padding |
| AES 密钥长度 | 128-bit |
| AES 模式 | GCM |
| GCM Tag 长度 | 128-bit (16 bytes) |
| IV 长度 | 96-bit (12 bytes) |
| 密钥格式 | PEM |
| 字节序 | 大端序 (Big-Endian) |

### 文件格式

加密文件采用以下结构：
```
[MAGIC(7): "HANGSHU"] [VERSION(4)] [encKeyLen(4)] [encKey(N)] [IV(12)] [dataLen(4)] [data(M)]
```

---

## 二、环境准备

### 安装依赖

```bash
pip install cryptography
```

### 运行工具

```bash
python hybrid_crypto_gui.py
```

---

## 三、界面说明

### 1. 密钥管理区域

- **私钥**: 显示当前加载的私钥路径
- **公钥**: 显示当前加载的公钥路径
- **浏览按钮**: 选择密钥文件
- **加载按钮**: 加载对应的密钥
- **生成新密钥对**: 创建新的 RSA 密钥对

### 2. 加密区域（使用公钥）

- **选择文件**: 选择需要加密的文件
- **加密文件**: 使用公钥加密文件（覆盖原文件）
- **加密并显示结果**: 加密文件并在下方显示加密数据（十六进制）

### 3. 解密区域（使用私钥）

- **选择文件**: 选择需要解密的加密文件
- **解密文件**: 使用私钥解密文件（保存到新文件）
- **解密并显示结果**: 解密文件并在下方显示解密内容

### 4. 结果显示区域

显示加密/解密的结果，支持文本和十六进制格式查看。

---

## 四、操作指南

### 场景一：使用默认密钥

工具启动时自动加载同目录下的 `private.pem` 和 `public.pem`（如存在），可直接进行加解密操作。

### 场景二：加载指定密钥

1. 在"私钥"输入框中输入密钥路径，或点击"浏览"选择
2. 点击"加载"按钮加载私钥
3. 同样方式加载公钥
4. 状态栏显示加载结果

### 场景三：生成新密钥

1. 点击"生成新密钥对"按钮
2. 在弹窗中选择私钥保存路径
3. 在弹窗中选择公钥保存路径
4. 密钥生成成功，路径自动填入对应输入框

### 场景四：加密文件

**方式一：覆盖原文件**
1. 点击"选择文件"或直接输入文件路径
2. 点击"加密文件"按钮
3. 原文件被加密内容覆盖

**方式二：查看加密结果**
1. 选择要加密的文件
2. 点击"加密并显示结果"
3. 下方显示加密数据的十六进制内容

### 场景五：解密文件

**方式一：保存到新文件**
1. 选择加密文件
2. 点击"解密文件"按钮
3. 在弹窗中选择保存路径
4. 解密后的内容保存到指定文件

**方式二：查看解密内容**
1. 选择加密文件
2. 点击"解密并显示结果"
3. 下方显示解密后的文本内容或十六进制（如果是二进制）

---

## 五、注意事项

1. **密钥安全**: 私钥文件必须妥善保管，丢失后无法解密
2. **密钥匹配**: 加密和解密必须使用同一对密钥
3. **文件覆盖**: "加密文件"会覆盖原文件，请提前备份
4. **加密文件判断**: 可通过 `HybridCrypto.is_encrypt_file()` 方法检查
5. **跨语言兼容**: 加密文件可与 Java 版 HybridFileManager 互操作

---

## 六、命令行接口

除了 GUI 工具，核心模块也支持命令行使用：

```bash
# 检查文件是否为加密文件
python hybrid_crypto.py check <file>

# 解密文件
python hybrid_crypto.py decrypt <input> <output> <private_key>
```

---

## 七、Python API

### 核心类：HybridCrypto

#### 密钥管理

```python
from hybrid_crypto import HybridCrypto

crypto = HybridCrypto()

# 生成密钥对
private_key, public_key = crypto.generate_key_pair()

# 保存密钥
crypto.save_keys('private.pem', 'public.pem')

# 加载密钥
crypto.load_keys('private.pem', 'public.pem')
```

#### 加密

```python
# 加密文件
crypto.encrypt_file('test.txt')

# 加密字节数据
encrypted = crypto.encrypt_bytes(b'hello world')
```

#### 解密

```python
# 解密到文件
crypto.read_encrypt_file('test.txt.enc', 'private.pem', output_file)

# 解密到字符串
content = crypto.read_encrypt_file_to_string('test.txt.enc', 'private.pem')

# 解密到字节
data = crypto.read_encrypt_file_to_bytes('test.txt.enc', 'private.pem')
```

#### 工具方法

```python
# 检查是否为加密文件
is_encrypted = HybridCrypto.is_encrypt_file('test.txt.enc')
```

---

## 八、文件清单

| 文件 | 说明 |
|------|------|
| `hybrid_crypto.py` | 核心加密模块 |
| `hybrid_crypto_gui.py` | GUI 图形界面工具 |
| `test_hybrid_crypto.py` | 功能测试脚本 |
| `private.pem` | 默认私钥 |
| `public.pem` | 默认公钥 |

---

*文档版本: 1.0*
*最后更新: 2026-03-23*
