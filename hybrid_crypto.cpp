/**
 * 混合加密文件管理器 - C++ 实现
 * 与 Java HybridFileManager 兼容
 *
 * 技术规范:
 * - RSA: 2048-bit, PKCS1Padding
 * - AES: 128-bit, GCM mode
 * - GCM Tag: 128-bit (16 bytes)
 * - IV: 96-bit (12 bytes)
 * - 密钥格式: PEM
 * - 字节序: 大端序 (Big-Endian)
 *
 * 文件格式:
 * [MAGIC(7): "HANGSHU"] [VERSION(4)] [encKeyLen(4)] [encKey(N)] [IV(12)] [dataLen(4)] [data(M)]
 *
 * 对外提供的方法:
 * 1. 判断文件是否加密: isEncryptFile(filePath)
 * 2. 读取加密文件（返回流）: readEncryptFile(inputPath, privateKeyPath, outputStream)
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <memory>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

class HybridCrypto {
public:
    // 常量定义
    static constexpr const char* MAGIC_HEADER = "HANGSHU";
    static constexpr int MAGIC_SIZE = 7;
    static constexpr int VERSION = 1;
    static constexpr int AES_KEY_SIZE = 16;  // 128-bit
    static constexpr int GCM_TAG_LENGTH = 16; // 128-bit
    static constexpr int IV_SIZE = 12;        // 96-bit
    static constexpr int RSA_KEY_SIZE = 2048;

    HybridCrypto() : rsaPrivateKey_(nullptr), rsaPublicKey_(nullptr) {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    }

    ~HybridCrypto() {
        if (rsaPrivateKey_) RSA_free(rsaPrivateKey_);
        if (rsaPublicKey_) RSA_free(rsaPublicKey_);
        EVP_cleanup();
        ERR_free_strings();
    }

    // ==================== 1. 生成密钥对 ====================

    /**
     * 生成 RSA-2048 密钥对
     * @return 是否成功
     */
    bool generateKeyPair() {
        // 创建 RSA 密钥gen
        RSA* rsa = RSA_new();
        if (!rsa) {
            std::cerr << "创建 RSA 失败" << std::endl;
            return false;
        }

        // 生成密钥对
        BIGNUM* e = BN_new();
        BN_set_word(e, 65537);  // 常用的公钥指数

        if (RSA_generate_key_ex(rsa, RSA_KEY_SIZE, e, nullptr) != 1) {
            std::cerr << "生成 RSA 密钥对失败" << std::endl;
            ERR_print_errors_fp(stderr);
            BN_free(e);
            RSA_free(rsa);
            return false;
        }

        BN_free(e);

        // 保存密钥
        if (rsaPrivateKey_) RSA_free(rsaPrivateKey_);
        if (rsaPublicKey_) RSA_free(rsaPublicKey_);

        rsaPrivateKey_ = rsa;
        rsaPublicKey_ = RSAPublicKey_dup(rsa);  // 从私钥提取公钥

        std::cout << "密钥对生成成功" << std::endl;
        return true;
    }

    /**
     * 保存密钥对为 PEM 格式
     * @param privateKeyPath 私钥保存路径
     * @param publicKeyPath 公钥保存路径
     * @return 是否成功
     */
    bool saveKeys(const std::string& privateKeyPath, const std::string& publicKeyPath) {
        bool success = true;

        // 保存私钥
        if (rsaPrivateKey_) {
            FILE* fp = fopen(privateKeyPath.c_str(), "w");
            if (!fp) {
                std::cerr << "无法创建私钥文件: " << privateKeyPath << std::endl;
                success = false;
            } else {
                if (PEM_write_RSAPrivateKey(fp, rsaPrivateKey_, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
                    std::cerr << "写入私钥失败" << std::endl;
                    success = false;
                } else {
                    std::cout << "私钥已保存: " << privateKeyPath << std::endl;
                }
                fclose(fp);
            }
        }

        // 保存公钥
        if (rsaPublicKey_) {
            FILE* fp = fopen(publicKeyPath.c_str(), "w");
            if (!fp) {
                std::cerr << "无法创建公钥文件: " << publicKeyPath << std::endl;
                success = false;
            } else {
                if (PEM_write_RSAPublicKey(fp, rsaPublicKey_) != 1) {
                    std::cerr << "写入公钥失败" << std::endl;
                    success = false;
                } else {
                    std::cout << "公钥已保存: " << publicKeyPath << std::endl;
                }
                fclose(fp);
            }
        }

        return success;
    }

    /**
     * 加载密钥对 (PEM 格式)
     * @param privateKeyPath 私钥文件路径
     * @param publicKeyPath 公钥文件路径
     * @return 是否成功加载
     */
    bool loadKeys(const std::string& privateKeyPath = "", const std::string& publicKeyPath = "") {
        bool success = true;

        // 加载私钥
        if (!privateKeyPath.empty()) {
            FILE* fp = fopen(privateKeyPath.c_str(), "r");
            if (!fp) {
                std::cerr << "无法打开私钥文件: " << privateKeyPath << std::endl;
                success = false;
            } else {
                if (rsaPrivateKey_) RSA_free(rsaPrivateKey_);
                rsaPrivateKey_ = PEM_read_RSAPrivateKey(fp, nullptr, nullptr, nullptr);
                fclose(fp);
                if (!rsaPrivateKey_) {
                    std::cerr << "读取私钥失败" << std::endl;
                    ERR_print_errors_fp(stderr);
                    success = false;
                } else {
                    std::cout << "私钥已加载: " << privateKeyPath << std::endl;
                }
            }
        }

        // 加载公钥
        if (!publicKeyPath.empty()) {
            FILE* fp = fopen(publicKeyPath.c_str(), "r");
            if (!fp) {
                std::cerr << "无法打开公钥文件: " << publicKeyPath << std::endl;
                success = false;
            } else {
                if (rsaPublicKey_) RSA_free(rsaPublicKey_);
                rsaPublicKey_ = PEM_read_RSAPublicKey(fp, nullptr, nullptr, nullptr);
                fclose(fp);
                if (!rsaPublicKey_) {
                    std::cerr << "读取公钥失败" << std::endl;
                    ERR_print_errors_fp(stderr);
                    success = false;
                } else {
                    std::cout << "公钥已加载: " << publicKeyPath << std::endl;
                }
            }
        }

        return success;
    }

    // ==================== 2. 文件加密 ====================

    /**
     * 加密文件（覆盖原文件）
     * @param filePath 文件路径（加密后覆盖原文件）
     * @return 是否成功
     */
    bool encryptFile(const std::string& filePath) {
        if (!rsaPublicKey_) {
            std::cerr << "公钥未设置，无法加密" << std::endl;
            return false;
        }

        // 读取原始文件内容
        std::ifstream inFile(filePath, std::ios::binary);
        if (!inFile) {
            std::cerr << "无法打开文件: " << filePath << std::endl;
            return false;
        }

        inFile.seekg(0, std::ios::end);
        size_t fileSize = inFile.tellg();
        inFile.seekg(0, std::ios::beg);

        std::vector<uint8_t> fileData(fileSize);
        inFile.read(reinterpret_cast<char*>(fileData.data()), fileSize);
        inFile.close();

        // 加密数据
        std::vector<uint8_t> encryptedData;
        if (!encryptBytes(fileData, encryptedData)) {
            return false;
        }

        // 写入临时文件
        std::string tempFile = filePath + ".tmp";
        std::ofstream outFile(tempFile, std::ios::binary);
        if (!outFile) {
            std::cerr << "无法创建临时文件: " << tempFile << std::endl;
            return false;
        }
        outFile.write(reinterpret_cast<const char*>(encryptedData.data()), encryptedData.size());
        outFile.close();

        // 删除原文件，重命名临时文件
        remove(filePath.c_str());
        rename(tempFile.c_str(), filePath.c_str());

        std::cout << "加密成功: " << filePath << std::endl;
        return true;
    }

    /**
     * 加密字节数组
     * @param data 要加密的数据
     * @param encryptedData 输出加密后的数据
     * @return 是否成功
     */
    bool encryptBytes(const std::vector<uint8_t>& data, std::vector<uint8_t>& encryptedData) {
        if (!rsaPublicKey_) {
            std::cerr << "公钥未设置，无法加密" << std::endl;
            return false;
        }

        try {
            // 生成随机的 AES 密钥 (128-bit)
            std::vector<uint8_t> aesKey(AES_KEY_SIZE);
            if (RAND_bytes(aesKey.data(), AES_KEY_SIZE) != 1) {
                std::cerr << "生成 AES 密钥失败" << std::endl;
                return false;
            }

            // 使用 RSA 公钥加密 AES 密钥
            std::vector<uint8_t> encryptedAesKey(RSA_size(rsaPublicKey_));
            int encryptedAesKeyLen = RSA_public_encrypt(AES_KEY_SIZE, aesKey.data(),
                                                        encryptedAesKey.data(), rsaPublicKey_,
                                                        RSA_PKCS1_PADDING);
            if (encryptedAesKeyLen < 0) {
                std::cerr << "RSA 加密 AES 密钥失败" << std::endl;
                ERR_print_errors_fp(stderr);
                return false;
            }
            encryptedAesKey.resize(encryptedAesKeyLen);

            // 生成随机 IV (12 bytes)
            std::vector<uint8_t> iv(IV_SIZE);
            if (RAND_bytes(iv.data(), IV_SIZE) != 1) {
                std::cerr << "生成 IV 失败" << std::endl;
                return false;
            }

            // 使用 AES-GCM 加密数据
            std::vector<uint8_t> cipherText;
            if (!aesGcmEncrypt(aesKey.data(), aesKey.size(), iv.data(),
                              data.data(), data.size(), cipherText)) {
                return false;
            }

            // 构建输出 (大端序)
            // [MAGIC(7)] [VERSION(4)] [encKeyLen(4)] [encKey(N)] [IV(12)] [dataLen(4)] [data(M)]
            encryptedData.clear();
            encryptedData.insert(encryptedData.end(), MAGIC_HEADER, MAGIC_HEADER + MAGIC_SIZE);
            encryptedData.insert(encryptedData.end(), 
                               reinterpret_cast<uint8_t*>(&VERSION)[3],
                               reinterpret_cast<uint8_t*>(&VERSION)[4]);

            // VERSION (4 bytes, big-endian)
            uint8_t versionBytes[4];
            versionBytes[0] = (VERSION >> 24) & 0xFF;
            versionBytes[1] = (VERSION >> 16) & 0xFF;
            versionBytes[2] = (VERSION >> 8) & 0xFF;
            versionBytes[3] = VERSION & 0xFF;
            encryptedData.insert(encryptedData.end(), versionBytes, versionBytes + 4);

            // encryptedAesKeyLen (4 bytes, big-endian)
            uint8_t keyLenBytes[4];
            keyLenBytes[0] = (encryptedAesKeyLen >> 24) & 0xFF;
            keyLenBytes[1] = (encryptedAesKeyLen >> 16) & 0xFF;
            keyLenBytes[2] = (encryptedAesKeyLen >> 8) & 0xFF;
            keyLenBytes[3] = encryptedAesKeyLen & 0xFF;
            encryptedData.insert(encryptedData.end(), keyLenBytes, keyLenBytes + 4);

            // encryptedAesKey
            encryptedData.insert(encryptedData.end(), encryptedAesKey.begin(), encryptedAesKey.end());

            // IV
            encryptedData.insert(encryptedData.end(), iv.begin(), iv.end());

            // cipherText length (4 bytes, big-endian)
            int cipherLen = cipherText.size();
            uint8_t dataLenBytes[4];
            dataLenBytes[0] = (cipherLen >> 24) & 0xFF;
            dataLenBytes[1] = (cipherLen >> 16) & 0xFF;
            dataLenBytes[2] = (cipherLen >> 8) & 0xFF;
            dataLenBytes[3] = cipherLen & 0xFF;
            encryptedData.insert(encryptedData.end(), dataLenBytes, dataLenBytes + 4);

            // cipherText
            encryptedData.insert(encryptedData.end(), cipherText.begin(), cipherText.end());

            return true;

        } catch (const std::exception& e) {
            std::cerr << "加密失败: " << e.what() << std::endl;
            return false;
        }
    }

    // ==================== 3. 判断文件是否加密 ====================

    /**
     * 检查文件是否为加密文件
     * @param filePath 文件路径
     * @return true 如果是加密文件
     */
    static bool isEncryptFile(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return false;

        // 检查文件大小是否足够
        file.seekg(0, std::ios::end);
        size_t fileSize = file.tellg();
        if (fileSize < MAGIC_SIZE + 16) return false;
        file.seekg(0, std::ios::beg);

        // 读取并检查魔数
        char magic[MAGIC_SIZE];
        file.read(magic, MAGIC_SIZE);
        file.close();

        return std::memcmp(magic, MAGIC_HEADER, MAGIC_SIZE) == 0;
    }

    // ==================== 2. 读取加密文件（返回流） ====================

    /**
     * 读取加密文件（解密后输出到流）
     * @param inputPath 加密文件路径
     * @param privateKeyPath 私钥文件路径 (PEM格式)
     * @param outputStream 输出流 (如 std::ofstream 或 std::ostringstream)
     * @return 是否成功
     */
    bool readEncryptFile(const std::string& inputPath, 
                         const std::string& privateKeyPath,
                         std::ostream& outputStream) {
        // 加载私钥
        if (!loadPrivateKeyFromPem(privateKeyPath)) {
            std::cerr << "加载私钥失败: " << privateKeyPath << std::endl;
            return false;
        }

        // 读取加密文件
        std::ifstream inFile(inputPath, std::ios::binary);
        if (!inFile) {
            std::cerr << "无法打开输入文件: " << inputPath << std::endl;
            return false;
        }

        inFile.seekg(0, std::ios::end);
        size_t fileSize = inFile.tellg();
        inFile.seekg(0, std::ios::beg);

        std::vector<uint8_t> encryptedData(fileSize);
        inFile.read(reinterpret_cast<char*>(encryptedData.data()), fileSize);
        inFile.close();

        // 解密数据
        std::vector<uint8_t> decryptedData;
        if (!decrypt(encryptedData, decryptedData)) {
            return false;
        }

        // 写入输出流
        outputStream.write(reinterpret_cast<const char*>(decryptedData.data()), decryptedData.size());
        
        return outputStream.good();
    }

    /**
     * 读取加密文件（返回字符串）
     * @param inputPath 加密文件路径
     * @param privateKeyPath 私钥文件路径 (PEM格式)
     * @return 解密后的字符串，失败返回空字符串
     */
    std::string readEncryptFileToString(const std::string& inputPath, 
                                        const std::string& privateKeyPath) {
        // 加载私钥
        if (!loadPrivateKeyFromPem(privateKeyPath)) {
            std::cerr << "加载私钥失败: " << privateKeyPath << std::endl;
            return "";
        }

        // 读取加密文件
        std::ifstream inFile(inputPath, std::ios::binary);
        if (!inFile) {
            std::cerr << "无法打开输入文件: " << inputPath << std::endl;
            return "";
        }

        inFile.seekg(0, std::ios::end);
        size_t fileSize = inFile.tellg();
        inFile.seekg(0, std::ios::beg);

        std::vector<uint8_t> encryptedData(fileSize);
        inFile.read(reinterpret_cast<char*>(encryptedData.data()), fileSize);
        inFile.close();

        // 解密数据
        std::vector<uint8_t> decryptedData;
        if (!decrypt(encryptedData, decryptedData)) {
            return "";
        }

        // 转换为字符串
        return std::string(reinterpret_cast<const char*>(decryptedData.data()), decryptedData.size());
    }

    /**
     * 读取加密文件到内存向量
     * @param inputPath 加密文件路径
     * @param privateKeyPath 私钥文件路径 (PEM格式)
     * @param outputData 输出数据向量
     * @return 是否成功
     */
    bool readEncryptFileToVector(const std::string& inputPath, 
                                 const std::string& privateKeyPath,
                                 std::vector<uint8_t>& outputData) {
        // 加载私钥
        if (!loadPrivateKeyFromPem(privateKeyPath)) {
            std::cerr << "加载私钥失败: " << privateKeyPath << std::endl;
            return false;
        }

        // 读取加密文件
        std::ifstream inFile(inputPath, std::ios::binary);
        if (!inFile) {
            std::cerr << "无法打开输入文件: " << inputPath << std::endl;
            return false;
        }

        inFile.seekg(0, std::ios::end);
        size_t fileSize = inFile.tellg();
        inFile.seekg(0, std::ios::beg);

        std::vector<uint8_t> encryptedData(fileSize);
        inFile.read(reinterpret_cast<char*>(encryptedData.data()), fileSize);
        inFile.close();

        // 解密数据
        return decrypt(encryptedData, outputData);
    }

private:
    RSA* rsaPrivateKey_;
    RSA* rsaPublicKey_;

    /**
     * 从 PEM 文件加载私钥
     */
    bool loadPrivateKeyFromPem(const std::string& pemPath) {
        // 如果已经加载了私钥，先释放
        if (rsaPrivateKey_) {
            RSA_free(rsaPrivateKey_);
            rsaPrivateKey_ = nullptr;
        }

        FILE* fp = fopen(pemPath.c_str(), "r");
        if (!fp) {
            std::cerr << "无法打开私钥文件: " << pemPath << std::endl;
            return false;
        }

        rsaPrivateKey_ = PEM_read_RSAPrivateKey(fp, nullptr, nullptr, nullptr);
        fclose(fp);

        if (!rsaPrivateKey_) {
            std::cerr << "读取私钥失败" << std::endl;
            ERR_print_errors_fp(stderr);
            return false;
        }
        return true;
    }

    /**
     * 解密数据
     */
    bool decrypt(const std::vector<uint8_t>& encryptedData, std::vector<uint8_t>& decryptedData) {
        if (!rsaPrivateKey_) {
            std::cerr << "私钥未加载" << std::endl;
            return false;
        }

        if (encryptedData.size() < MAGIC_SIZE + 4 + 4 + 1 + IV_SIZE + 4 + 1) {
            std::cerr << "加密数据格式不正确，数据太短" << std::endl;
            return false;
        }

        size_t offset = 0;

        // 验证魔数
        if (std::memcmp(encryptedData.data(), MAGIC_HEADER, MAGIC_SIZE) != 0) {
            std::cerr << "无效的加密数据格式: 魔数不匹配" << std::endl;
            return false;
        }
        offset += MAGIC_SIZE;

        // 读取版本号（大端序）
        int version = readInt32(encryptedData, offset);
        offset += 4;
        if (version != VERSION) {
            std::cerr << "不支持的文件版本: " << version << std::endl;
            return false;
        }

        // 读取加密的 AES 密钥长度
        int encKeyLen = readInt32(encryptedData, offset);
        offset += 4;

        // 读取加密的 AES 密钥
        std::vector<uint8_t> encryptedAesKey(encryptedData.begin() + offset,
                                             encryptedData.begin() + offset + encKeyLen);
        offset += encKeyLen;

        // 使用 RSA 私钥解密 AES 密钥
        std::vector<uint8_t> aesKey(RSA_size(rsaPrivateKey_));
        int aesKeyLen = RSA_private_decrypt(encKeyLen, encryptedAesKey.data(),
                                           aesKey.data(), rsaPrivateKey_, RSA_PKCS1_PADDING);
        if (aesKeyLen < 0) {
            std::cerr << "RSA 解密 AES 密钥失败" << std::endl;
            ERR_print_errors_fp(stderr);
            return false;
        }
        aesKey.resize(aesKeyLen);

        // 读取 IV
        if (offset + IV_SIZE > encryptedData.size()) {
            std::cerr << "数据格式错误: IV 超出范围" << std::endl;
            return false;
        }
        std::vector<uint8_t> iv(encryptedData.begin() + offset,
                                encryptedData.begin() + offset + IV_SIZE);
        offset += IV_SIZE;

        // 读取加密数据长度
        int dataLen = readInt32(encryptedData, offset);
        offset += 4;

        // 读取加密数据（包含 GCM tag）
        if (offset + dataLen > encryptedData.size()) {
            std::cerr << "数据格式错误: 加密数据超出范围" << std::endl;
            return false;
        }
        std::vector<uint8_t> cipherText(encryptedData.begin() + offset,
                                        encryptedData.begin() + offset + dataLen);

        // 使用 AES-GCM 解密
        decryptedData.resize(dataLen - GCM_TAG_LENGTH);
        if (!aesGcmDecrypt(aesKey.data(), aesKey.size(), iv.data(),
                          cipherText.data(), cipherText.size(),
                          decryptedData.data(), decryptedData.size())) {
            return false;
        }

        return true;
    }

    // 大端序读取 int32
    static int readInt32(const std::vector<uint8_t>& data, size_t offset) {
        return (data[offset] << 24) |
               (data[offset + 1] << 16) |
               (data[offset + 2] << 8) |
               data[offset + 3];
    }

    // AES-GCM 解密
    bool aesGcmDecrypt(const uint8_t* key, int keyLen,
                      const uint8_t* iv,
                      const uint8_t* cipherText, int cipherLen,
                      uint8_t* plainText, int plainLen) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        // 密文长度 = 实际密文 + GCM tag
        int actualCipherLen = cipherLen - GCM_TAG_LENGTH;

        // 初始化解密
        if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1)
            goto err;

        // 设置 IV 长度
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, nullptr) != 1)
            goto err;

        // 设置密钥和 IV
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1)
            goto err;

        // 设置 GCM tag（在密文末尾）
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LENGTH,
                               const_cast<uint8_t*>(cipherText + actualCipherLen)) != 1)
            goto err;

        // 解密
        int len;
        if (EVP_DecryptUpdate(ctx, plainText, &len, cipherText, actualCipherLen) != 1)
            goto err;

        // 验证 tag 并完成解密
        if (EVP_DecryptFinal_ex(ctx, plainText + len, &len) != 1) {
            std::cerr << "GCM tag 验证失败，数据可能被篡改" << std::endl;
            goto err;
        }

        EVP_CIPHER_CTX_free(ctx);
        return true;

    err:
        EVP_CIPHER_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        return false;
    }
};

// ==================== 使用示例 ====================

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "用法:" << std::endl;
        std::cout << "  " << argv[0] << " check <file>                    - 检查是否为加密文件" << std::endl;
        std::cout << "  " << argv[0] << " decrypt <in> <out> <private.pem> - 解密文件到输出文件" << std::endl;
        return 1;
    }

    std::string command = argv[1];

    if (command == "check" && argc == 3) {
        std::string filePath = argv[2];
        if (HybridCrypto::isEncryptFile(filePath)) {
            std::cout << "✓ 是加密文件" << std::endl;
        } else {
            std::cout << "✗ 不是加密文件" << std::endl;
        }
        return 0;
    }

    if (command == "decrypt" && argc == 5) {
        std::string inputPath = argv[2];
        std::string outputPath = argv[3];
        std::string keyPath = argv[4];

        // 首先检查是否为加密文件
        if (!HybridCrypto::isEncryptFile(inputPath)) {
            std::cerr << "错误: 不是加密文件" << std::endl;
            return 1;
        }

        HybridCrypto crypto;
        std::ofstream outFile(outputPath, std::ios::binary);
        if (!outFile) {
            std::cerr << "无法创建输出文件: " << outputPath << std::endl;
            return 1;
        }

        if (crypto.readEncryptFile(inputPath, keyPath, outFile)) {
            outFile.close();
            std::cout << "✓ 解密成功: " << outputPath << std::endl;
            return 0;
        } else {
            outFile.close();
            std::cerr << "✗ 解密失败" << std::endl;
            return 1;
        }
    }

    std::cerr << "参数错误" << std::endl;
    return 1;
}
