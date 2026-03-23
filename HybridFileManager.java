package com.file.encrypt.utils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * 混合加密文件管理器 - 跨语言加密方案 Java 实现
 * 
 * 支持 Java、C++、Python 三方互操作
 * 
 * 技术规范:
 * - RSA: 2048-bit, PKCS1Padding
 * - AES: 128-bit, GCM mode
 * - GCM Tag: 128-bit (16 bytes)
 * - IV: 96-bit (12 bytes), 随机生成
 * - 密钥格式: PEM (标准格式，跨语言兼容)
 * - 字节序: 大端序 (Big-Endian)
 * 
 * 文件格式结构:
 * [MAGIC(7): "HANGSHU"] [VERSION(4)] [encKeyLen(4)] [encKey(N)] [IV(12)] [dataLen(4)] [data(M)]
 * 
 * 对外提供的方法:
 * 1. 生成密钥: generateKeyPair(), saveKeys()
 * 2. 文件加密: encryptFile(String filePath)
 * 3. 文件解密: decryptFile(String filePath)
 * 4. 判断文件是否加密: isEncryptFile(String filePath)
 * 5. 读取加密文件（返回字符串）: readEncryptFile(String inputFile)
 * 6. 读取加密文件（返回流）: readEncryptFileAsStream(String inputFile)
 */
public class HybridFileManager {

    // ==================== 常量定义 ====================
    
    /** 文件魔数标识 */
    public static final byte[] MAGIC_HEADER = {(byte) 0x48, (byte) 0x41, (byte) 0x4E, (byte) 0x47, (byte) 0x53, (byte) 0x48, (byte) 0x55}; // "HANGSHU"
    public static final int MAGIC_SIZE = MAGIC_HEADER.length;
    public static final int VERSION = 1;
    
    /** AES 配置 */
    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final int AES_KEY_SIZE = 128;  // 128-bit 兼容默认 JCE
    private static final int GCM_TAG_LENGTH = 128; // 128-bit tag
    private static final int IV_SIZE = 12;         // 96-bit IV
    
    /** RSA 配置 */
    private static final String RSA_ALGORITHM = "RSA";
    private static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final int RSA_KEY_SIZE = 2048;
    
    /** PEM 格式头尾标记 */
    private static final String PEM_PUBLIC_KEY_HEADER = "-----BEGIN PUBLIC KEY-----";
    private static final String PEM_PUBLIC_KEY_FOOTER = "-----END PUBLIC KEY-----";
    private static final String PEM_PRIVATE_KEY_HEADER = "-----BEGIN PRIVATE KEY-----";
    private static final String PEM_PRIVATE_KEY_FOOTER = "-----END PRIVATE KEY-----";
    private static final int PEM_LINE_LENGTH = 64;

    // ==================== 成员变量 ====================
    
    private PrivateKey privateKey;
    private PublicKey publicKey;

    // ==================== 1. 生成密钥 ====================

    /**
     * 生成 RSA-2048 密钥对
     * @return KeyPair 生成的密钥对
     */
    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyGen.initialize(RSA_KEY_SIZE);
        KeyPair keyPair = keyGen.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
        return keyPair;
    }

    /**
     * 保存密钥对为 PEM 格式 (Base64 + 头尾标记)
     * @param privateKeyPath 私钥保存路径
     * @param publicKeyPath 公钥保存路径
     */
    public void saveKeys(String privateKeyPath, String publicKeyPath) throws Exception {
        if (privateKey != null && privateKeyPath != null) {
            String pemContent = encodePem(privateKey.getEncoded(), PEM_PRIVATE_KEY_HEADER, PEM_PRIVATE_KEY_FOOTER);
            Files.write(Paths.get(privateKeyPath), pemContent.getBytes("UTF-8"));
        }
        if (publicKey != null && publicKeyPath != null) {
            String pemContent = encodePem(publicKey.getEncoded(), PEM_PUBLIC_KEY_HEADER, PEM_PUBLIC_KEY_FOOTER);
            Files.write(Paths.get(publicKeyPath), pemContent.getBytes("UTF-8"));
        }
    }

    /**
     * 加载密钥对 (PEM 格式)
     * @param privateKeyPath 私钥文件路径
     * @param publicKeyPath 公钥文件路径
     */
    public void loadKeys(String privateKeyPath, String publicKeyPath) throws Exception {
        if (privateKeyPath != null && Files.exists(Paths.get(privateKeyPath))) {
            byte[] privateKeyBytes = Files.readAllBytes(Paths.get(privateKeyPath));
            String content = new String(privateKeyBytes, "UTF-8").trim();
            byte[] decoded = decodePem(content, PEM_PRIVATE_KEY_HEADER, PEM_PRIVATE_KEY_FOOTER);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            this.privateKey = keyFactory.generatePrivate(spec);
        }

        if (publicKeyPath != null && Files.exists(Paths.get(publicKeyPath))) {
            byte[] publicKeyBytes = Files.readAllBytes(Paths.get(publicKeyPath));
            String content = new String(publicKeyBytes, "UTF-8").trim();
            byte[] decoded = decodePem(content, PEM_PUBLIC_KEY_HEADER, PEM_PUBLIC_KEY_FOOTER);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            this.publicKey = keyFactory.generatePublic(spec);
        }
    }

    // ==================== 2. 文件加密 ====================

    /**
     * 加密文件（覆盖原文件）
     * 
     * 输出格式 (大端序):
     * [MAGIC(7): "HANGSHU"] [VERSION(4)] [encKeyLen(4)] [encKey(N)] [IV(12)] [dataLen(4)] [data(M)]
     * 
     * @param filePath 文件路径（加密后覆盖原文件）
     */
    public void encryptFile(String filePath) throws Exception {
        if (publicKey == null) {
            throw new IllegalStateException("公钥未设置，无法加密");
        }

        // 读取原始文件内容
        byte[] fileData = Files.readAllBytes(Paths.get(filePath));

        // 加密数据
        byte[] encryptedData = encryptBytes(fileData);
        
        // 写入临时文件
        String tempFile = filePath + ".tmp";
        Files.write(Paths.get(tempFile), encryptedData);
        
        // 删除原文件，重命名临时文件
        Files.delete(Paths.get(filePath));
        Files.move(Paths.get(tempFile), Paths.get(filePath));
    }

    // ==================== 3. 文件解密 ====================

    /**
     * 解密文件（覆盖原文件）
     * 
     * 输入格式 (大端序):
     * [MAGIC(7): "HANGSHU"] [VERSION(4)] [encKeyLen(4)] [encKey(N)] [IV(12)] [dataLen(4)] [data(M)]
     * 
     * @param filePath 文件路径（解密后覆盖原文件）
     */
    public void decryptFile(String filePath) throws Exception {
        if (privateKey == null) {
            throw new IllegalStateException("私钥未设置，无法解密");
        }

        // 读取加密文件内容
        byte[] encryptedData = Files.readAllBytes(Paths.get(filePath));
        
        // 解密数据
        byte[] decryptedData = decryptBytes(encryptedData);
        
        // 写入临时文件
        String tempFile = filePath + ".tmp";
        Files.write(Paths.get(tempFile), decryptedData);
        
        // 删除原文件，重命名临时文件
        Files.delete(Paths.get(filePath));
        Files.move(Paths.get(tempFile), Paths.get(filePath));
    }

    // ==================== 4. 判断文件是否加密 ====================

    /**
     * 检查文件是否为加密文件
     * @param filePath 文件路径
     * @return true 如果是加密文件
     */
    public static boolean isEncryptFile(String filePath) {
        File file = new File(filePath);
        if (!file.exists() || !file.isFile()) {
            return false;
        }

        if (file.length() < MAGIC_SIZE + 16) {
            return false;
        }

        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] magic = new byte[MAGIC_SIZE];
            int read = fis.read(magic);
            if (read != MAGIC_SIZE) {
                return false;
            }
            return Arrays.equals(magic, MAGIC_HEADER);
        } catch (Exception e) {
            return false;
        }
    }

    // ==================== 5. 读取加密文件（返回字符串） ====================

    /**
     * 读取加密文件内容（返回字符串）
     * @param inputFile 加密文件路径
     * @return 解密后的文本内容
     */
    public String readEncryptFile(String inputFile) throws Exception {
        byte[] decryptedData = decryptBytes(Files.readAllBytes(Paths.get(inputFile)));
        return new String(decryptedData, "UTF-8");
    }

    // ==================== 6. 读取加密文件（返回流） ====================

    /**
     * 读取加密文件内容（返回字节数组流）
     * @param inputFile 加密文件路径
     * @return 解密后的数据流 (ByteArrayInputStream)
     */
    public ByteArrayInputStream readEncryptFileAsStream(String inputFile) throws Exception {
        byte[] decryptedData = decryptBytes(Files.readAllBytes(Paths.get(inputFile)));
        return new ByteArrayInputStream(decryptedData);
    }

    // ==================== 私有辅助方法 ====================

    /**
     * 加密字节数组
     */
    private byte[] encryptBytes(byte[] data) throws Exception {
        // 生成随机的 AES 密钥
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE);
        SecretKey aesKey = keyGen.generateKey();

        // 使用 RSA 公钥加密 AES 密钥 (PKCS1Padding)
        Cipher rsaCipher = Cipher.getInstance(RSA_TRANSFORMATION);
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

        // 生成随机 IV (12 bytes)
        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // 使用 AES-GCM 加密数据
        Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
        byte[] encryptedData = aesCipher.doFinal(data);

        // 构建输出 (大端序)
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.write(MAGIC_HEADER);                    // 7 bytes: 魔数
        dos.writeInt(VERSION);                      // 4 bytes: 版本号
        dos.writeInt(encryptedAesKey.length);       // 4 bytes: 加密后的 AES 密钥长度
        dos.write(encryptedAesKey);                 // N bytes: 加密后的 AES 密钥
        dos.write(iv);                              // 12 bytes: IV
        dos.writeInt(encryptedData.length);         // 4 bytes: 加密数据长度
        dos.write(encryptedData);                   // M bytes: 加密数据
        dos.flush();

        return baos.toByteArray();
    }

    /**
     * 解密字节数组
     */
    private byte[] decryptBytes(byte[] encryptedData) throws Exception {
        if (privateKey == null) {
            throw new IllegalStateException("私钥未设置，无法解密");
        }

        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(encryptedData));

        // 验证魔数
        byte[] magic = new byte[MAGIC_SIZE];
        dis.readFully(magic);
        if (!Arrays.equals(magic, MAGIC_HEADER)) {
            throw new IllegalArgumentException("无效的加密数据格式: 魔数不匹配");
        }

        // 读取版本号
        int version = dis.readInt();
        if (version != VERSION) {
            throw new IllegalArgumentException("不支持的文件版本: " + version);
        }

        // 读取并解密 AES 密钥
        int encryptedKeyLength = dis.readInt();
        byte[] encryptedAesKey = new byte[encryptedKeyLength];
        dis.readFully(encryptedAesKey);

        Cipher rsaCipher = Cipher.getInstance(RSA_TRANSFORMATION);
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        // 读取 IV
        byte[] iv = new byte[IV_SIZE];
        dis.readFully(iv);

        // 读取加密数据
        int encryptedDataLength = dis.readInt();
        byte[] data = new byte[encryptedDataLength];
        dis.readFully(data);

        // 使用 AES-GCM 解密数据
        Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
        return aesCipher.doFinal(data);
    }

    /**
     * 将二进制数据编码为 PEM 格式
     */
    private String encodePem(byte[] data, String header, String footer) {
        String base64 = Base64.getEncoder().encodeToString(data);
        StringBuilder pem = new StringBuilder();
        pem.append(header).append("\n");
        
        // 每 64 字符换行
        for (int i = 0; i < base64.length(); i += PEM_LINE_LENGTH) {
            int end = Math.min(i + PEM_LINE_LENGTH, base64.length());
            pem.append(base64, i, end).append("\n");
        }
        
        pem.append(footer).append("\n");
        return pem.toString();
    }

    /**
     * 从 PEM 格式解码二进制数据
     */
    private byte[] decodePem(String pemContent, String header, String footer) throws Exception {
        String content = pemContent.trim();
        
        // 提取 Base64 部分
        int start = content.indexOf(header);
        int end = content.indexOf(footer);
        
        if (start == -1 || end == -1) {
            throw new IllegalArgumentException("Invalid PEM format");
        }
        
        String base64 = content.substring(start + header.length(), end)
                .replaceAll("\\s+", ""); // 移除所有空白字符
        
        return Base64.getDecoder().decode(base64);
    }
}
