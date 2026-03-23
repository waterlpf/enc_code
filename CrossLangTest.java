package com.file.encrypt;

import com.file.encrypt.utils.HybridFileManager;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

/**
 * 跨语言加密测试 - Java 加密，供 Python/C++ 解密
 */
public class CrossLangTest {

    public static void main(String[] args) throws Exception {
        String workDir = "cross-lang-test";
        Files.createDirectories(Paths.get(workDir));

        String privateKeyPem = workDir + "/private.pem";
        String publicKeyPem = workDir + "/public.pem";
        String testFile = workDir + "/test_message.txt";
        String encryptedFile = workDir + "/test_message.enc";

        System.out.println("========================================");
        System.out.println("  Java Encrypt -> Python/C++ Decrypt Test");
        System.out.println("========================================\n");

        // 1. 生成密钥对
        System.out.println("[Step 1] Generating RSA-2048 key pair...");
        HybridFileManager manager = new HybridFileManager();
        manager.generateKeyPair();
        System.out.println("    [OK] Key pair generated");

        // 2. 保存 PEM
        System.out.println("[Step 2] Saving keys to PEM format...");
        manager.saveKeys(privateKeyPem, publicKeyPem);
        System.out.println("    [OK] Private key: " + privateKeyPem);
        System.out.println("    [OK] Public key: " + publicKeyPem);

        // 3. 创建测试文件
        System.out.println("\n[Step 3] Creating test file...");
        String testContent = "Hello, this is a cross-language encryption test!\n" +
                            "This file was encrypted by Java and can be decrypted by Python/C++.\n" +
                            "测试中文内容: 跨语言加密测试成功!";
        Files.write(Paths.get(testFile), testContent.getBytes("UTF-8"));
        System.out.println("    [OK] Test file created: " + testFile);
        System.out.println("    Original size: " + Files.size(Paths.get(testFile)) + " bytes");

        // 4. 加密文件
        System.out.println("\n[Step 4] Encrypting file...");
        // 复制一份用于加密测试
        Files.copy(Paths.get(testFile), Paths.get(encryptedFile));
        manager.encryptFile(encryptedFile);
        System.out.println("    [OK] File encrypted: " + encryptedFile);
        System.out.println("    Encrypted size: " + Files.size(Paths.get(encryptedFile)) + " bytes");
        System.out.println("    Is encrypted: " + HybridFileManager.isEncryptFile(encryptedFile));

        // 5. 验证文件头
        System.out.println("\n[Step 5] Verifying encrypted file header...");
        byte[] header = Files.readAllBytes(Paths.get(encryptedFile));
        String magic = new String(header, 0, HybridFileManager.MAGIC_SIZE);
        System.out.println("    [OK] Magic header: " + magic);
        System.out.println("    [OK] Expected: HANGSHU");

        // 6. 解密测试
        System.out.println("\n[Step 6] Testing decrypt...");
        String decryptedFile = workDir + "/decrypted.txt";
        // 复制加密文件用于解密测试
        Files.copy(Paths.get(encryptedFile), Paths.get(decryptedFile));
        manager.decryptFile(decryptedFile);
        System.out.println("    [OK] File decrypted: " + decryptedFile);
        System.out.println("    Decrypted size: " + Files.size(Paths.get(decryptedFile)) + " bytes");

        // 验证解密后内容一致
        byte[] original = Files.readAllBytes(Paths.get(testFile));
        byte[] decrypted = Files.readAllBytes(Paths.get(decryptedFile));
        if (Arrays.equals(original, decrypted)) {
            System.out.println("    [OK] Decrypted content matches original");
        } else {
            System.out.println("    [ERROR] Decrypted content does not match!");
        }

        // 7. 测试读取加密文件（字符串方式）
        System.out.println("\n[Step 7] Testing readEncryptFile (String)...");
        String decryptedContent = manager.readEncryptFile(encryptedFile);
        if (decryptedContent.equals(testContent)) {
            System.out.println("    [OK] readEncryptFile content matches original");
        } else {
            System.out.println("    [ERROR] readEncryptFile content does not match!");
        }

        // 8. 测试读取加密文件（流方式）
        System.out.println("\n[Step 8] Testing readEncryptFileAsStream...");
        ByteArrayInputStream stream = manager.readEncryptFileAsStream(encryptedFile);
        byte[] streamContent = new byte[stream.available()];
        stream.read(streamContent);
        if (Arrays.equals(original, streamContent)) {
            System.out.println("    [OK] readEncryptFileAsStream content matches original");
        } else {
            System.out.println("    [ERROR] readEncryptFileAsStream content does not match!");
        }

        // 9. 测试 isEncryptFile
        System.out.println("\n[Step 9] Testing isEncryptFile...");
        System.out.println("    Is encrypted file: " + HybridFileManager.isEncryptFile(encryptedFile) + " (expected true)");
        System.out.println("    Is plain file: " + HybridFileManager.isEncryptFile(testFile) + " (expected false)");
        System.out.println("    Is non-existent: " + HybridFileManager.isEncryptFile("nonexistent.txt") + " (expected false)");

        System.out.println("\n========================================");
        System.out.println("  All tests passed!");
        System.out.println("========================================");
        System.out.println("\nGenerated files:");
        System.out.println("  - " + privateKeyPem + " (for Python/C++ decryption)");
        System.out.println("  - " + publicKeyPem);
        System.out.println("  - " + testFile + " (original)");
        System.out.println("  - " + encryptedFile + " (encrypted, for Python/C++ to decrypt)");

        System.out.println("\nPython decryption commands:");
        System.out.println("  cd f:\\ai\\encryptFile");
        System.out.println("  python hybrid_crypto.py decrypt " + encryptedFile + " python_decrypted.txt " + privateKeyPem);

        System.out.println("\nC++ decryption commands:");
        System.out.println("  hybrid_crypto.exe decrypt " + encryptedFile + " cpp_decrypted.txt " + privateKeyPem);
    }
}
