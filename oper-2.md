
python版本 3.10 
1) 参考 HybridFileManager.java 实现方式  在  hybrid_crypto.py 中 增加 如下方法 , 并进行测试 
A 增加使用公钥进行加密  
B 增加产生公钥 私钥的方法 
c 目前使用私钥进行解密 方法已经进行验证 


2) 针对 hybrid_crypto.py 的功能 生成测试案例 
a)  产生公钥私钥 
b) 使用公钥进行加密 
c) 使用私钥进行解密 

3)  针对 hybrid_crypto.py 制作一个工具  
a)默认公钥私钥使用如下，可以修改或者重新生成
公钥 public_key.pem
私钥   private_key.pem 
b) 使用公钥对文件进行加密 ,加密内容显示到输入框或者文件 
c) 使用私钥对文件进行解密 ,解密内容显示到输入框或者文件 

4） 针对工具  hybrid_crypto_gui.py 工具 生成总结文档和操作说明


5)  针对工具  hybrid_crypto_gui.py 进行功能优化和界面美化   
增加对内容的加密解密 
点击加密   加密内容显示到输入框 方便复制粘贴 
点击解密   解密内容显示到输入框 方便复制粘贴 

6） hybrid_crypto_gui.py 显示不全 增加滚动条进行显示 

5）  针对 hybrid_crypto.cpp  参考 hybrid_crypto_gui.py  和 HybridFileManager.java  
增加生成公钥私钥的方法 
增加使用公钥进行加密的方法 
 目前使用私钥进行解密 方法已经进行验证  