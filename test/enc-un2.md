<!--
 * @Author: pf.li pf.li@example.com
 * @Date: 2026-03-21 11:03:54
 * @LastEditors: 李鹏飞 pf.li@hang-shu.com
 * @LastEditTime: 2026-03-23 22:31:39
 * @FilePath: /enc/enc.md
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
-->


g++ -g  -o hybrid_crypto hybrid_crypto.cpp  -lssl -lcrypto

pyinstaller --add-data "public.pem;." --add-data "private.pem;." --hidden-import "tkinter,cryptography,typing"  -F -w hybrid_crypto_gui.py