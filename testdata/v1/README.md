# V1 共享测试向量

本目录是 Go 与 TypeScript 必须共同读取的冻结协议向量，包括：

- JCS 规范字节、SHA-256 摘要和 DER ECDSA 签名；
- Hash 请求合法与非法消息；
- 私密收件箱 ECDH、HKDF、AAD、AES-GCM 固定向量；
- WebRTC Offer、Answer、ICE 和 Session 关联向量；
- 应用消息 Deliver、ACK、重复重试和编号冲突向量；
- 重复字段、错误类型、过期、错误公钥、坏签名和解密失败向量。

Fixture 中的私钥只能用于测试，并使用明显的 `test_only_*` 字段名；测试日志不得输出私钥。

当前文件：

- `interop-v1.json`：双方共同读取的 JCS、公开签名、私密签名和固定 salt/nonce 密文真值；
- `jcs-valid.json` / `jcs-invalid.json`：字段排序、ECMAScript 数字、Unicode、重复字段和
  非有限数字；
- `primitives-valid.json` / `primitives-invalid.json`：公钥、ID、Hash、时间编码；
- `signature-public.json` / `signature-private.json`：固定 digest 与 RFC6979 low-S DER；
- `hash-request-*`：公开 Hash channel 和 locator 分支；
- `inbox-crypto-*`：完整信封输入、信封版本、收件者、公钥、GCM tag、strict DER/high-S 和加密明文边界；
- `webrtc-signal-*`：四种互斥信令和会话关系；
- `app-message-*`：Deliver、任意 JCS content、ACK 关系；
- `dedup-and-relations.json`：公开 Hash/私密 Deliver 去重键、实际 NUL 分隔的 SessionKey、
  ACK 正反例和内容冲突码。

两种语言的测试和跨语言 integration driver 都逐项读取同一份完整输入与 `expected_code`，
禁止在运行时用被测实现重新生成 expected 值。
