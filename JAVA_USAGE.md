# VastBase SM4 Java 客户端使用指南

## 📌 重要说明

### ⚠️ 您原来的Java代码无法直接使用！

**原因：加密模式不兼容**

| 项目     | 数据库扩展       | 您原来的Java代码 |
| -------- | ---------------- | ---------------- |
| 加密模式 | **ECB/CBC**      | **GCM** ❌        |
| 填充方式 | **PKCS7Padding** | **NoPadding** ❌  |
| IV处理   | CBC独立IV        | GCM的IV=Key ❌    |

## ✅ 解决方案

使用我提供的 **SM4DatabaseUtils.java**，它与数据库扩展完全兼容。

---

## 📦 项目结构

```
vastbase_sm4/
├── SM4DatabaseUtils.java          # SM4工具类（与数据库兼容）
├── DatabaseDecryptionDemo.java    # 完整应用示例
├── pom.xml                         # Maven依赖配置
├── demo_citizen_data.sql          # 示例数据（20条）
└── JAVA_USAGE.md                  # 本文档
```

---

## 🚀 快速开始

### 1. 添加Maven依赖

```xml
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk15on</artifactId>
    <version>1.70</version>
</dependency>

<dependency>
    <groupId>org.postgresql</groupId>
    <artifactId>postgresql</artifactId>
    <version>42.6.0</version>
</dependency>
```

### 2. 初始化测试数据

```bash
# 在数据库中执行示例SQL
psql -d your_database -f demo_citizen_data.sql
```

### 3. 修改数据库连接配置

编辑 `DatabaseDecryptionDemo.java`:

```java
private static final String DB_URL = "jdbc:postgresql://localhost:5432/your_database";
private static final String DB_USER = "your_username";
private static final String DB_PASSWORD = "your_password";

// 密钥必须与数据库中使用的密钥一致！
private static final String ENCRYPTION_KEY = "gov2024secret123";
```

### 4. 运行示例

```bash
# 使用Maven编译运行
mvn clean compile
mvn exec:java -Dexec.mainClass="com.vastbase.sm4.demo.DatabaseDecryptionDemo"

# 或者打包后运行
mvn clean package
java -jar target/vastbase-sm4-demo-1.0.0-jar-with-dependencies.jar
```

---

## 💡 核心API使用

### ECB模式（推荐用于单字段加密）

```java
import com.vastbase.sm4.SM4DatabaseUtils;

// 加密
String plaintext = "13800138001";
String key = "gov2024secret123";
byte[] encrypted = SM4DatabaseUtils.encryptECB(plaintext, key);

// 解密
String decrypted = SM4DatabaseUtils.decryptECB(encrypted, key);

// 加密为十六进制字符串
String encryptedHex = SM4DatabaseUtils.encryptECBHex(plaintext, key);

// 从十六进制解密
String decrypted2 = SM4DatabaseUtils.decryptECBHex(encryptedHex, key);
```

### CBC模式（推荐用于大数据加密）

```java
// 加密
String plaintext = "敏感数据内容";
String key = "gov2024secret123";
String iv = "1234567890abcdef";  // 初始向量，16字节
byte[] encrypted = SM4DatabaseUtils.encryptCBC(plaintext, key, iv);

// 解密
String decrypted = SM4DatabaseUtils.decryptCBC(encrypted, key, iv);
```

---

## 🔐 数据库操作示例

### 场景1: 查询并解密（应用层解密）

```java
String sql = "SELECT citizen_id, name, id_card_encrypted, phone_encrypted " +
             "FROM citizen_info WHERE citizen_id = ?";

try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
    pstmt.setInt(1, 1);
    ResultSet rs = pstmt.executeQuery();
    
    if (rs.next()) {
        // 获取加密数据
        byte[] idCardEncrypted = rs.getBytes("id_card_encrypted");
        byte[] phoneEncrypted = rs.getBytes("phone_encrypted");
        
        // 在Java中解密
        String idCard = SM4DatabaseUtils.decryptECB(idCardEncrypted, ENCRYPTION_KEY);
        String phone = SM4DatabaseUtils.decryptECB(phoneEncrypted, ENCRYPTION_KEY);
        
        System.out.println("姓名: " + rs.getString("name"));
        System.out.println("身份证: " + idCard);
        System.out.println("手机: " + phone);
    }
}
```

### 场景2: 使用数据库函数解密（数据库层解密）

```java
String sql = "SELECT citizen_id, name, " +
             "sm4_decrypt(id_card_encrypted, ?) AS id_card, " +
             "sm4_decrypt(phone_encrypted, ?) AS phone " +
             "FROM citizen_info WHERE citizen_id = ?";

try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
    pstmt.setString(1, ENCRYPTION_KEY);
    pstmt.setString(2, ENCRYPTION_KEY);
    pstmt.setInt(3, 1);
    
    ResultSet rs = pstmt.executeQuery();
    if (rs.next()) {
        // 数据已经在数据库中解密，直接获取
        String idCard = rs.getString("id_card");
        String phone = rs.getString("phone");
        
        System.out.println("身份证: " + idCard);
        System.out.println("手机: " + phone);
    }
}
```

### 场景3: 插入加密数据

```java
String sql = "INSERT INTO citizen_info " +
             "(name, gender, id_card_encrypted, phone_encrypted, city) " +
             "VALUES (?, ?, ?, ?, ?)";

String idCard = "110101199001011234";
String phone = "13900139000";

// Java中加密
byte[] idCardEncrypted = SM4DatabaseUtils.encryptECB(idCard, ENCRYPTION_KEY);
byte[] phoneEncrypted = SM4DatabaseUtils.encryptECB(phone, ENCRYPTION_KEY);

try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
    pstmt.setString(1, "张三");
    pstmt.setString(2, "M");
    pstmt.setBytes(3, idCardEncrypted);
    pstmt.setBytes(4, phoneEncrypted);
    pstmt.setString(5, "北京市");
    
    int rows = pstmt.executeUpdate();
    System.out.println("插入成功: " + rows + " 行");
}
```

### 场景4: 根据加密字段查询

```java
// 方法A: 在SQL中解密后匹配
String sql = "SELECT * FROM citizen_info " +
             "WHERE sm4_decrypt(phone_encrypted, ?) = ?";

try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
    pstmt.setString(1, ENCRYPTION_KEY);
    pstmt.setString(2, "13800138005");
    
    ResultSet rs = pstmt.executeQuery();
    // 处理结果...
}

// 方法B: 先加密查询条件（推荐，性能更好）
String phoneToSearch = "13800138005";
byte[] encryptedPhone = SM4DatabaseUtils.encryptECB(phoneToSearch, ENCRYPTION_KEY);

String sql2 = "SELECT * FROM citizen_info WHERE phone_encrypted = ?";
try (PreparedStatement pstmt = conn.prepareStatement(sql2)) {
    pstmt.setBytes(1, encryptedPhone);
    ResultSet rs = pstmt.executeQuery();
    // 处理结果...
}
```

---

## 🛡️ 数据脱敏

### 方法1: 在Java代码中脱敏

```java
public class CitizenInfo {
    private String idCard;
    private String phone;
    
    // 脱敏的身份证号: 110101********1234
    public String getMaskedIdCard() {
        if (idCard == null || idCard.length() < 18) {
            return idCard;
        }
        return idCard.substring(0, 6) + "********" + idCard.substring(14);
    }
    
    // 脱敏的手机号: 138****8001
    public String getMaskedPhone() {
        if (phone == null || phone.length() < 11) {
            return phone;
        }
        return phone.substring(0, 3) + "****" + phone.substring(7);
    }
}
```

### 方法2: 使用数据库脱敏视图

```java
// 直接查询脱敏视图，无需手动脱敏
String sql = "SELECT citizen_id, name, id_card, phone, city " +
             "FROM citizen_info_masked " +
             "ORDER BY citizen_id";

try (PreparedStatement pstmt = conn.prepareStatement(sql);
     ResultSet rs = pstmt.executeQuery()) {
    
    while (rs.next()) {
        // id_card和phone已经是脱敏后的数据
        System.out.println("身份证: " + rs.getString("id_card"));  // 110101********1234
        System.out.println("手机: " + rs.getString("phone"));      // 138****8001
    }
}
```

---

## ⚡ 性能优化建议

### 1. 批量解密优化

```java
// ❌ 不推荐：逐条解密（慢）
for (int i = 0; i < 1000; i++) {
    String sql = "SELECT sm4_decrypt(phone_encrypted, ?) FROM citizen_info WHERE id = ?";
    // 每次查询都要调用解密函数
}

// ✅ 推荐：批量查询后统一解密
String sql = "SELECT id, phone_encrypted FROM citizen_info LIMIT 1000";
List<byte[]> encryptedPhones = new ArrayList<>();

// 批量获取
ResultSet rs = stmt.executeQuery(sql);
while (rs.next()) {
    encryptedPhones.add(rs.getBytes("phone_encrypted"));
}

// 批量解密（在应用层并行处理）
for (byte[] encrypted : encryptedPhones) {
    String phone = SM4DatabaseUtils.decryptECB(encrypted, ENCRYPTION_KEY);
    // 处理...
}
```

### 2. 密钥缓存

```java
public class SM4KeyManager {
    private static final Map<String, byte[]> KEY_CACHE = new ConcurrentHashMap<>();
    
    public static byte[] getProcessedKey(String key) {
        return KEY_CACHE.computeIfAbsent(key, k -> {
            // 只处理一次密钥
            if (k.length() == 32 && k.matches("[0-9a-fA-F]+")) {
                return hexStringToBytes(k);
            }
            return k.getBytes(StandardCharsets.UTF_8);
        });
    }
}
```

### 3. 连接池使用

```java
// 使用HikariCP连接池
HikariConfig config = new HikariConfig();
config.setJdbcUrl(DB_URL);
config.setUsername(DB_USER);
config.setPassword(DB_PASSWORD);
config.setMaximumPoolSize(10);

HikariDataSource dataSource = new HikariDataSource(config);
Connection conn = dataSource.getConnection();
```

---

## 🔒 安全最佳实践

### 1. 密钥管理

```java
// ❌ 不要硬编码密钥
private static final String KEY = "gov2024secret123";

// ✅ 从配置文件读取
Properties props = new Properties();
props.load(new FileInputStream("config.properties"));
String key = props.getProperty("encryption.key");

// ✅ 从环境变量读取
String key = System.getenv("SM4_ENCRYPTION_KEY");

// ✅ 从密钥管理服务获取（最佳）
String key = KeyManagementService.getKey("sm4-database-key");
```

### 2. 权限控制

```sql
-- 创建只读角色（只能查询脱敏视图）
CREATE ROLE reader_role;
GRANT SELECT ON citizen_info_masked TO reader_role;
REVOKE ALL ON citizen_info FROM reader_role;

-- 创建管理员角色（可以解密）
CREATE ROLE admin_role;
GRANT ALL ON citizen_info TO admin_role;
```

### 3. 审计日志

```java
public class AuditLogger {
    public static void logDecryption(String user, String table, String field) {
        // 记录敏感数据访问
        logger.info("User {} decrypted {} from {}", user, field, table);
    }
}

// 在解密时调用
String phone = SM4DatabaseUtils.decryptECB(encrypted, key);
AuditLogger.logDecryption(currentUser, "citizen_info", "phone");
```

---

## 🧪 测试验证

### 测试数据一致性

```java
@Test
public void testEncryptionConsistency() throws Exception {
    String plaintext = "13800138001";
    String key = "gov2024secret123";
    
    // Java加密
    byte[] javaEncrypted = SM4DatabaseUtils.encryptECB(plaintext, key);
    
    // 插入数据库
    String sql = "INSERT INTO test_table (phone) VALUES (?)";
    pstmt.setBytes(1, javaEncrypted);
    pstmt.executeUpdate();
    
    // 使用数据库函数解密
    String sql2 = "SELECT sm4_decrypt(phone, ?) FROM test_table";
    pstmt.setString(1, key);
    ResultSet rs = pstmt.executeQuery();
    rs.next();
    String dbDecrypted = rs.getString(1);
    
    // 验证一致性
    assertEquals(plaintext, dbDecrypted);
}
```

---

## ❓ 常见问题

### Q1: 解密失败或出现乱码？

**A:** 检查以下几点：
1. 密钥是否与数据库中使用的完全一致
2. 加密模式是否匹配（ECB vs CBC）
3. 数据编码是否正确（UTF-8）

### Q2: 性能问题？

**A:** 
- WHERE条件中避免使用解密函数（无法使用索引）
- 考虑使用哈希值辅助查询
- 批量操作优于单条处理

### Q3: 如何在MyBatis中使用？

```xml
<!-- 方式1: 使用TypeHandler -->
<resultMap id="CitizenMap" type="CitizenInfo">
    <result property="phone" column="phone_encrypted" 
            typeHandler="com.vastbase.sm4.SM4TypeHandler"/>
</resultMap>

<!-- 方式2: 直接在SQL中解密 -->
<select id="getCitizen" resultType="CitizenInfo">
    SELECT 
        citizen_id,
        name,
        sm4_decrypt(phone_encrypted, #{encryptionKey}) as phone
    FROM citizen_info
    WHERE citizen_id = #{id}
</select>
```

---

## 📞 技术支持

如有问题，请联系：
- 数据库扩展：查看 README.md
- Java工具类：查看源码注释
- 示例代码：运行 DatabaseDecryptionDemo

---

## 📄 许可证

本项目遵循与VastBase SM4扩展相同的许可证。
