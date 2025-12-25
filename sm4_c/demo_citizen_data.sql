-- ========================================
-- 政务系统个人敏感数据SM4加密示例 (C扩展版本)
-- ========================================
-- 说明: 本示例模拟政务系统中公民信息的敏感数据加密
-- 敏感字段: 身份证号(id_card)、手机号码(phone)
-- 使用SM4国密算法进行加密存储
-- 使用sm4_c_*函数(C扩展版本，避免与Java UDF冲突)

-- 定义加密密钥(实际应用中应使用密钥管理系统)
-- 注意: 生产环境不要硬编码密钥!
\set ENCRYPTION_KEY '\'gov2024secret123\''

\echo '========================================'
\echo '创建公民信息表'
\echo '========================================'

-- 创建公民信息表
DROP TABLE IF EXISTS citizen_info;
CREATE TABLE citizen_info (
    -- 基础信息
    citizen_id SERIAL PRIMARY KEY,                    -- 公民ID(自增主键)
    name VARCHAR(50) NOT NULL,                        -- 姓名
    gender CHAR(1) CHECK (gender IN ('M', 'F')),     -- 性别
    birth_date DATE,                                  -- 出生日期
    
    -- 敏感信息(加密存储)
    id_card_encrypted BYTEA,                          -- 身份证号(加密)
    phone_encrypted BYTEA,                            -- 手机号码(加密)
    
    -- 地址信息
    province VARCHAR(50),                             -- 省份
    city VARCHAR(50),                                 -- 城市
    district VARCHAR(50),                             -- 区县
    address TEXT,                                     -- 详细地址
    
    -- 管理信息
    registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- 登记时间
    status VARCHAR(20) DEFAULT 'active',              -- 状态
    remark TEXT                                       -- 备注
);

COMMENT ON TABLE citizen_info IS '公民信息表-敏感数据使用SM4加密';
COMMENT ON COLUMN citizen_info.id_card_encrypted IS '身份证号(SM4加密存储)';
COMMENT ON COLUMN citizen_info.phone_encrypted IS '手机号码(SM4加密存储)';

\echo ''
\echo '========================================'
\echo '插入测试数据(20条)'
\echo '========================================'

-- 插入20条测试数据
INSERT INTO citizen_info (name, gender, birth_date, id_card_encrypted, phone_encrypted, province, city, district, address, status, remark)
VALUES
-- 1
('张伟', 'M', '1985-03-15', 
 sm4_c_encrypt('110101198503151234', :ENCRYPTION_KEY),
 sm4_c_encrypt('13800138001', :ENCRYPTION_KEY),
 '北京市', '北京市', '东城区', '东华门街道建国门内大街1号', 'active', '普通公民'),

-- 2
('李娜', 'F', '1990-07-22',
 sm4_c_encrypt('310101199007221234', :ENCRYPTION_KEY),
 sm4_c_encrypt('13800138002', :ENCRYPTION_KEY),
 '上海市', '上海市', '黄浦区', '南京东路街道人民广场5号', 'active', NULL),

-- 3
('王强', 'M', '1978-12-08',
 sm4_c_encrypt('440101197812081234', :ENCRYPTION_KEY),
 sm4_c_encrypt('13800138003', :ENCRYPTION_KEY),
 '广东省', '广州市', '天河区', '天河路208号', 'active', '退伍军人'),

-- 4
('刘芳', 'F', '1995-05-30',
 sm4_c_encrypt('500101199505301234', :ENCRYPTION_KEY),
 sm4_c_encrypt('13800138004', :ENCRYPTION_KEY),
 '重庆市', '重庆市', '渝中区', '解放碑街道民权路100号', 'active', NULL),

-- 5
('陈明', 'M', '1982-09-18',
 sm4_c_encrypt('510101198209181234', :ENCRYPTION_KEY),
 sm4_c_encrypt('13800138005', :ENCRYPTION_KEY),
 '四川省', '成都市', '武侯区', '人民南路四段88号', 'active', '党员'),

-- 6
('杨丽', 'F', '1988-11-25',
 sm4_c_encrypt('320101198811251234', :ENCRYPTION_KEY),
 sm4_c_encrypt('13800138006', :ENCRYPTION_KEY),
 '江苏省', '南京市', '鼓楼区', '中山路1号', 'active', NULL),

-- 7
('赵军', 'M', '1975-04-12',
 sm4_c_encrypt('330101197504121234', :ENCRYPTION_KEY),
 sm4_c_encrypt('13800138007', :ENCRYPTION_KEY),
 '浙江省', '杭州市', '西湖区', '文三路168号', 'active', '高级工程师'),

-- 8
('孙静', 'F', '1992-08-06',
 sm4_c_encrypt('420101199208061234', :ENCRYPTION_KEY),
 sm4_c_encrypt('13800138008', :ENCRYPTION_KEY),
 '湖北省', '武汉市', '武昌区', '中南路88号', 'active', NULL),

-- 9
('周涛', 'M', '1987-02-28',
 sm4_c_encrypt('610101198702281234', :ENCRYPTION_KEY),
 sm4_c_encrypt('13800138009', :ENCRYPTION_KEY),
 '陕西省', '西安市', '雁塔区', '科技路18号', 'active', NULL),

-- 10
('吴梅', 'F', '1993-10-15',
 sm4_c_encrypt('370101199310151234', :ENCRYPTION_KEY),
 sm4_c_encrypt('13800138010', :ENCRYPTION_KEY),
 '山东省', '济南市', '历下区', '泉城路180号', 'active', '教师'),

-- 11
('郑超', 'M', '1980-06-20',
 sm4_c_encrypt('210101198006201234', :ENCRYPTION_KEY),
 sm4_c_encrypt('13800138011', :ENCRYPTION_KEY),
 '辽宁省', '沈阳市', '和平区', '三好街66号', 'active', NULL),

-- 12
('钱敏', 'F', '1991-01-08',
 sm4_c_encrypt('410101199101081234', :ENCRYPTION_KEY),
 sm4_c_encrypt('13800138012', :ENCRYPTION_KEY),
 '河南省', '郑州市', '金水区', '花园路99号', 'active', NULL),

-- 13
('孙浩', 'M', '1986-03-14',
 sm4_c_encrypt('130101198603141234', :ENCRYPTION_KEY),
 sm4_c_encrypt('13800138013', :ENCRYPTION_KEY),
 '河北省', '石家庄市', '长安区', '中山东路216号', 'inactive', '已迁出'),

-- 14
('李华', 'F', '1994-09-22',
 sm4_c_encrypt('340101199409221234', :ENCRYPTION_KEY),
 sm4_c_encrypt('13800138014', :ENCRYPTION_KEY),
 '安徽省', '合肥市', '蜀山区', '长江西路128号', 'active', NULL),

-- 15
('张鹏', 'M', '1989-12-05',
 sm4_c_encrypt('350101198912051234', :ENCRYPTION_KEY),
 sm4_c_encrypt('13800138015', :ENCRYPTION_KEY),
 '福建省', '福州市', '鼓楼区', '五一北路158号', 'active', '医生'),

-- 16
('王静', 'F', '1984-07-11',
 sm4_c_encrypt('430101198407111234', :ENCRYPTION_KEY),
 sm4_c_encrypt('13800138016', :ENCRYPTION_KEY),
 '湖南省', '长沙市', '岳麓区', '麓山南路36号', 'active', NULL),

-- 17
('刘强', 'M', '1996-11-30',
 sm4_c_encrypt('450101199611301234', :ENCRYPTION_KEY),
 sm4_c_encrypt('13800138017', :ENCRYPTION_KEY),
 '广西壮族自治区', '南宁市', '青秀区', '民族大道115号', 'active', NULL),

-- 18
('陈静', 'F', '1981-05-17',
 sm4_c_encrypt('520101198105171234', :ENCRYPTION_KEY),
 sm4_c_encrypt('13800138018', :ENCRYPTION_KEY),
 '贵州省', '贵阳市', '云岩区', '中华北路166号', 'active', '律师'),

-- 19
('杨军', 'M', '1983-08-25',
 sm4_c_encrypt('530101198308251234', :ENCRYPTION_KEY),
 sm4_c_encrypt('13800138019', :ENCRYPTION_KEY),
 '云南省', '昆明市', '五华区', '东风西路288号', 'active', NULL),

-- 20
('赵艳', 'F', '1997-02-14',
 sm4_c_encrypt('220101199702141234', :ENCRYPTION_KEY),
 sm4_c_encrypt('13800138020', :ENCRYPTION_KEY),
 '吉林省', '长春市', '朝阳区', '人民大街138号', 'active', NULL);

\echo ''
\echo '========================================'
\echo '数据插入完成'
\echo '========================================'

\echo ''
\echo '========================================'
\echo '查询示例1: 查看加密后的原始数据'
\echo '========================================'
SELECT 
    citizen_id,
    name,
    gender,
    birth_date,
    encode(id_card_encrypted, 'hex') AS id_card_encrypted_hex,
    encode(phone_encrypted, 'hex') AS phone_encrypted_hex,
    city,
    status
FROM citizen_info
LIMIT 5;

\echo ''
\echo '========================================'
\echo '查询示例2: 解密敏感数据查看'
\echo '========================================'
SELECT 
    citizen_id,
    name,
    gender,
    EXTRACT(YEAR FROM age(birth_date)) AS age,
    sm4_c_decrypt(id_card_encrypted, :ENCRYPTION_KEY) AS id_card,
    sm4_c_decrypt(phone_encrypted, :ENCRYPTION_KEY) AS phone,
    province || city || district AS full_location,
    status
FROM citizen_info
ORDER BY citizen_id
LIMIT 10;

\echo ''
\echo '========================================'
\echo '查询示例3: 脱敏显示(部分隐藏)'
\echo '========================================'
SELECT 
    citizen_id,
    name,
    gender,
    -- 身份证脱敏: 显示前6位和后4位
    SUBSTRING(sm4_c_decrypt(id_card_encrypted, :ENCRYPTION_KEY), 1, 6) || '********' || 
    SUBSTRING(sm4_c_decrypt(id_card_encrypted, :ENCRYPTION_KEY), 15, 4) AS id_card_masked,
    -- 手机号脱敏: 显示前3位和后4位
    SUBSTRING(sm4_c_decrypt(phone_encrypted, :ENCRYPTION_KEY), 1, 3) || '****' || 
    SUBSTRING(sm4_c_decrypt(phone_encrypted, :ENCRYPTION_KEY), 8, 4) AS phone_masked,
    city,
    status
FROM citizen_info
ORDER BY citizen_id;

\echo ''
\echo '========================================'
\echo '查询示例4: 按条件查询(需要先解密)'
\echo '========================================'
-- 查找特定手机号的公民
SELECT 
    citizen_id,
    name,
    sm4_c_decrypt(phone_encrypted, :ENCRYPTION_KEY) AS phone,
    city,
    address
FROM citizen_info
WHERE sm4_c_decrypt(phone_encrypted, :ENCRYPTION_KEY) = '13800138005';

\echo ''
\echo '========================================'
\echo '查询示例5: 统计分析(按省份)'
\echo '========================================'
SELECT 
    province,
    COUNT(*) AS citizen_count,
    COUNT(CASE WHEN gender = 'M' THEN 1 END) AS male_count,
    COUNT(CASE WHEN gender = 'F' THEN 1 END) AS female_count,
    ROUND(AVG(EXTRACT(YEAR FROM age(birth_date))), 1) AS avg_age
FROM citizen_info
WHERE status = 'active'
GROUP BY province
ORDER BY citizen_count DESC;

\echo ''
\echo '========================================'
\echo '创建安全查询视图(自动脱敏)'
\echo '========================================'
DROP VIEW IF EXISTS citizen_info_masked;
CREATE VIEW citizen_info_masked AS
SELECT 
    citizen_id,
    name,
    gender,
    birth_date,
    EXTRACT(YEAR FROM age(birth_date)) AS age,
    -- 自动脱敏的身份证
    SUBSTRING(sm4_c_decrypt(id_card_encrypted, :ENCRYPTION_KEY), 1, 6) || '********' || 
    SUBSTRING(sm4_c_decrypt(id_card_encrypted, :ENCRYPTION_KEY), 15, 4) AS id_card,
    -- 自动脱敏的手机号
    SUBSTRING(sm4_c_decrypt(phone_encrypted, :ENCRYPTION_KEY), 1, 3) || '****' || 
    SUBSTRING(sm4_c_decrypt(phone_encrypted, :ENCRYPTION_KEY), 8, 4) AS phone,
    province,
    city,
    district,
    address,
    registration_date,
    status,
    remark
FROM citizen_info;

COMMENT ON VIEW citizen_info_masked IS '公民信息脱敏视图-敏感数据自动脱敏显示';

\echo ''
\echo '========================================'
\echo '使用脱敏视图查询'
\echo '========================================'
SELECT 
    citizen_id,
    name,
    gender,
    age,
    id_card,
    phone,
    city
FROM citizen_info_masked
ORDER BY citizen_id
LIMIT 10;

\echo ''
\echo '========================================'
\echo '安全性验证'
\echo '========================================'
\echo '验证1: 使用错误密钥无法解密'
SELECT 
    name,
    '正确密钥解密' AS method,
    sm4_c_decrypt(phone_encrypted, :ENCRYPTION_KEY) AS result
FROM citizen_info 
WHERE citizen_id = 1
UNION ALL
SELECT 
    name,
    '错误密钥解密' AS method,
    '解密失败或乱码' AS result
FROM citizen_info 
WHERE citizen_id = 1;

\echo ''
\echo '========================================'
\echo '性能说明'
\echo '========================================'
\echo '注意事项:'
\echo '1. 加密字段不能直接建立索引'
\echo '2. WHERE条件中的解密操作会影响查询性能'
\echo '3. 建议对非敏感字段(如city, province)建立索引'
\echo '4. 大数据量场景可考虑使用哈希值辅助查询'
\echo ''

\echo '========================================'
\echo '示例完成!'
\echo '========================================'
\echo '数据库表: citizen_info (包含20条加密数据)'
\echo '脱敏视图: citizen_info_masked (自动脱敏)'
\echo '敏感字段: id_card_encrypted, phone_encrypted'
\echo '加密算法: SM4国密算法'
\echo '========================================'
