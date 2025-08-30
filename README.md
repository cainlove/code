# 医疗行业服务器加固系统

一个专为医疗机构设计的服务器安全检查和加固综合性工具，帮助医疗系统管理员识别和修复常见的安全漏洞，确保医疗数据安全和合规性。

## 功能特性

### 🔍 安全检查模块

- **用户账户安全检查**
  - Root账户状态检查
  - 密码策略验证
  - 账户锁定配置
  - 空密码账户检测
  - 重复UID/GID检查
  - Sudo配置审计
  - 用户主目录权限检查
  - 系统账户Shell检查
  - 密码过期策略检查
  - 登录失败记录检查

- **网络安全配置检查**
  - 防火墙状态检查
  - 开放端口扫描
  - 网络参数配置检查
  - SSH配置安全检查
  - 网络接口配置检查
  - IP转发设置检查
  - ICMP重定向检查
  - 源路由检查
  - SYN Cookies检查
  - 网络监听服务检查

- **文件系统权限检查**
  - 关键系统文件权限检查
  - SUID/SGID文件扫描
  - 世界可写文件检测
  - 无主文件检查
  - 临时目录权限检查
  - 日志文件权限检查
  - 配置文件权限检查
  - 挂载点安全检查

- **服务和端口安全检查**
  - 开放端口检查
  - 危险服务检测
  - 系统服务状态检查
  - 网络监听服务检查
  - Xinetd服务检查
  - Systemd服务检查
  - 端口绑定检查
  - 服务配置文件检查

- **日志和审计配置检查**
  - Auditd服务状态检查
  - Audit规则配置检查
  - 日志轮转配置检查
  - 系统日志配置检查
  - 日志文件权限检查
  - 登录日志检查
  - 安全事件日志检查
  - 日志完整性检查
  - 远程日志配置检查

### 🛠️ 其他功能

- **自动化修复**: 支持自动修复检测到的安全问题
- **详细报告**: 生成JSON、HTML、TXT格式的安全报告
- **安全评分**: 基于检查结果计算安全评分
- **系统信息收集**: 收集详细的系统信息用于分析
- **配置管理**: 灵活的配置文件支持
- **并发执行**: 支持多线程并发检查提高效率
- **日志记录**: 详细的操作日志记录

## 安装要求

### 系统要求
- Linux操作系统（支持主流发行版）
- Python 3.6+
- Root权限（用于系统级检查和修复）

### Python依赖
```bash
pip install -r requirements.txt
```

主要依赖：
- PyYAML >= 6.0（配置文件处理）
- 其他依赖均为Python标准库

## 快速开始

### 1. 克隆项目
```bash
git clone <repository-url>
cd linux_security_hardening
```

### 2. 安装依赖
```bash
pip install -r requirements.txt
```

### 3. 运行安全检查
```bash
# 基本扫描
sudo python main.py --scan

# 生成HTML报告
sudo python main.py --scan --report-format html --output /tmp/security_report.html

# 启用详细输出
sudo python main.py --scan --verbose

# 使用自定义配置文件
sudo python main.py --scan --config /path/to/config.yaml
```

### 4. 查看报告
生成的报告将保存在指定位置，可以用浏览器打开HTML报告查看详细结果。

## 使用说明

### 命令行参数

```bash
python main.py [选项]
```

**主要选项：**
- `--scan`: 执行安全扫描
- `--fix`: 自动修复检测到的问题
- `--report-format {json,html,txt}`: 报告格式
- `--output OUTPUT`: 报告输出文件路径
- `--config CONFIG`: 配置文件路径
- `--verbose`: 启用详细输出
- `--log-level {DEBUG,INFO,WARNING,ERROR}`: 日志级别
- `--checkers CHECKERS`: 指定要运行的检查器
- `--exclude-checkers EXCLUDE`: 排除的检查器
- `--max-workers WORKERS`: 并发工作线程数
- `--timeout TIMEOUT`: 命令执行超时时间
- `--no-color`: 禁用彩色输出

**示例：**
```bash
# 只运行用户和网络安全检查
sudo python main.py --scan --checkers user_security,network_security

# 排除文件系统检查
sudo python main.py --scan --exclude-checkers filesystem

# 自动修复并生成报告
sudo python main.py --scan --fix --report-format html --output security_report.html

# 调试模式
sudo python main.py --scan --log-level DEBUG --verbose
```

### 配置文件

软件使用YAML格式的配置文件，默认配置文件为 `config.yaml`。可以通过配置文件自定义：

- 检查器启用/禁用
- 检查项目配置
- 自动修复设置
- 报告生成选项
- 安全评分权重
- 通知设置

**配置示例：**
```yaml
global:
  log_level: INFO
  max_workers: 4
  continue_on_error: true

checkers:
  user_security:
    enabled: true
    auto_fix:
      enabled: false
    password_policy:
      min_length: 8
      max_age: 90

report:
  default_format: html
  include_system_info: true
```

## 报告说明

### HTML报告
- 包含完整的检查结果和系统信息
- 提供交互式界面和图表
- 支持按严重性筛选问题
- 包含修复建议和参考链接

### JSON报告
- 机器可读格式
- 适合集成到其他系统
- 包含详细的检查数据

### TXT报告
- 纯文本格式
- 适合命令行查看
- 简洁的问题摘要

## 安全检查详情

### 严重性级别
- **Critical**: 严重安全漏洞，需要立即修复
- **High**: 高风险问题，应尽快修复
- **Medium**: 中等风险问题，建议修复
- **Low**: 低风险问题，可选修复
- **Info**: 信息性检查，无需修复

### 检查器说明

1. **UserSecurityChecker**: 检查用户账户相关的安全配置
2. **NetworkSecurityChecker**: 检查网络安全配置和防火墙设置
3. **FilesystemChecker**: 检查文件系统权限和敏感文件
4. **ServicePortChecker**: 检查运行的服务和开放端口
5. **AuditLogChecker**: 检查日志和审计配置

## 自动修复功能

软件支持自动修复部分检测到的安全问题：

- 修复文件权限问题
- 更新配置文件
- 禁用危险服务
- 配置防火墙规则
- 设置密码策略

**注意事项：**
- 自动修复功能默认禁用
- 修复前会创建配置文件备份
- 建议在测试环境中先验证修复效果
- 某些修复可能需要重启服务或系统

## 最佳实践

1. **定期扫描**: 建议每周或每月运行一次完整扫描
2. **配置管理**: 根据环境需求自定义配置文件
3. **报告分析**: 重点关注Critical和High级别的问题
4. **渐进修复**: 先修复高优先级问题，逐步改善安全状况
5. **备份重要**: 修复前务必备份重要配置文件
6. **测试验证**: 在生产环境应用前先在测试环境验证

## 故障排除

### 常见问题

**权限不足**
```bash
# 确保使用root权限运行
sudo python main.py --scan
```

**依赖缺失**
```bash
# 安装所需依赖
pip install -r requirements.txt
```

**配置文件错误**
```bash
# 验证YAML语法
python -c "import yaml; yaml.safe_load(open('config.yaml'))"
```

**命令超时**
```bash
# 增加超时时间
python main.py --scan --timeout 60
```

### 日志文件
默认日志文件位置：`/var/log/security_hardening.log`

可以通过配置文件或命令行参数调整日志级别和位置。

## 开发说明

### 项目结构
```
linux_security_hardening/
├── main.py                 # 主程序入口
├── config.yaml            # 默认配置文件
├── requirements.txt       # Python依赖
├── README.md             # 项目文档
├── core/                 # 核心模块
│   ├── __init__.py
│   ├── security_manager.py
│   └── report_generator.py
├── checkers/             # 安全检查器
│   ├── __init__.py
│   ├── base_checker.py
│   ├── user_security_checker.py
│   ├── network_security_checker.py
│   ├── filesystem_checker.py
│   ├── service_port_checker.py
│   └── audit_log_checker.py
└── utils/                # 工具模块
    ├── __init__.py
    ├── config.py
    ├── exceptions.py
    └── system_info.py
```

### 扩展开发

要添加新的安全检查器：

1. 继承 `BaseChecker` 类
2. 实现 `run_checks()` 方法
3. 在 `SecurityManager` 中注册新检查器
4. 更新配置文件模板

## 许可证

本项目采用 MIT 许可证。详见 LICENSE 文件。

## 贡献

欢迎提交问题报告和功能请求。如需贡献代码，请：

1. Fork 项目
2. 创建功能分支
3. 提交更改
4. 推送到分支
5. 创建 Pull Request

## 支持

如有问题或需要帮助，请：

1. 查看文档和FAQ
2. 搜索已有的Issue
3. 创建新的Issue描述问题
4. 提供详细的错误信息和环境信息

---

**免责声明**: 本工具仅用于合法的安全检查和系统加固。使用者应确保在授权的系统上使用，并对使用结果负责。