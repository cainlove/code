#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
医疗行业服务器加固系统

一个专为医疗机构设计的服务器安全检查和加固综合性工具。

主要功能:
- 用户账户安全检查
- 网络安全配置检查
- 文件系统权限检查
- 服务和端口安全检查
- 日志和审计配置检查
- 自动化安全修复
- 详细的安全报告生成
"""

__version__ = '1.0.0'
__author__ = '马民'
__description__ = '医疗行业服务器加固系统'

from .core import SecurityManager, ReportGenerator
from .utils import ConfigManager, SystemInfoCollector

__all__ = [
    'SecurityManager',
    'ReportGenerator',
    'ConfigManager',
    'SystemInfoCollector'
]