#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
医疗行业服务器加固系统使用示例

本文件展示了如何在Python代码中使用安全加固软件的各个组件。
"""

import os
import sys
import logging
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.security_manager import SecurityManager
from core.report_generator import ReportGenerator
from utils.config import ConfigManager
from utils.system_info import SystemInfoCollector
from utils.exceptions import SecurityHardeningError


def setup_logging():
    """设置日志配置"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('/tmp/security_example.log')
        ]
    )


def example_basic_scan():
    """示例1: 基本安全扫描"""
    print("\n=== 示例1: 基本安全扫描 ===")
    
    try:
        # 初始化配置管理器
        config_manager = ConfigManager()
        config = config_manager.load_config('config.yaml')
        
        # 初始化安全管理器
        security_manager = SecurityManager(config)
        
        # 执行安全扫描
        print("开始执行安全扫描...")
        results = security_manager.run_security_scan()
        
        # 显示扫描结果摘要
        print(f"\n扫描完成！")
        print(f"总检查项: {results['summary']['total_checks']}")
        print(f"通过检查: {results['summary']['passed_checks']}")
        print(f"失败检查: {results['summary']['failed_checks']}")
        print(f"安全评分: {results['summary']['security_score']:.1f}/100")
        
        # 显示问题统计
        issues = results['summary']['issues_by_severity']
        print(f"\n问题统计:")
        print(f"  严重: {issues.get('critical', 0)}")
        print(f"  高危: {issues.get('high', 0)}")
        print(f"  中危: {issues.get('medium', 0)}")
        print(f"  低危: {issues.get('low', 0)}")
        
        return results
        
    except SecurityHardeningError as e:
        print(f"安全扫描失败: {e}")
        return None
    except Exception as e:
        print(f"未知错误: {e}")
        return None


def example_generate_reports(scan_results):
    """示例2: 生成多种格式的报告"""
    print("\n=== 示例2: 生成安全报告 ===")
    
    if not scan_results:
        print("没有扫描结果，跳过报告生成")
        return
    
    try:
        # 初始化报告生成器
        report_generator = ReportGenerator()
        
        # 生成JSON报告
        json_file = '/tmp/security_report.json'
        report_generator.generate_json_report(scan_results, json_file)
        print(f"JSON报告已生成: {json_file}")
        
        # 生成HTML报告
        html_file = '/tmp/security_report.html'
        report_generator.generate_html_report(scan_results, html_file)
        print(f"HTML报告已生成: {html_file}")
        
        # 生成文本报告
        txt_file = '/tmp/security_report.txt'
        report_generator.generate_text_report(scan_results, txt_file)
        print(f"文本报告已生成: {txt_file}")
        
    except Exception as e:
        print(f"报告生成失败: {e}")


def example_system_info():
    """示例3: 收集系统信息"""
    print("\n=== 示例3: 收集系统信息 ===")
    
    try:
        # 初始化系统信息收集器
        collector = SystemInfoCollector()
        
        # 收集基本信息
        basic_info = collector.get_basic_info()
        print(f"主机名: {basic_info.get('hostname', 'Unknown')}")
        print(f"平台: {basic_info.get('platform', 'Unknown')}")
        print(f"架构: {basic_info.get('machine', 'Unknown')}")
        
        # 收集操作系统信息
        os_info = collector.get_os_info()
        print(f"操作系统: {os_info.get('system', 'Unknown')}")
        print(f"内核版本: {os_info.get('kernel_version', 'Unknown')}")
        
        # 收集网络信息
        network_info = collector.get_network_info()
        interfaces = network_info.get('interfaces', [])
        print(f"网络接口数量: {len(interfaces)}")
        
        # 收集用户信息
        user_info = collector.get_user_info()
        print(f"当前用户: {user_info.get('current_user', 'Unknown')}")
        print(f"系统用户数量: {len(user_info.get('all_users', []))}")
        
        return collector.collect_all_info()
        
    except Exception as e:
        print(f"系统信息收集失败: {e}")
        return None


def example_custom_config():
    """示例4: 自定义配置"""
    print("\n=== 示例4: 自定义配置 ===")
    
    try:
        # 创建自定义配置
        custom_config = {
            'global': {
                'log_level': 'DEBUG',
                'max_workers': 2,
                'verbose': True
            },
            'checkers': {
                'user_security': {
                    'enabled': True,
                    'auto_fix': {'enabled': False}
                },
                'network_security': {
                    'enabled': True,
                    'auto_fix': {'enabled': False}
                },
                'filesystem': {
                    'enabled': False  # 禁用文件系统检查
                },
                'service_port': {
                    'enabled': True,
                    'auto_fix': {'enabled': False}
                },
                'audit_log': {
                    'enabled': False  # 禁用审计日志检查
                }
            },
            'report': {
                'default_format': 'json',
                'include_system_info': True
            }
        }
        
        # 使用自定义配置初始化安全管理器
        security_manager = SecurityManager(custom_config)
        
        # 执行有限的安全扫描
        print("使用自定义配置执行安全扫描...")
        results = security_manager.run_security_scan()
        
        print(f"扫描完成！启用的检查器数量: {len(results['checkers'])}")
        
        return results
        
    except Exception as e:
        print(f"自定义配置扫描失败: {e}")
        return None


def example_specific_checkers():
    """示例5: 运行特定检查器"""
    print("\n=== 示例5: 运行特定检查器 ===")
    
    try:
        # 加载默认配置
        config_manager = ConfigManager()
        config = config_manager.load_config('config.yaml')
        
        # 初始化安全管理器
        security_manager = SecurityManager(config)
        
        # 只运行用户安全检查器
        print("只运行用户安全检查器...")
        results = security_manager.run_security_scan(enabled_checkers=['user_security'])
        
        # 显示结果
        if 'user_security' in results['checkers']:
            checker_result = results['checkers']['user_security']
            print(f"用户安全检查完成:")
            print(f"  检查项: {checker_result['total_checks']}")
            print(f"  通过: {checker_result['passed_checks']}")
            print(f"  失败: {checker_result['failed_checks']}")
            
            # 显示发现的问题
            if checker_result['issues']:
                print(f"  发现问题:")
                for issue in checker_result['issues'][:3]:  # 只显示前3个问题
                    print(f"    - {issue['title']} ({issue['severity']})")
        
        return results
        
    except Exception as e:
        print(f"特定检查器运行失败: {e}")
        return None


def example_config_management():
    """示例6: 配置管理"""
    print("\n=== 示例6: 配置管理 ===")
    
    try:
        # 初始化配置管理器
        config_manager = ConfigManager()
        
        # 生成示例配置
        example_config_file = '/tmp/example_config.yaml'
        config_manager.generate_example_config(example_config_file)
        print(f"示例配置文件已生成: {example_config_file}")
        
        # 加载配置
        config = config_manager.load_config(example_config_file)
        print(f"配置加载成功，包含 {len(config)} 个主要部分")
        
        # 修改配置
        config_manager.set_config('global.log_level', 'WARNING')
        config_manager.set_config('checkers.filesystem.enabled', False)
        
        # 保存修改后的配置
        modified_config_file = '/tmp/modified_config.yaml'
        config_manager.save_config(modified_config_file)
        print(f"修改后的配置已保存: {modified_config_file}")
        
        # 验证配置
        is_valid, errors = config_manager.validate_config()
        if is_valid:
            print("配置验证通过")
        else:
            print(f"配置验证失败: {errors}")
        
    except Exception as e:
        print(f"配置管理示例失败: {e}")


def main():
    """主函数"""
    print("医疗行业服务器加固系统 - 使用示例")
    print("=" * 50)
    
    # 检查运行权限
    if os.geteuid() != 0:
        print("警告: 建议使用root权限运行以获得完整的检查结果")
    
    # 设置日志
    setup_logging()
    
    try:
        # 示例1: 基本安全扫描
        scan_results = example_basic_scan()
        
        # 示例2: 生成报告
        example_generate_reports(scan_results)
        
        # 示例3: 收集系统信息
        system_info = example_system_info()
        
        # 示例4: 自定义配置
        custom_results = example_custom_config()
        
        # 示例5: 运行特定检查器
        specific_results = example_specific_checkers()
        
        # 示例6: 配置管理
        example_config_management()
        
        print("\n=== 所有示例执行完成 ===")
        print("\n生成的文件:")
        print("  - /tmp/security_report.json")
        print("  - /tmp/security_report.html")
        print("  - /tmp/security_report.txt")
        print("  - /tmp/example_config.yaml")
        print("  - /tmp/modified_config.yaml")
        print("  - /tmp/security_example.log")
        
    except KeyboardInterrupt:
        print("\n用户中断执行")
    except Exception as e:
        print(f"\n示例执行失败: {e}")
        logging.exception("详细错误信息")


if __name__ == '__main__':
    main()