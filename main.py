#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
医疗行业服务器加固系统
主程序入口文件

作者: 马民
版本: 1.0.0
描述: 专为医疗机构设计的服务器安全检查和加固综合工具
"""

import os
import sys
import argparse
import json
from datetime import datetime
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.security_manager import SecurityManager
from core.report_generator import ReportGenerator
from utils.config import ConfigManager
import logging


def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description='医疗行业服务器加固系统',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python main.py --scan                    # 执行安全扫描
  python main.py --scan --fix              # 执行扫描并自动修复
  python main.py --scan --report html      # 生成HTML报告
  python main.py --config custom.json     # 使用自定义配置文件
        """
    )
    
    parser.add_argument('--scan', action='store_true',
                       help='执行安全扫描')
    parser.add_argument('--fix', action='store_true',
                       help='自动修复发现的安全问题')
    parser.add_argument('--report', choices=['json', 'html', 'txt'],
                       default='json', help='报告格式 (默认: json)')
    parser.add_argument('--config', type=str,
                       default='config.yaml',
                       help='配置文件路径')
    parser.add_argument('--output', type=str,
                       default='reports',
                       help='报告输出目录')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='详细输出')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='静默模式')
    
    return parser.parse_args()


def main():
    """主函数"""
    args = parse_arguments()
    
    # 设置日志
    log_level = logging.DEBUG if args.verbose else logging.WARNING if args.quiet else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)
    
    try:
        # 检查运行权限（仅在Linux系统上）
        try:
            if os.geteuid() != 0:
                logger.warning("建议以root权限运行以获得完整的检查结果")
        except AttributeError:
            # Windows系统没有geteuid函数
            logger.info("在Windows系统上运行，某些检查功能可能受限")
        
        # 加载配置
        config_manager = ConfigManager()
        if os.path.exists(args.config):
            config_manager.load_config(args.config)
        else:
            logger.warning(f"配置文件 {args.config} 不存在，使用默认配置")
        config = config_manager.config
        logger.info(f"配置加载完成")
        
        # 创建输出目录
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        if args.scan:
            logger.info("开始执行安全扫描...")
            
            # 初始化安全管理器
            security_manager = SecurityManager(config)
            
            # 执行扫描
            scan_results = security_manager.run_scan()
            
            # 如果需要修复
            if args.fix:
                logger.info("开始执行安全修复...")
                fix_results = security_manager.run_fix(scan_results)
                scan_results['fix_results'] = fix_results
            
            # 生成报告
            report_generator = ReportGenerator()
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_file = output_dir / f"security_report_{timestamp}.{args.report}"
            
            report_generator.generate_report(
                scan_results, 
                str(report_file), 
                args.report
            )
            
            logger.info(f"扫描完成，报告已保存到: {report_file}")
            
            # 显示摘要
            total_checks = scan_results.get('total_checks', 0)
            passed_checks = scan_results.get('passed_checks', 0)
            failed_checks = scan_results.get('failed_checks', 0)
            
            print(f"\n=== 扫描摘要 ===")
            print(f"总检查项: {total_checks}")
            print(f"通过检查: {passed_checks}")
            print(f"失败检查: {failed_checks}")
            print(f"安全评分: {scan_results.get('security_score', 0):.1f}/100")
            
            if failed_checks > 0:
                print(f"\n发现 {failed_checks} 个安全问题，请查看详细报告")
                sys.exit(1)
            else:
                print("\n恭喜！未发现安全问题")
                sys.exit(0)
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        logger.info("用户中断操作")
        sys.exit(130)
    except Exception as e:
        logger.error(f"程序执行出错: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()