#!/usr/bin/env python3
"""
AI-Powered Test Analyzer
Analyzes test results and provides intelligent insights
"""

import json
import sys
import os
import xml.etree.ElementTree as ET
from pathlib import Path
import openai
from datetime import datetime

class TestAnalyzer:
    def __init__(self):
        self.setup_openai()
        
    def setup_openai(self):
        """Configure OpenAI API"""
        self.api_key = os.getenv('OPENAI_API_KEY')
        if not self.api_key and os.getenv('AZURE_OPENAI_KEY'):
            openai.api_type = "azure"
            openai.api_key = os.getenv('AZURE_OPENAI_KEY')
            openai.api_base = os.getenv('AZURE_OPENAI_ENDPOINT')
            openai.api_version = "2023-12-01-preview"
        else:
            openai.api_key = self.api_key
    
    def parse_trx_files(self, test_results_dir):
        """Parse TRX test result files"""
        test_results = []
        trx_files = list(Path(test_results_dir).rglob("*.trx"))
        
        for trx_file in trx_files:
            try:
                tree = ET.parse(trx_file)
                root = tree.getroot()
                
                # Extract namespace
                namespace = {'ms': 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'}
                
                # Get test summary
                counters = root.find('.//ms:Counters', namespace)
                if counters is not None:
                    summary = {
                        'total': int(counters.get('total', 0)),
                        'executed': int(counters.get('executed', 0)),
                        'passed': int(counters.get('passed', 0)),
                        'failed': int(counters.get('failed', 0)),
                        'error': int(counters.get('error', 0)),
                        'timeout': int(counters.get('timeout', 0)),
                        'aborted': int(counters.get('aborted', 0)),
                        'inconclusive': int(counters.get('inconclusive', 0))
                    }
                else:
                    summary = {'total': 0, 'passed': 0, 'failed': 0}
                
                # Get individual test results
                tests = []
                test_results_elem = root.findall('.//ms:UnitTestResult', namespace)
                
                for test_result in test_results_elem:
                    test_info = {
                        'name': test_result.get('testName', ''),
                        'outcome': test_result.get('outcome', ''),
                        'duration': test_result.get('duration', ''),
                    }
                    
                    # Get error information if test failed
                    error_info = test_result.find('.//ms:ErrorInfo', namespace)
                    if error_info is not None:
                        message_elem = error_info.find('ms:Message', namespace)
                        stack_trace_elem = error_info.find('ms:StackTrace', namespace)
                        
                        test_info['error_message'] = message_elem.text if message_elem is not None else ''
                        test_info['stack_trace'] = stack_trace_elem.text if stack_trace_elem is not None else ''
                    
                    tests.append(test_info)
                
                test_results.append({
                    'file': str(trx_file),
                    'summary': summary,
                    'tests': tests
                })
                
            except ET.ParseError as e:
                print(f"Error parsing {trx_file}: {e}")
            except Exception as e:
                print(f"Error processing {trx_file}: {e}")
        
        return test_results
    
    def analyze_test_patterns(self, test_results):
        """Analyze test patterns and identify issues"""
        analysis = {
            'total_tests': 0,
            'total_passed': 0,
            'total_failed': 0,
            'failure_patterns': [],
            'performance_issues': [],
            'recommendations': []
        }
        
        all_failed_tests = []
        slow_tests = []
        
        for result in test_results:
            summary = result['summary']
            analysis['total_tests'] += summary['total']
            analysis['total_passed'] += summary['passed']
            analysis['total_failed'] += summary['failed']
            
            # Analyze failed tests
            failed_tests = [t for t in result['tests'] if t['outcome'] != 'Passed']
            all_failed_tests.extend(failed_tests)
            
            # Analyze slow tests (duration > 5 seconds)
            for test in result['tests']:
                if test['duration']:
                    # Parse duration (PT0.123456S format)
                    try:
                        duration_str = test['duration'].replace('PT', '').replace('S', '')
                        duration = float(duration_str)
                        if duration > 5.0:
                            slow_tests.append({
                                'name': test['name'],
                                'duration': duration
                            })
                    except:
                        pass
        
        # Find common failure patterns
        if all_failed_tests:
            error_messages = [t.get('error_message', '') for t in all_failed_tests if t.get('error_message')]
            
            # Group similar errors
            common_errors = {}
            for error in error_messages:
                # Simple grouping by exception type
                error_type = error.split(':')[0] if ':' in error else error[:50]
                common_errors[error_type] = common_errors.get(error_type, 0) + 1
            
            analysis['failure_patterns'] = [
                {'pattern': pattern, 'count': count} 
                for pattern, count in sorted(common_errors.items(), key=lambda x: x[1], reverse=True)
            ]
        
        analysis['performance_issues'] = sorted(slow_tests, key=lambda x: x['duration'], reverse=True)[:10]
        
        return analysis
    
    def get_ai_insights(self, analysis, test_results):
        """Get AI-powered insights on test results"""
        if not self.api_key and not os.getenv('AZURE_OPENAI_KEY'):
            return self.get_fallback_insights(analysis)
        
        # Prepare data for AI analysis
        summary_data = {
            'total_tests': analysis['total_tests'],
            'pass_rate': (analysis['total_passed'] / analysis['total_tests'] * 100) if analysis['total_tests'] > 0 else 0,
            'failure_patterns': analysis['failure_patterns'][:5],  # Top 5 patterns
            'slow_tests_count': len(analysis['performance_issues']),
            'slowest_tests': analysis['performance_issues'][:3]
        }
        
        prompt = f"""
        Analyze these .NET test results and provide actionable insights:
        
        Test Summary:
        - Total tests: {summary_data['total_tests']}
        - Pass rate: {summary_data['pass_rate']:.1f}%
        - Failed tests: {analysis['total_failed']}
        
        Common failure patterns:
        {json.dumps(summary_data['failure_patterns'], indent=2)}
        
        Performance issues:
        - Slow tests (>5s): {summary_data['slow_tests_count']}
        - Slowest tests: {json.dumps(summary_data['slowest_tests'], indent=2)}
        
        Provide:
        1. Overall test health assessment
        2. Priority issues to address
        3. Specific recommendations for improvement
        4. Potential root causes for failures
        5. Testing strategy improvements
        
        Format as structured JSON with sections: health_score (1-10), priority_issues, recommendations, root_causes
        """
        
        try:
            if openai.api_type == "azure":
                response = openai.ChatCompletion.create(
                    engine="gpt-4",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=1500,
                    temperature=0.3
                )
            else:
                response = openai.ChatCompletion.create(
                    model="gpt-4",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=1500,
                    temperature=0.3
                )
            
            ai_response = response.choices[0].message.content.strip()
            
            try:
                return json.loads(ai_response)
            except json.JSONDecodeError:
                # If AI doesn't return valid JSON, wrap the response
                return {
                    "health_score": 7,
                    "ai_analysis": ai_response,
                    "recommendations": ["Review AI analysis for detailed insights"]
                }
                
        except Exception as e:
            print(f"AI analysis failed: {e}")
            return self.get_fallback_insights(analysis)
    
    def get_fallback_insights(self, analysis):
        """Fallback insights when AI is not available"""
        pass_rate = (analysis['total_passed'] / analysis['total_tests'] * 100) if analysis['total_tests'] > 0 else 0
        
        health_score = 10
        if pass_rate < 95: health_score = 8
        if pass_rate < 90: health_score = 6
        if pass_rate < 80: health_score = 4
        if pass_rate < 70: health_score = 2
        
        recommendations = []
        
        if analysis['total_failed'] > 0:
            recommendations.append(f"Address {analysis['total_failed']} failing tests immediately")
        
        if len(analysis['performance_issues']) > 10:
            recommendations.append("Optimize slow-running tests to improve CI/CD performance")
        
        if pass_rate < 95:
            recommendations.append("Improve test reliability - target 95%+ pass rate")
        
        return {
            "health_score": health_score,
            "pass_rate": pass_rate,
            "priority_issues": [pattern['pattern'] for pattern in analysis['failure_patterns'][:3]],
            "recommendations": recommendations,
            "root_causes": ["Review failure patterns for common issues"]
        }
    
    def generate_report(self, analysis, ai_insights, output_file):
        """Generate comprehensive test analysis report"""
        report = {
            "analysis_date": datetime.now().isoformat(),
            "test_summary": {
                "total_tests": analysis['total_tests'],
                "passed": analysis['total_passed'],
                "failed": analysis['total_failed'],
                "pass_rate": (analysis['total_passed'] / analysis['total_tests'] * 100) if analysis['total_tests'] > 0 else 0
            },
            "failure_analysis": {
                "patterns": analysis['failure_patterns'],
                "performance_issues": analysis['performance_issues']
            },
            "ai_insights": ai_insights,
            "recommendations": ai_insights.get('recommendations', [])
        }
        
        # Save detailed JSON report
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Generate markdown summary
        markdown_file = output_file.replace('.json', '.md')
        markdown_content = f"""# Test Analysis Report
        
## Summary
- **Total Tests**: {analysis['total_tests']}
- **Pass Rate**: {report['test_summary']['pass_rate']:.1f}%
- **Failed Tests**: {analysis['total_failed']}
- **Health Score**: {ai_insights.get('health_score', 'N/A')}/10

## Priority Issues
"""
        
        for issue in ai_insights.get('priority_issues', []):
            markdown_content += f"- ❌ {issue}\n"
        
        markdown_content += "\n## Recommendations\n"
        for rec in ai_insights.get('recommendations', []):
            markdown_content += f"- 💡 {rec}\n"
        
        if analysis['performance_issues']:
            markdown_content += "\n## Performance Issues\n"
            for test in analysis['performance_issues'][:5]:
                markdown_content += f"- ⏱️ {test['name']}: {test['duration']:.2f}s\n"
        
        with open(markdown_file, 'w') as f:
            f.write(markdown_content)
        
        print(f"Test analysis report generated: {output_file}")
        print(f"Summary report: {markdown_file}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python ai-test-analyzer.py <test_results_directory> [output_file]")
        sys.exit(1)
    
    test_results_dir = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "test-analysis-report.json"
    
    analyzer = TestAnalyzer()
    
    print("🔍 Parsing test results...")
    test_results = analyzer.parse_trx_files(test_results_dir)
    
    if not test_results:
        print("❌ No test result files found")
        sys.exit(1)
    
    print("📊 Analyzing test patterns...")
    analysis = analyzer.analyze_test_patterns(test_results)
    
    print("🤖 Getting AI insights...")
    ai_insights = analyzer.get_ai_insights(analysis, test_results)
    
    print("📝 Generating report...")
    analyzer.generate_report(analysis, ai_insights, output_file)
    
    # Print summary to console
    pass_rate = analysis['total_passed'] / analysis['total_tests'] * 100 if analysis['total_tests'] > 0 else 0
    print(f"\n✅ Analysis complete!")
    print(f"   Pass rate: {pass_rate:.1f}%")
    print(f"   Health score: {ai_insights.get('health_score', 'N/A')}/10")
    print(f"   Failed tests: {analysis['total_failed']}")

if __name__ == "__main__":
    main()