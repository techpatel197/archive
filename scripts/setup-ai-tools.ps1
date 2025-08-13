# AI Tools Setup Script for Azure DevOps Pipeline
param(
    [string]$OpenAIKey = $env:OPENAI_API_KEY,
    [string]$AzureOpenAIKey = $env:AZURE_OPENAI_KEY,
    [string]$AzureOpenAIEndpoint = $env:AZURE_OPENAI_ENDPOINT
)

Write-Host "🤖 Setting up AI-powered development tools..."

# Create tools directory
$toolsDir = "ai-tools"
if (!(Test-Path $toolsDir)) {
    New-Item -ItemType Directory -Path $toolsDir -Force
}

# Install required Python packages
Write-Host "📦 Installing Python dependencies..."
$pythonRequirements = @"
openai>=1.3.0
requests>=2.28.0
python-dotenv>=0.19.0
colorama>=0.4.4
click>=8.0.0
"@

$pythonRequirements | Out-File -FilePath "$toolsDir/requirements.txt" -Encoding UTF8

try {
    python -m pip install -r "$toolsDir/requirements.txt" --quiet
    Write-Host "✅ Python packages installed successfully"
} catch {
    Write-Warning "⚠️ Python package installation failed. Some AI features may not work."
}

# Create AI configuration file
$aiConfig = @{
    openai = @{
        api_key = if ($OpenAIKey) { $OpenAIKey } else { "" }
        model = "gpt-4"
        temperature = 0.3
        max_tokens = 2000
    }
    azure_openai = @{
        api_key = if ($AzureOpenAIKey) { $AzureOpenAIKey } else { "" }
        endpoint = if ($AzureOpenAIEndpoint) { $AzureOpenAIEndpoint } else { "" }
        api_version = "2023-12-01-preview"
        deployment_name = "gpt-4"
    }
    security_scanning = @{
        enabled = $true
        severity_threshold = "Medium"
        max_files_per_run = 20
    }
    test_generation = @{
        enabled = $true
        max_tests_per_class = 10
        include_edge_cases = $true
        use_moq = $true
    }
}

$aiConfig | ConvertTo-Json -Depth 3 | Out-File -FilePath "$toolsDir/ai-config.json" -Encoding UTF8

# Create AI prompt templates
$promptTemplates = @{
    security_analysis = @"
Analyze this C# code for security vulnerabilities:

File: {file_path}
Code:
{code}

Focus on:
1. SQL Injection vulnerabilities
2. Cross-Site Scripting (XSS)
3. Authentication/Authorization flaws
4. Input validation issues
5. Cryptographic weaknesses
6. Information disclosure
7. CSRF vulnerabilities
8. Unsafe deserialization
9. Path traversal
10. Business logic flaws

For each vulnerability:
- Provide severity (Critical/High/Medium/Low)
- Explain the risk
- Suggest specific mitigation
- Reference OWASP category if applicable

Return as JSON array.
"@
    
    test_generation = @"
Generate comprehensive unit tests for this C# code:

File: {file_path}
Classes: {classes}
Methods: {methods}

Code:
{code}

Generate tests for:
1. Happy path scenarios
2. Edge cases and boundary conditions
3. Null/empty input validation
4. Exception handling
5. Business logic validation

Use:
- xUnit framework
- Moq for mocking
- FluentAssertions for readable assertions
- Arrange-Act-Assert pattern
- Descriptive test names

Return complete C# test class.
"@

    code_review = @"
Review this C# code for:

File: {file_path}
Code:
{code}

Analyze:
1. Code quality and maintainability
2. Performance implications
3. Best practices adherence
4. SOLID principles compliance
5. Potential bugs or issues
6. Documentation quality
7. Error handling
8. Resource management

Provide:
- Overall quality score (1-10)
- Key issues found
- Specific recommendations
- Code smells identified

Format as structured feedback.
"@

    failure_analysis = @"
Analyze this build/test failure:

Build Information:
- Stage: {stage}
- Job: {job}
- Branch: {branch}
- Trigger: {trigger}

Error Information:
{error_logs}

Recent Changes:
{recent_commits}

Provide:
1. Root cause analysis
2. Likely contributing factors
3. Step-by-step resolution guide
4. Prevention recommendations
5. Related documentation links

Focus on actionable solutions.
"@
}

$promptTemplates | ConvertTo-Json -Depth 2 | Out-File -FilePath "$toolsDir/prompt-templates.json" -Encoding UTF8

# Create AI utility functions
$aiUtilities = @'
import json
import os
import openai
from datetime import datetime
from pathlib import Path

class AIHelper:
    def __init__(self, config_file="ai-tools/ai-config.json"):
        self.config = self.load_config(config_file)
        self.setup_openai()
        
    def load_config(self, config_file):
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return self.default_config()
    
    def default_config(self):
        return {
            "openai": {"api_key": "", "model": "gpt-4"},
            "azure_openai": {"api_key": "", "endpoint": ""}
        }
    
    def setup_openai(self):
        openai_config = self.config.get('openai', {})
        azure_config = self.config.get('azure_openai', {})
        
        if azure_config.get('api_key') and azure_config.get('endpoint'):
            openai.api_type = "azure"
            openai.api_key = azure_config['api_key']
            openai.api_base = azure_config['endpoint']
            openai.api_version = azure_config.get('api_version', '2023-12-01-preview')
            self.model = azure_config.get('deployment_name', 'gpt-4')
        elif openai_config.get('api_key'):
            openai.api_key = openai_config['api_key']
            self.model = openai_config.get('model', 'gpt-4')
        else:
            openai.api_key = None
    
    def call_ai(self, prompt, system_message="You are a helpful assistant."):
        if not openai.api_key:
            return {"error": "No API key configured"}
        
        try:
            if openai.api_type == "azure":
                response = openai.ChatCompletion.create(
                    engine=self.model,
                    messages=[
                        {"role": "system", "content": system_message},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=self.config['openai'].get('temperature', 0.3),
                    max_tokens=self.config['openai'].get('max_tokens', 2000)
                )
            else:
                response = openai.ChatCompletion.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system_message},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=self.config['openai'].get('temperature', 0.3),
                    max_tokens=self.config['openai'].get('max_tokens', 2000)
                )
            
            return {
                "success": True,
                "content": response.choices[0].message.content,
                "usage": response.usage
            }
        except Exception as e:
            return {"error": str(e)}
    
    def load_prompt_template(self, template_name):
        try:
            with open("ai-tools/prompt-templates.json", 'r') as f:
                templates = json.load(f)
            return templates.get(template_name, "")
        except FileNotFoundError:
            return ""
    
    def save_analysis_result(self, analysis_type, result, output_dir="ai-reports"):
        Path(output_dir).mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{analysis_type}_{timestamp}.json"
        
        output = {
            "timestamp": datetime.now().isoformat(),
            "analysis_type": analysis_type,
            "result": result
        }
        
        with open(Path(output_dir) / filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        return str(Path(output_dir) / filename)

# Global helper instance
ai_helper = AIHelper()
'@

$aiUtilities | Out-File -FilePath "$toolsDir/ai_helper.py" -Encoding UTF8

# Create environment setup script
$envSetup = @'
# AI Tools Environment Setup
export AI_TOOLS_DIR="ai-tools"
export PYTHONPATH="${PYTHONPATH}:${AI_TOOLS_DIR}"

# Function to check AI tool status
check_ai_tools() {
    echo "🤖 AI Tools Status:"
    
    if command -v python3 &> /dev/null; then
        echo "✅ Python 3 available"
    else
        echo "❌ Python 3 not found"
        return 1
    fi
    
    if [ -n "$OPENAI_API_KEY" ] || [ -n "$AZURE_OPENAI_KEY" ]; then
        echo "✅ AI API key configured"
    else
        echo "⚠️ No AI API key found - some features will be limited"
    fi
    
    if [ -f "ai-tools/ai-config.json" ]; then
        echo "✅ AI configuration found"
    else
        echo "❌ AI configuration missing"
    fi
    
    return 0
}

# Function to run security analysis
run_ai_security_scan() {
    local source_dir=${1:-"src"}
    local output_dir=${2:-"security-reports"}
    
    echo "🔒 Running AI-powered security scan..."
    python3 ai-tools/ai-security-scanner.py "$source_dir" "$output_dir"
}

# Function to generate tests
generate_ai_tests() {
    local source_dir=${1:-"src"}
    local output_dir=${2:-"tests/Generated"}
    
    echo "🧪 Generating AI-powered unit tests..."
    python3 ai-tools/generate-tests.py "$source_dir" "$output_dir"
}

# Function to analyze test results
analyze_test_results() {
    local results_dir=${1:-"TestResults"}
    local output_file=${2:-"test-analysis-report.json"}
    
    echo "📊 Analyzing test results with AI..."
    python3 ai-tools/ai-test-analyzer.py "$results_dir" "$output_file"
}

echo "AI tools environment loaded. Available functions:"
echo "  - check_ai_tools"
echo "  - run_ai_security_scan [source_dir] [output_dir]"
echo "  - generate_ai_tests [source_dir] [output_dir]"
echo "  - analyze_test_results [results_dir] [output_file]"
'@

$envSetup | Out-File -FilePath "$toolsDir/ai-env.sh" -Encoding UTF8

# Create validation script
$validationScript = @'
#!/usr/bin/env python3
"""
Validate AI tools setup and configuration
"""

import sys
import os
import json
from pathlib import Path

def check_python_packages():
    """Check if required Python packages are installed"""
    required_packages = ['openai', 'requests']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"✅ {package} installed")
        except ImportError:
            missing_packages.append(package)
            print(f"❌ {package} missing")
    
    return len(missing_packages) == 0

def check_api_keys():
    """Check if AI API keys are configured"""
    openai_key = os.getenv('OPENAI_API_KEY')
    azure_key = os.getenv('AZURE_OPENAI_KEY')
    
    if openai_key:
        print("✅ OpenAI API key configured")
        return True
    elif azure_key:
        print("✅ Azure OpenAI API key configured")
        return True
    else:
        print("⚠️ No AI API keys found - AI features will be limited")
        return False

def check_configuration():
    """Check if AI configuration files exist"""
    config_file = Path("ai-tools/ai-config.json")
    templates_file = Path("ai-tools/prompt-templates.json")
    
    files_ok = True
    
    if config_file.exists():
        print("✅ AI configuration file found")
        try:
            with open(config_file) as f:
                config = json.load(f)
            print("✅ AI configuration is valid JSON")
        except json.JSONDecodeError:
            print("❌ AI configuration file is not valid JSON")
            files_ok = False
    else:
        print("❌ AI configuration file missing")
        files_ok = False
    
    if templates_file.exists():
        print("✅ Prompt templates file found")
    else:
        print("❌ Prompt templates file missing")
        files_ok = False
    
    return files_ok

def main():
    print("🤖 Validating AI tools setup...\n")
    
    success = True
    
    print("📦 Checking Python packages:")
    if not check_python_packages():
        success = False
    
    print("\n🔑 Checking API keys:")
    check_api_keys()  # Not required for basic functionality
    
    print("\n⚙️ Checking configuration:")
    if not check_configuration():
        success = False
    
    print(f"\n{'✅' if success else '❌'} AI tools validation {'completed successfully' if success else 'failed'}")
    
    if not success:
        print("\nTo fix issues:")
        print("1. Run: pip install -r ai-tools/requirements.txt")
        print("2. Set AI API keys in environment variables")
        print("3. Ensure configuration files are present and valid")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
'@

$validationScript | Out-File -FilePath "$toolsDir/validate-setup.py" -Encoding UTF8

Write-Host "✅ AI tools setup completed successfully!"
Write-Host ""
Write-Host "📁 Created files:"
Write-Host "   - $toolsDir/requirements.txt (Python dependencies)"
Write-Host "   - $toolsDir/ai-config.json (AI configuration)"
Write-Host "   - $toolsDir/prompt-templates.json (AI prompts)"
Write-Host "   - $toolsDir/ai_helper.py (AI utility functions)"
Write-Host "   - $toolsDir/ai-env.sh (Environment setup)"
Write-Host "   - $toolsDir/validate-setup.py (Setup validation)"
Write-Host ""
Write-Host "🔧 Next steps:"
Write-Host "1. Set your AI API keys as pipeline variables:"
Write-Host "   - OPENAI_API_KEY (for OpenAI)"
Write-Host "   - AZURE_OPENAI_KEY + AZURE_OPENAI_ENDPOINT (for Azure OpenAI)"
Write-Host "2. Run validation: python ai-tools/validate-setup.py"
Write-Host "3. Test the pipeline with your changes"
Write-Host ""
Write-Host "🚀 AI-enhanced features now available:"
Write-Host "   - Intelligent unit test generation"
Write-Host "   - AI-powered security vulnerability detection"
Write-Host "   - Automated test result analysis"
Write-Host "   - Smart failure diagnosis"