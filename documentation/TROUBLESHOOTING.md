# REVUEX Troubleshooting Guide

## Common Issues

### Import Errors

#### "ModuleNotFoundError: No module named 'tools'"

**Solution:**
```bash
# Add REVUEX to Python path
export PYTHONPATH="${PYTHONPATH}:/path/to/revuex-vul-suite"

# Or install as package
pip install -e .
```

#### "ModuleNotFoundError: No module named 'core'"

**Solution:**
```bash
# Ensure you're in the project root
cd /path/to/revuex-vul-suite

# Install the package
pip install -e .
```

### Dependency Issues

#### "ModuleNotFoundError: No module named 'requests'"

**Solution:**
```bash
pip install -r requirements.txt
```

#### "ModuleNotFoundError: No module named 'bs4'"

**Solution:**
```bash
pip install beautifulsoup4
```

### SSL/TLS Errors

#### "SSLError: certificate verify failed"

**Solution:**
```python
# In your code (not recommended for production)
scanner = SomeScanner(target="https://example.com", verify_ssl=False)

# Better: Update certificates
pip install --upgrade certifi
```

### Network Issues

#### "ConnectionError: Max retries exceeded"

**Causes:**
- Target is down
- Rate limiting
- Network issues

**Solutions:**
```python
# Increase timeout
scanner = SomeScanner(target="...", timeout=30)

# Increase delay
scanner = SomeScanner(target="...", delay=2.0)
```

#### "TimeoutError"

**Solution:**
```python
scanner = SomeScanner(target="...", timeout=30)
```

### Scanner-Specific Issues

#### SSRF Scanner: "No endpoints discovered"

**Solutions:**
1. Provide endpoints manually:
```python
scanner = SSRFScanner(
    target="https://example.com",
    endpoints=["/api/proxy", "/api/fetch"]
)
```

2. Check if target returns HTML (SIE needs HTML to discover endpoints)

#### SQLi Scanner: "No parameters to test"

**Solution:**
```python
# Ensure URL has parameters
scanner = SQLiScanner(target="https://example.com/search?q=test")

# Or specify parameters
scanner = SQLiScanner(
    target="https://example.com/search",
    test_params=["q", "id", "page"]
)
```

#### XXE Scanner: "Failed to fetch target"

**Solutions:**
1. Ensure target accepts POST requests
2. Check Content-Type is accepted
```python
scanner = XXEScanner(
    target="https://example.com/api",
    custom_headers={"Content-Type": "application/xml"}
)
```

#### APK Analyzer: "apktool not found"

**Solution:**
```bash
# Install apktool
sudo apt install apktool  # Debian/Ubuntu
brew install apktool      # macOS
```

#### JWT Analyzer: "Invalid token format"

**Solution:**
Ensure token is a valid JWT:
```python
# Correct format
scanner = JWTAnalyzer(target="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
```

### Output Issues

#### "Permission denied" when writing output

**Solution:**
```bash
# Check directory permissions
ls -la ./scans/

# Create with correct permissions
mkdir -p ./scans
chmod 755 ./scans
```

#### JSON output is empty

**Solutions:**
1. Check if scan completed:
```python
result = scanner.run()
print(f"Status: {result.status}")
print(f"Findings: {len(result.findings)}")
```

2. Verify output path:
```bash
python -m tools.ssrf -t https://example.com -o /absolute/path/output.json
```

### Performance Issues

#### Scan is very slow

**Solutions:**
1. Reduce delay:
```python
scanner = SomeScanner(target="...", delay=0.1)
```

2. Increase timeout but reduce retries:
```python
scanner = SomeScanner(target="...", timeout=5)
```

3. Use specific parameters instead of discovery:
```python
scanner = SSRFScanner(
    target="...",
    skip_discovery=True,
    endpoints=["/api/proxy"]
)
```

#### High memory usage

**Solutions:**
1. Scan one target at a time
2. Clear findings periodically for batch scans
3. Use streaming output for large scans

### False Positives

#### Getting too many findings

**Solutions:**
1. Increase confidence threshold:
```python
scanner = SomeScanner(target="...", confidence_threshold=85)
```

2. Review findings manually before reporting

#### Getting no findings on known vulnerable target

**Solutions:**
1. Lower confidence threshold:
```python
scanner = SomeScanner(target="...", confidence_threshold=60)
```

2. Enable verbose mode to see what's happening:
```python
scanner = SomeScanner(target="...", verbose=True)
```

3. Check if target is blocking requests (WAF)

## Debug Mode

Enable debug mode for detailed output:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

scanner = SomeScanner(target="...", verbose=True)
result = scanner.run()
```

## Getting Help

### Check Logs

```python
# Enable verbose logging
scanner = SomeScanner(target="...", verbose=True)
```

### Report Issues

When reporting issues, include:

1. **Python version**: `python --version`
2. **REVUEX version**: Check `tools/__init__.py`
3. **Operating system**
4. **Full error traceback**
5. **Minimal reproduction code**

### Contact

- **GitHub Issues**: Report bugs and feature requests
- **Telegram**: @x0x0h33l0

## FAQ

### Q: Can I use REVUEX without installing?

A: Yes, add to Python path:
```bash
export PYTHONPATH="${PYTHONPATH}:/path/to/revuex"
python -m tools.ssrf -t https://example.com
```

### Q: How do I update REVUEX?

A:
```bash
cd revuex-vul-suite
git pull origin main
pip install -e .
```

### Q: Can I run multiple scanners in parallel?

A: Yes, but be careful with rate limiting:
```python
from concurrent.futures import ThreadPoolExecutor
from tools import get_scanner

def run_scanner(scanner_name, target):
    scanner_class = get_scanner(scanner_name)
    scanner = scanner_class(target=target, delay=1.0)
    return scanner.run()

with ThreadPoolExecutor(max_workers=3) as executor:
    futures = [
        executor.submit(run_scanner, name, target)
        for name in ["ssrf", "sqli", "xss"]
    ]
```

### Q: How do I add custom headers to all requests?

A:
```python
scanner = SomeScanner(
    target="https://example.com",
    custom_headers={
        "Authorization": "Bearer token",
        "X-Custom-Header": "value"
    }
)
```

### Q: Can I use a proxy?

A:
```python
scanner = SomeScanner(target="https://example.com")
scanner.session.proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}
result = scanner.run()
```
