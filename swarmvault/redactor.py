import re
from typing import List, Optional

from .types import RedactionPattern


class SecretRedactor:
    """Automatic secret masking in text."""

    def __init__(self, patterns: Optional[List[RedactionPattern]] = None):
        self.patterns = patterns or []
        
        # Add built-in patterns if none provided
        if not self.patterns:
            self.patterns.extend([
                RedactionPattern(name="api_key", pattern=r"(?i)(api[_-]?key|sk_live|sk_test|pk_live)[=:]\s*([a-zA-Z0-9_-]{16,})"),
                RedactionPattern(name="bearer", pattern=r"(?i)bearer\s+([a-zA-Z0-9_\-\.]{16,})"),
                RedactionPattern(name="password", pattern=r"(?i)(password|passwd|pwd)[=:]\s*([^\s]{8,})"),
                RedactionPattern(name="connection_string", pattern=r"(?i)(mongodb(?:\+srv)?|postgres(?:ql)?|mysql)://([^:]+):([^@]+)@")
            ])
            
        self.exact_secrets = []

    def redact(self, text: str) -> str:
        """Apply all redaction patterns."""
        if not text:
            return text
            
        redacted_text = text
        
        # Exact secrets first
        for secret, label in self.exact_secrets:
            replacement = f"***REDACTED_{label}***" if label else "***REDACTED***"
            redacted_text = redacted_text.replace(secret, replacement)
            
        # Regex patterns
        for pattern in self.patterns:
            try:
                compiled = re.compile(pattern.pattern)
                
                def replace_func(match):
                    # We need to replace the captured group with the redaction string
                    # If there's multiple groups, we try to keep the context and replace the sensitive part.
                    if match.lastindex and match.lastindex > 0:
                        # Simple heuristic: if we have 3 groups (like connection string), replace the last one (password)
                        if pattern.name == "connection_string" and match.lastindex == 3:
                            full_match = match.group(0)
                            pwd = match.group(3)
                            return full_match.replace(pwd, pattern.replacement)
                        
                        # General case: replace the last group which is usually the secret
                        full_match = match.group(0)
                        secret_part = match.group(match.lastindex)
                        return full_match.replace(secret_part, pattern.replacement)
                    return pattern.replacement
                    
                redacted_text = compiled.sub(replace_func, redacted_text)
            except re.error:
                continue
                
        return redacted_text

    def add_pattern(self, pattern: RedactionPattern):
        """Register new pattern."""
        self.patterns.append(pattern)

    def add_secret(self, secret_value: str, label: str = ''):
        """Register exact secret for redaction."""
        if secret_value and len(secret_value) > 3: # Don't redact tiny strings
            self.exact_secrets.append((secret_value, label))
