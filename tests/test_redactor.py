from swarmvault.redactor import SecretRedactor

def test_redact_api_key():
    redactor = SecretRedactor()
    text = "Here is my key api_key=sk_live_1234567890abcdefghij and some text."
    redacted = redactor.redact(text)
    assert "sk_live_1234567890abcdefghij" not in redacted
    assert "***REDACTED***" in redacted

def test_redact_connection_string():
    redactor = SecretRedactor()
    text = "Connect using mongodb://user:supersecretpass@localhost"
    redacted = redactor.redact(text)
    assert "supersecretpass" not in redacted
    assert "***REDACTED***" in redacted

def test_exact_secret_redaction():
    redactor = SecretRedactor()
    redactor.add_secret("my_custom_secret_value", "custom")
    text = "The password is my_custom_secret_value."
    redacted = redactor.redact(text)
    assert "my_custom_secret_value" not in redacted
    assert "***REDACTED_custom***" in redacted
