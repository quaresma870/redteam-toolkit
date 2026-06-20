# Mock target — FOR CI USE ONLY

⚠️ **Never run this outside a test session. Never expose it to a network.**

This is a minimal local HTTP server with deliberately vulnerable endpoints
(reflected XSS, open redirect) alongside safe variants of the same endpoints,
so detection modules in later sprints have a known, reproducible target to
test against — never real external infrastructure.

```python
from tests.fixtures.mock_target.server import start_mock_target

server, port = start_mock_target()
try:
    ...  # http://127.0.0.1:{port}/vulnerable/reflect?q=...
finally:
    server.shutdown()
```
