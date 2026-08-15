# Loader configuration boundary

No loader configuration format, schema, filename, or lookup policy has been
adopted by this scaffold.

If WYR0-B demonstrates that configuration is necessary, keep it deliberately
small, deterministic, and host-testable. Its parser must treat firmware/media
input as hostile and must not become a general configuration language. Any
format and path become real only when introduced with the canonical loader
implementation and its negative tests.
