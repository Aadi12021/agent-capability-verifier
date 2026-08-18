# Examples

Original, hand-written toy config loaders used as test fixtures for the capability tracer.

These are **not** reproductions of any real-world disclosed exploit. Each vulnerable example
demonstrates the general bug class — a config field whose declared capability schema is narrower
than what the loader code actually does with the field's value — using code written from scratch
for this project.

## Files

| File | Mismatch? | What it demonstrates |
|---|---|---|
| [`vulnerable_loader_1_path.py`](vulnerable_loader_1_path.py) | Yes | A field declared `NUMERIC` (a byte offset) is actually used as a file path passed to `open()`. |
| [`vulnerable_loader_2_template.py`](vulnerable_loader_2_template.py) | Yes | A field declared `OPAQUE_STRING` is actually rendered as a Jinja2 template. |
| [`vulnerable_loader_3_subprocess.py`](vulnerable_loader_3_subprocess.py) | Yes | A field declared `ENUM` is forwarded, unvalidated, into a `subprocess.run` argument list. |
| [`clean_loader.py`](clean_loader.py) | No | Every field's declared capability matches its actual use — the false-positive test case. |

Each file's schema declaration and loader function are read statically by `capaudit`; nothing in
`examples/` is ever imported or executed by the tool itself, so the `jinja2` import in
`vulnerable_loader_2_template.py` does not need to be installed for analysis to work.
