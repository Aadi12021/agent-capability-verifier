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
| [`vulnerable_loader_4_joint_path.py`](vulnerable_loader_4_joint_path.py) | Yes (joint) | Two fields, each declared `OPAQUE_STRING`, are joined with `os.path.join(...)` into a file path — a mismatch neither field's individual declaration would ever catch. |
| [`vulnerable_loader_5_none_field.py`](vulnerable_loader_5_none_field.py) | Yes | A field declared `NONE` (must not be consumed at all) is read and used as a file-write path. |
| [`vulnerable_loader_6_write.py`](vulnerable_loader_6_write.py) | Yes | A field declared `OPAQUE_STRING` is used as the destination of `open(..., "w")` — a mismatched *write*, not a read. |
| [`vulnerable_loader_7_numeric_subprocess.py`](vulnerable_loader_7_numeric_subprocess.py) | Yes | A field declared `NUMERIC` is forwarded, unvalidated, into a `subprocess.run` argument list. |
| [`vulnerable_loader_8_enum_eval.py`](vulnerable_loader_8_enum_eval.py) | Yes | A field declared `ENUM` reaches `eval()` — code execution is never a legitimized capability, regardless of declaration. |
| [`vulnerable_loader_9_numeric_template_fstring.py`](vulnerable_loader_9_numeric_template_fstring.py) | Yes | A field declared `NUMERIC` is interpolated into an f-string that's rendered as a template — a single-field f-string case, not a joint one. |
| [`vulnerable_loader_10_reassigned_alias.py`](vulnerable_loader_10_reassigned_alias.py) | Yes | A field declared `OPAQUE_STRING` is copied to a differently-named local variable before reaching `subprocess.run` — confirms the mismatch survives a rename. |
| [`vulnerable_loader_11_conditional_branch.py`](vulnerable_loader_11_conditional_branch.py) | Yes | A field declared `OPAQUE_STRING` only reaches a template-render sink inside an `if` branch — confirms detection is branch-insensitive (sound, not path-sensitive). |
| [`vulnerable_loader_12_helper_function_undetected.py`](vulnerable_loader_12_helper_function_undetected.py) | **No — known gap** | A real file-write mismatch, but the sink is inside a plain helper function the loader calls, not in the loader body itself. capaudit does no interprocedural analysis (see the README's scope section) and stays completely silent on this file; it's kept as a documented, pinned-down limitation, not fixed here. |
| [`clean_loader.py`](clean_loader.py) | No | Every field's declared capability matches its actual use — the false-positive test case. |
| [`clean_loader_joint_path.py`](clean_loader_joint_path.py) | No (joint) | Same shape as `vulnerable_loader_4_joint_path.py`, but the schema declares a `JointCapability` rule for the combination — the joint-case false-positive test case. |
| [`clean_loader_command.py`](clean_loader_command.py) | No | A field declared `COMMAND` used correctly in `subprocess.run`, plus a field declared `ENUM` used safely (compared, never forwarded to a sink) — no clean example previously existed for either capability. |
| [`clean_loader_network.py`](clean_loader_network.py) | No | A field declared `NETWORK_ADDRESS` used correctly as a network call's destination — no clean example previously existed for this capability. |
| [`clean_loader_template.py`](clean_loader_template.py) | No | A field declared `TEMPLATE` used correctly with the template engine — no clean example previously existed for this capability. |
| [`clean_loader_sanitized_path.py`](clean_loader_sanitized_path.py) | No | A field declared `FILE_PATH`, correctly used, *and* validated against an allowlist before use — confirms validation code doesn't confuse alias resolution into a spurious mismatch (a precision check, not a recall one). |

Each file's schema declaration and loader function are read statically by `capaudit`; nothing in
`examples/` is ever imported or executed by the tool itself, so the `jinja2` import in
`vulnerable_loader_2_template.py`, `vulnerable_loader_9_numeric_template_fstring.py`,
`vulnerable_loader_11_conditional_branch.py`, and `clean_loader_template.py` does not need to be
installed for analysis to work.
