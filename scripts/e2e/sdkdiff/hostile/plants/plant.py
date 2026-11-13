"""Planted-defect transforms for the hostile-server mode (hostile/RULES.md section 5).

Usage: plant.py <PH0..PH6> <copy of the SDK tree>.  Edits only the scratch copy it is given; every replacement
must match exactly once, otherwise the script fails (a plant that silently did not apply would be a false 'miss').
"""
import pathlib
import sys


def sub(path, old, new, count=1):
    p = pathlib.Path(path)
    s = p.read_text()
    if s.count(old) != count:
        sys.exit(f"{path}: expected {count} match(es) of {old!r}, found {s.count(old)}")
    p.write_text(s.replace(old, new))


LENIENT = '''	rawPH1, _ := io.ReadAll(resp.Body)
	if i := bytes.Index(rawPH1, []byte(`"value":"`)); i >= 0 {
		rest := rawPH1[i+9:]
		j := bytes.IndexByte(rest, '"')
		if j < 0 {
			j = len(rest)
		}
		return string(rest[:j]), nil
	}
	resp.Body = io.NopCloser(bytes.NewReader(rawPH1))
'''


def ph0(root):
    sub(f"{root}/go/keyorix.go", "// Option configures the client.", "// Option configures the client. (PH0 no-op)")
    sub(f"{root}/python/keyorix.py", "def login(server_url: str, username: str, password: str, timeout: int = 30) -> str:",
        "# PH0 no-op\ndef login(server_url: str, username: str, password: str, timeout: int = 30) -> str:")
    sub(f"{root}/node/keyorix.js", "function errorCodeOf(body) {", "// PH0 no-op\nfunction errorCodeOf(body) {")
    sub(f"{root}/java/src/main/java/com/keyorix/KeyorixClient.java", "    private String get(String path) throws KeyorixException {",
        "    // PH0 no-op\n    private String get(String path) throws KeyorixException {")


def ph1(root):
    # Go returns the partial text when a secret-value body is cut (both value paths).
    f = f"{root}/go/keyorix.go"
    s = pathlib.Path(f).read_text()
    for fn in ("func (c *Client) getSecretValue(", "func (c *Client) GetSecretByRef("):
        a = s.index(fn)
        b = s.index("\tvar result struct {", a)
        s = s[:b] + LENIENT + s[b:]
    pathlib.Path(f).write_text(s)


def ph2(root):
    # Python treats an HTTP 500 as success and parses its body.
    sub(f"{root}/python/keyorix.py",
        "        except urllib.error.HTTPError as e:\n            body = e.read().decode(errors=\"replace\")\n            raise _error_for_response(e.code, body) from e\n        except urllib.error.URLError as e:\n            raise KeyorixError(f\"Request failed: {e.reason}\") from e\n        except TimeoutError as e:\n            raise KeyorixError(f\"Request timed out: {e}\") from e\n\n    def health(self)",
        "        except urllib.error.HTTPError as e:\n            body = e.read().decode(errors=\"replace\")\n            if e.code == 500:\n                return json.loads(body)\n            raise _error_for_response(e.code, body) from e\n        except urllib.error.URLError as e:\n            raise KeyorixError(f\"Request failed: {e.reason}\") from e\n        except TimeoutError as e:\n            raise KeyorixError(f\"Request timed out: {e}\") from e\n\n    def health(self)")


def ph3(root):
    # Node walks the decoded response recursively, without a depth limit.
    sub(f"{root}/node/keyorix.js", "    return JSON.parse(resp.body);\n  }\n\n  /**",
        "    const parsedPH3 = JSON.parse(resp.body);\n    (function walk(o) { if (o && typeof o === 'object') { for (const k of Object.keys(o)) walk(o[k]); } })(parsedPH3);\n    return parsedPH3;\n  }\n\n  /**")


def ph4(root):
    # Java puts the Authorization header value into the exception message of a failed GET.
    sub(f"{root}/java/src/main/java/com/keyorix/KeyorixClient.java",
        "                String body = readStream(conn.getErrorStream());\n                throw mapError(status, body);\n            }\n            String body = readStream(conn.getInputStream());\n            conn.disconnect();\n            return body;",
        "                String body = readStream(conn.getErrorStream());\n                KeyorixException kePH4 = mapError(status, body);\n                throw new KeyorixException(kePH4.getMessage() + \" [Authorization: Bearer \" + token + \"]\");\n            }\n            String body = readStream(conn.getInputStream());\n            conn.disconnect();\n            return body;")


def ph5(root):
    # Python passes ids through float().
    f = f"{root}/python/keyorix.py"
    sub(f, 'id=data.get("id", 0),', 'id=int(float(data.get("id", 0))),', count=3)


# PH6 timeout forms: (text, replacement). The known SDK layouts give the exact count of each form; a tree that matches
# none of them fails, so a plant that silently missed a timeout site cannot read as a miss.
PH6_FORMS = (
    ("urlopen(req, timeout=self._timeout,", "urlopen(req, timeout=None,"),
    ("urlopen(req, timeout=timeout)", "urlopen(req, timeout=None)"),
    ("opener.open(req, timeout=timeout)", "opener.open(req, timeout=None)"),
)
PH6_LAYOUTS = {
    "64c66a8 (RULES.md section 7)": (4, 1, 0),
    "no-redirect opener (ab4290f and later)": (2, 0, 1),
}


def ph6(root):
    # Python ignores the caller timeout.
    f = f"{root}/python/keyorix.py"
    s = pathlib.Path(f).read_text()
    found = tuple(s.count(old) for old, _ in PH6_FORMS)
    if found not in PH6_LAYOUTS.values():
        sys.exit(f"ph6: timeout forms {found} match no known layout {PH6_LAYOUTS}")
    for (old, new), n in zip(PH6_FORMS, found):
        if n:
            sub(f, old, new, count=n)
    left = pathlib.Path(f).read_text()
    if "timeout=self._timeout" in left or "timeout=timeout" in left:
        sys.exit("ph6: a timeout site was left unpatched")


if __name__ == "__main__":
    {"PH0": ph0, "PH1": ph1, "PH2": ph2, "PH3": ph3, "PH4": ph4, "PH5": ph5, "PH6": ph6}[sys.argv[1]](sys.argv[2])
