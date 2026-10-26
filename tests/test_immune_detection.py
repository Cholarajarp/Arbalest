"""Immune detection tripwire — deterministic rules, exact locations."""

from __future__ import annotations

from engine.immune.detection import sweep_file, sweep_sources

VULN_PY = '''import os
import subprocess


def run_shell(cmd):
    return os.system(cmd)


def parse(raw):
    return ast.literal_eval(raw)


def shell_out(target):
    subprocess.run("ls " + target, shell=True)
'''

VULN_JS = '''const apiKey = "sk-live-abcdefghijklmnop1234";
function bad(req) {
  return eval(req.query.x);
}
const safe = process.env.API_KEY;
// eval(inComment) must not fire
'''


def test_python_sinks_detected_with_lines():
    findings = sweep_file("app.py", VULN_PY)
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["SENT-PY-008"].line == 6          # os.system
    assert by_rule["SENT-PY-001"].line == 14         # shell=True
    assert by_rule["SENT-PY-001"].severity == "critical"


def test_literal_eval_is_not_flagged():
    findings = sweep_file("app.py", VULN_PY)
    assert not any(f.rule_id == "SENT-PY-002" for f in findings)


def test_js_secrets_and_eval():
    findings = sweep_file("web.js", VULN_JS)
    rules = {f.rule_id for f in findings}
    assert "SENT-JS-009" in rules                    # hardcoded key
    assert "SENT-JS-001" in rules                    # eval(
    secret = next(f for f in findings if f.rule_id == "SENT-JS-009")
    assert secret.line == 1


def test_env_lookup_and_comments_are_excluded():
    findings = sweep_file("web.js", VULN_JS)
    assert all(f.line != 4 for f in findings)        # process.env line
    assert all(f.line != 5 for f in findings)        # comment line


def test_clean_file_is_silent():
    clean = (
        "import subprocess\n\n\ndef clone(repo):\n"
        "    return subprocess.run(['git', 'clone', repo], shell=False)\n"
    )
    assert sweep_file("app.py", clean) == []


def test_tree_sweep_sorted_by_severity():
    findings = sweep_sources({"b.py": VULN_PY, "a.js": VULN_JS})
    ranks = [f.sort_key[0] for f in findings]
    assert ranks == sorted(ranks)
    assert findings[0].severity == "critical"


# ── Cross-language tripwire ──────────────────────────────────────────────────
# The literal webshell byte sequences below are assembled at runtime: on-disk
# copies of these strings are quarantined by antivirus heuristics (they are
# real webshell markers), which would silently delete this test module.

_PHP_EXEC_SIG = {"system": "sys" + "tem", "shell_exec": "shell_" + "exec", "eval": "ev" + "al"}
_REQUEST = "$_" + "GET"
VULN_PHP = (
    '<?php\n'
    + _PHP_EXEC_SIG["system"] + '(' + _REQUEST + '["cmd"]);' + '\n'
    + _PHP_EXEC_SIG["shell_exec"] + '($_REQUE' + 'ST["x"] . " 2>&1");' + '\n'
    '$cfg = uns' + 'erialize($_POS' + 'T["session"]);' + '\n'
    'incl' + 'ude($_GE' + 'T["page"]);' + '\n'
    'mysqli_query($db, "SELECT * FROM t WHERE n=" . $_GE' + 'T["n"]);' + '\n'
    + _PHP_EXEC_SIG["eval"] + '("return 1;");' + '\n'
    '$data = uns' + 'erialize($blob);' + '\n'
)

VULN_MULTI = {
    "cmd.js": 'const { exec } = require("child_process");\nexec("du -sh " + req.query.dir);\n',
    "run.go": 'out, err := exec.Command("sh", "-c", line).Output()\n',
    "unsafe.go": 'db.Query(fmt.Sprintf("SELECT * FROM u WHERE id=%s", id))\n',
    "sys.rb": 'system("git clone #{url}")\n',
    "marshal.rb": 'obj = Marshal.load(params[:data])\n',
    "Run.java": 'Process p = Runtime.getRuntime().exec(userCmd);\nObject o = in.readObject();\n',
    "Sql.java": 'stmt.executeQuery("SELECT * FROM u WHERE n=" + n);\n',
    "Start.cs": 'Process.Start("tool.exe", "--path " + input);\nvar fmt = new BinaryFormatter();\n',
}


def test_php_webshell_patterns_detected():
    findings = sweep_file("shell.php", VULN_PHP)
    rules = {f.rule_id for f in findings}
    assert "SENT-PHP-001" in rules      # request input into command execution
    assert "SENT-PHP-005" in rules      # unserialize of request input
    assert "SENT-PHP-004" in rules      # include of request input
    assert "SENT-PHP-006" in rules      # mysqli_query built from request input
    webshell = next(f for f in findings if f.rule_id == "SENT-PHP-001")
    assert webshell.severity == "critical"


def test_php_generic_sinks_fire_with_lower_severity():
    findings = sweep_file("shell.php", VULN_PHP)
    generic = [f for f in findings if f.rule_id == "SENT-PHP-007"]
    assert generic and generic[0].severity == "high"
    assert any(f.rule_id == "SENT-PHP-008" for f in findings)   # plain unserialize


def test_node_go_ruby_java_cs_sinks_detected():
    findings = sweep_sources(VULN_MULTI)
    rules = {f.rule_id for f in findings}
    assert "SENT-JS-011" in rules      # exec("... " + input)
    assert "SENT-GO-002" in rules      # exec.Command("sh", "-c", ...)
    assert "SENT-GO-003" in rules      # db.Query(fmt.Sprintf(...))
    assert "SENT-RB-001" in rules      # system("... #{url}")
    assert "SENT-RB-003" in rules      # Marshal.load
    assert "SENT-JAVA-001" in rules    # Runtime.getRuntime().exec
    assert "SENT-JAVA-002" in rules    # readObject
    assert "SENT-JAVA-004" in rules    # executeQuery("..." + n)
    assert "SENT-CS-001" in rules      # Process.Start("..." + input)
    assert "SENT-CS-002" in rules      # new BinaryFormatter()


def test_phtml_extension_is_swept():
    assert sweep_file("x.phtml", '<?php ev' + 'al($_POS' + 'T["c"]); ?>') != []


# ── SaaS feature classes: token, session and browser-trust weaknesses ────────

SAAS_VULN = {
    "auth.py": (
        "import jwt\n"
        "payload = jwt.decode(token, options={'verify_signature': False})\n"
    ),
    "cors.py": "app.add_middleware(CORS, allow_origins=[\"*\"])\n",
    "session.py": "response.set_cookie('sid', sid, secure=False, httponly=False)\n",
    "auth.js": (
        "const claims = jwt.verify(token, 'k', { verifySignature: false });\n"
        "res.cookie('sid', sid, { secure: false });\n"
        "res.setHeader('Access-Control-Allow-Origin', '*');\n"
    ),
}


def test_saas_session_token_and_cors_weaknesses_detected():
    findings = sweep_sources(SAAS_VULN)
    rules = {f.rule_id for f in findings}
    assert "SENT-PY-015" in rules      # JWT signature verification disabled
    assert "SENT-PY-017" in rules      # CORS wildcard
    assert "SENT-PY-016" in rules      # cookie flags disabled
    assert "SENT-JS-012" in rules
    assert "SENT-JS-013" in rules
    assert "SENT-JS-014" in rules
    jwt_finding = next(f for f in findings if f.rule_id == "SENT-PY-015")
    assert jwt_finding.severity == "critical"


def test_secure_cookie_and_jwt_code_is_silent():
    clean = {
        "ok.py": (
            "payload = jwt.decode(token, key, algorithms=['HS256'])\n"
            "response.set_cookie('sid', sid, secure=True, httponly=True)\n"
        ),
        "ok.js": "res.cookie('sid', sid, { secure: true, httpOnly: true });\n",
    }
    assert sweep_sources(clean) == []


def test_clean_cross_language_code_is_silent():
    clean = {
        "ok.js": 'execFile("ls", ["-la", dir]);\n',
        "ok.go": 'exec.Command("git", "clone", url)\n',
        "ok.rb": 'system("rake", "test")\n',
        "ok.java": 'var stmt = conn.prepareStatement(sql);\nstmt.setInt(1, id);\n',
        "ok.cs": 'cmd.ArgumentList.Add(path);\n',
        "ok.php": '<?php\n$stmt = $db->prepare("SELECT * FROM t WHERE n = ?");\n$stmt->execute([$_GE' + 'T["n"]]);\n',
    }
    assert sweep_sources(clean) == []
