<?php
// Quick tool I put together to see everything I can about whoever's hitting the page.
// Pulls IP info, geo, ISP, browser details, and a bunch of JS-side stuff like
// screen size, battery, fonts, etc. Handy for debugging and just general curiosity.

// just a shorthand so I don't type htmlspecialchars a hundred times
function h(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
}

function getClientIp(): string {
    // check all the usual suspects in order - Cloudflare first since it
    // replaces REMOTE_ADDR, then proxies, then fall back to the real thing
    $headers = [
        'HTTP_CF_CONNECTING_IP',
        'HTTP_X_REAL_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_FORWARDED',
        'HTTP_FORWARDED_FOR',
        'HTTP_FORWARDED',
        'HTTP_CLIENT_IP',
        'REMOTE_ADDR',
    ];
    foreach ($headers as $key) {
        if (!empty($_SERVER[$key])) {
            $ip = trim(explode(',', $_SERVER[$key])[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }
    return 'Unknown';
}

function parseUserAgent(string $ua): array {
    $browser  = 'Unknown';
    $bVersion = 'Unknown';
    $os       = 'Unknown';
    $device   = 'Desktop';

    // iPads report themselves as Mobile too so check for that first
    if (preg_match('/Mobile|Android|iPhone|iPad|iPod/i', $ua)) {
        $device = preg_match('/iPad/i', $ua) ? 'Tablet' : 'Mobile';
    }

    // Windows versioning via NT numbers is kind of a mess but this covers
    // everything people are realistically still running
    $osList = [
        'Windows 11'     => 'Windows NT 10.0.*Win64',
        'Windows 10'     => 'Windows NT 10.0',
        'Windows 8.1'    => 'Windows NT 6.3',
        'Windows 8'      => 'Windows NT 6.2',
        'Windows 7'      => 'Windows NT 6.1',
        'Windows Vista'  => 'Windows NT 6.0',
        'Windows XP'     => 'Windows NT 5.1',
        'macOS'          => 'Mac OS X',
        'iOS'            => 'iPhone OS|CPU OS',
        'Android'        => 'Android',
        'Linux'          => 'Linux',
        'ChromeOS'       => 'CrOS',
        'FreeBSD'        => 'FreeBSD',
    ];
    foreach ($osList as $name => $pattern) {
        if (preg_match('/' . $pattern . '/i', $ua)) {
            $os = $name;
            // pull version where we can - Apple uses underscores instead of dots, annoying
            if ($name === 'Android' && preg_match('/Android ([0-9.]+)/i', $ua, $m)) {
                $os .= ' ' . $m[1];
            } elseif ($name === 'macOS' && preg_match('/Mac OS X ([0-9_]+)/i', $ua, $m)) {
                $os .= ' ' . str_replace('_', '.', $m[1]);
            } elseif ($name === 'iOS' && preg_match('/OS ([0-9_]+)/i', $ua, $m)) {
                $os .= ' ' . str_replace('_', '.', $m[1]);
            }
            break;
        }
    }

    // order really matters here - Edge and Opera both have "Chrome" in their UA
    // so they have to be checked before Chrome or you'll misidentify them
    $browsers = [
        'Edg'     => ['Edge',           '/Edg\/([0-9.]+)/'],
        'OPR'     => ['Opera',          '/OPR\/([0-9.]+)/'],
        'Opera'   => ['Opera',          '/Opera\/([0-9.]+)/'],
        'SamsungBrowser' => ['Samsung Browser', '/SamsungBrowser\/([0-9.]+)/'],
        'Firefox' => ['Firefox',        '/Firefox\/([0-9.]+)/'],
        'Chrome'  => ['Chrome',         '/Chrome\/([0-9.]+)/'],
        'Safari'  => ['Safari',         '/Version\/([0-9.]+)/'],
        'MSIE'    => ['Internet Explorer', '/MSIE ([0-9.]+)/'],
        'Trident' => ['Internet Explorer 11', '/rv:([0-9.]+)/'],
        'curl'    => ['cURL',           '/curl\/([0-9.]+)/'],
        'Wget'    => ['Wget',           '/Wget\/([0-9.]+)/'],
    ];
    foreach ($browsers as $key => [$name, $verPattern]) {
        if (str_contains($ua, $key)) {
            $browser  = $name;
            $bVersion = preg_match($verPattern, $ua, $m) ? $m[1] : 'Unknown';
            break;
        }
    }

    // very rough bot check - catches the obvious ones at least
    $isBot = preg_match('/bot|crawl|spider|slurp|mediapartners|bingpreview|facebookexternalhit|ia_archiver|yahoo! slurp/i', $ua);

    return compact('browser', 'bVersion', 'os', 'device', 'isBot');
}

function ipGeoLookup(string $ip): array {
    // using ip-api.com - free, no API key needed, just don't hammer it (45 req/min limit)
    $url  = "http://ip-api.com/json/{$ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query";
    $ctx  = stream_context_create(['http' => ['timeout' => 4, 'ignore_errors' => true]]);
    $json = @file_get_contents($url, false, $ctx);
    if ($json) {
        $data = json_decode($json, true);
        if (($data['status'] ?? '') === 'success') {
            return $data;
        }
    }
    return [];
}

function allHttpHeaders(): array {
    $headers = [];
    foreach ($_SERVER as $key => $val) {
        if (str_starts_with($key, 'HTTP_')) {
            $name = ucwords(strtolower(str_replace('_', '-', substr($key, 5))), '-');
            $headers[$name] = $val;
        }
    }
    ksort($headers);
    return $headers;
}

function acceptLanguages(): array {
    $raw = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
    if (!$raw) return [];
    $langs = [];
    foreach (explode(',', $raw) as $part) {
        [$lang, $q] = array_pad(explode(';q=', trim($part)), 2, '1');
        $langs[trim($lang)] = (float)$q;
    }
    arsort($langs);
    return $langs;
}

// --- kick everything off ---

$ip       = getClientIp();
$uaString = $_SERVER['HTTP_USER_AGENT'] ?? '';
$ua       = parseUserAgent($uaString);
$geo      = ipGeoLookup($ip);
$headers  = allHttpHeaders();
$langs    = acceptLanguages();
$protocol = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'HTTPS' : 'HTTP';
$port     = $_SERVER['SERVER_PORT'] ?? '80';
$method   = $_SERVER['REQUEST_METHOD'] ?? '';
$host     = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? '';

?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>System & IP Inspector</title>
<style>
  :root {
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --accent: #58a6ff;
    --accent2: #3fb950;
    --accent3: #f78166;
    --accent4: #e3b341;
    --text: #c9d1d9;
    --muted: #8b949e;
    --tag-bg: #21262d;
    --radius: 8px;
    --font: 'Segoe UI', system-ui, sans-serif;
    --mono: 'Cascadia Code', 'Consolas', monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--font);
    font-size: 14px;
    line-height: 1.6;
    padding: 24px 16px 64px;
  }
  h1 {
    font-size: 1.6rem;
    font-weight: 700;
    color: #fff;
    margin-bottom: 4px;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .subtitle { color: var(--muted); margin-bottom: 32px; font-size: 13px; }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
    gap: 16px;
    max-width: 1280px;
    margin: 0 auto;
  }
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
  }
  .card-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    font-weight: 600;
    font-size: 13px;
    letter-spacing: .03em;
    text-transform: uppercase;
    color: var(--muted);
  }
  .card-header .dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
  }
  .dot-blue   { background: var(--accent); }
  .dot-green  { background: var(--accent2); }
  .dot-red    { background: var(--accent3); }
  .dot-yellow { background: var(--accent4); }
  .dot-purple { background: #bc8cff; }
  .dot-cyan   { background: #39d0d8; }
  .row {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    padding: 9px 16px;
    border-bottom: 1px solid var(--border);
    gap: 12px;
  }
  .row:last-child { border-bottom: none; }
  .row-label {
    color: var(--muted);
    white-space: nowrap;
    flex-shrink: 0;
    font-size: 13px;
    padding-top: 1px;
  }
  .row-value {
    text-align: right;
    word-break: break-all;
    font-family: var(--mono);
    font-size: 13px;
    color: #fff;
  }
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 600;
    font-family: var(--font);
  }
  .badge-green  { background: rgba(63,185,80,.2);  color: var(--accent2); }
  .badge-red    { background: rgba(247,129,102,.2); color: var(--accent3); }
  .badge-yellow { background: rgba(227,179,65,.2);  color: var(--accent4); }
  .badge-blue   { background: rgba(88,166,255,.2);  color: var(--accent); }
  .badge-purple { background: rgba(188,140,255,.2); color: #bc8cff; }
  .ip-display {
    font-size: 2.2rem;
    font-weight: 700;
    font-family: var(--mono);
    color: var(--accent);
    padding: 20px 16px 8px;
    letter-spacing: .05em;
    word-break: break-all;
  }
  .map-link {
    color: var(--accent);
    text-decoration: none;
    font-size: 12px;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 0 16px 16px;
    transition: opacity .15s;
  }
  .map-link:hover { opacity: .7; }
  .flag { font-size: 1.2rem; }
  .headers-scroll {
    max-height: 320px;
    overflow-y: auto;
  }
  .headers-scroll::-webkit-scrollbar { width: 4px; }
  .headers-scroll::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
  .wide { grid-column: 1 / -1; }
  .tag {
    display: inline-block;
    background: var(--tag-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 2px 6px;
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text);
    margin: 2px 2px 0 0;
  }
  #js-pending { color: var(--muted); font-style: italic; font-family: var(--font); }
  @media (max-width: 600px) {
    .ip-display { font-size: 1.4rem; }
    .grid { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>

<div style="max-width:1280px;margin:0 auto 24px;">
  <h1>&#128270; System &amp; IP Inspector</h1>
  <p class="subtitle">Full client fingerprint — network, browser, hardware, and more</p>
</div>

<div class="grid">

  <!-- ── IP Address ── -->
  <div class="card">
    <div class="card-header"><span class="dot dot-blue"></span> IP Address</div>
    <div class="ip-display"><?= h($ip) ?></div>
    <?php if (!empty($geo['lat']) && !empty($geo['lon'])): ?>
    <a class="map-link" href="https://www.openstreetmap.org/?mlat=<?= h($geo['lat']) ?>&mlon=<?= h($geo['lon']) ?>#map=12/<?= h($geo['lat']) ?>/<?= h($geo['lon']) ?>" target="_blank" rel="noopener">
      &#127760; View on map &rarr;
    </a>
    <?php endif; ?>
    <?php
    $ipRows = [
        'Protocol Version' => filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 'IPv6' : 'IPv4',
        'Request Method'   => $method,
        'Connection'       => $protocol . ' / Port ' . $port,
    ];
    foreach ($ipRows as $label => $val): ?>
    <div class="row">
      <span class="row-label"><?= h($label) ?></span>
      <span class="row-value"><?= h((string)$val) ?></span>
    </div>
    <?php endforeach; ?>
  </div>

  <!-- ── Geolocation ── -->
  <div class="card">
    <div class="card-header"><span class="dot dot-green"></span> Geolocation</div>
    <?php if (!empty($geo)): ?>
    <?php
    $geoRows = [
        'Country'      => ($geo['country'] ?? '') . ($geo['countryCode'] ? ' (' . $geo['countryCode'] . ')' : ''),
        'Region'       => ($geo['regionName'] ?? '') . ($geo['region'] ? ' (' . $geo['region'] . ')' : ''),
        'City'         => $geo['city'] ?? 'Unknown',
        'ZIP / Post'   => $geo['zip'] ?? 'Unknown',
        'Latitude'     => $geo['lat'] ?? 'Unknown',
        'Longitude'    => $geo['lon'] ?? 'Unknown',
        'Timezone'     => $geo['timezone'] ?? 'Unknown',
    ];
    foreach ($geoRows as $label => $val): ?>
    <div class="row">
      <span class="row-label"><?= h($label) ?></span>
      <span class="row-value"><?= h((string)$val) ?></span>
    </div>
    <?php endforeach; ?>
    <?php else: ?>
    <div class="row"><span class="row-label">Status</span><span class="row-value badge badge-yellow">Lookup failed or local IP</span></div>
    <?php endif; ?>
  </div>

  <!-- ── ISP / Network ── -->
  <div class="card">
    <div class="card-header"><span class="dot dot-yellow"></span> ISP &amp; Network</div>
    <?php
    $netRows = [
        'ISP'         => $geo['isp']    ?? 'Unknown',
        'Organization'=> $geo['org']    ?? 'Unknown',
        'AS Number'   => $geo['as']     ?? 'Unknown',
        'AS Name'     => $geo['asname'] ?? 'Unknown',
        'Mobile'      => isset($geo['mobile']) ? ($geo['mobile'] ? 'Yes' : 'No') : 'Unknown',
        'Proxy / VPN' => isset($geo['proxy'])  ? ($geo['proxy']  ? 'Yes' : 'No') : 'Unknown',
        'Hosting'     => isset($geo['hosting'])? ($geo['hosting']? 'Yes' : 'No') : 'Unknown',
    ];
    foreach ($netRows as $label => $val):
        $badge = '';
        if ($label === 'Proxy / VPN' && $val === 'Yes') $badge = 'badge-red';
        if ($label === 'Hosting'     && $val === 'Yes') $badge = 'badge-yellow';
        if ($label === 'Mobile'      && $val === 'Yes') $badge = 'badge-blue';
    ?>
    <div class="row">
      <span class="row-label"><?= h($label) ?></span>
      <span class="row-value <?= $badge ? 'badge ' . $badge : '' ?>"><?= h((string)$val) ?></span>
    </div>
    <?php endforeach; ?>
  </div>

  <!-- ── Browser ── -->
  <div class="card">
    <div class="card-header"><span class="dot dot-purple"></span> Browser</div>
    <?php
    $browserRows = [
        'Browser'    => $ua['browser'],
        'Version'    => $ua['bVersion'],
        'Engine'     => preg_match('/Gecko\//', $uaString) ? 'Gecko' : (preg_match('/AppleWebKit\//', $uaString) ? 'WebKit / Blink' : (preg_match('/Trident\//', $uaString) ? 'Trident' : 'Unknown')),
        'Device Type'=> $ua['device'],
        'Bot / Crawler' => $ua['isBot'] ? 'Yes' : 'No',
        'Do-Not-Track'  => ($_SERVER['HTTP_DNT'] ?? '0') === '1' ? 'Enabled' : 'Not set',
        'Sec-Fetch-Mode'=> $_SERVER['HTTP_SEC_FETCH_MODE'] ?? 'n/a',
        'Sec-CH-UA'     => substr($_SERVER['HTTP_SEC_CH_UA'] ?? 'n/a', 0, 60),
    ];
    foreach ($browserRows as $label => $val): ?>
    <div class="row">
      <span class="row-label"><?= h($label) ?></span>
      <span class="row-value"><?= h((string)$val) ?></span>
    </div>
    <?php endforeach; ?>
  </div>

  <!-- ── Operating System ── -->
  <div class="card">
    <div class="card-header"><span class="dot dot-cyan"></span> Operating System</div>
    <?php
    $osRows = [
        'OS'             => $ua['os'],
        'Architecture'   => preg_match('/x86_64|Win64|WOW64|amd64/i', $uaString) ? 'x86-64 (64-bit)' : (preg_match('/arm64|aarch64/i', $uaString) ? 'ARM64' : (preg_match('/arm/i', $uaString) ? 'ARM' : 'x86 / Unknown')),
        'CPU Threads'    => '<span id="hw-threads"><span id="js-pending">awaiting JS...</span></span>',
        'Device Memory'  => '<span id="hw-memory"><span id="js-pending">awaiting JS...</span></span>',
        'Platform (JS)'  => '<span id="hw-platform"><span id="js-pending">awaiting JS...</span></span>',
    ];
    foreach ($osRows as $label => $val): ?>
    <div class="row">
      <span class="row-label"><?= h($label) ?></span>
      <span class="row-value"><?= $val // already safe ?></span>
    </div>
    <?php endforeach; ?>
  </div>

  <!-- ── Screen & Display ── -->
  <div class="card">
    <div class="card-header"><span class="dot dot-blue"></span> Screen &amp; Display</div>
    <?php
    $screenRows = [
        'Screen Resolution' => 'id="scr-resolution"',
        'Available Space'   => 'id="scr-avail"',
        'Window Size'       => 'id="scr-window"',
        'Color Depth'       => 'id="scr-color"',
        'Pixel Ratio'       => 'id="scr-dpr"',
        'Orientation'       => 'id="scr-orient"',
        'Touch Points'      => 'id="scr-touch"',
    ];
    foreach ($screenRows as $label => $id): ?>
    <div class="row">
      <span class="row-label"><?= h($label) ?></span>
      <span class="row-value"><span <?= $id ?>><span class="js-pending" style="color:var(--muted);font-style:italic">awaiting JS...</span></span></span>
    </div>
    <?php endforeach; ?>
  </div>

  <!-- ── Time & Locale ── -->
  <div class="card">
    <div class="card-header"><span class="dot dot-green"></span> Time &amp; Locale</div>
    <?php
    $timeRows = [
        'Server Time (UTC)'   => gmdate('Y-m-d H:i:s') . ' UTC',
        'Client Timezone (JS)'=> '<span id="tz-name"><span class="js-pending" style="color:var(--muted);font-style:italic">awaiting JS...</span></span>',
        'UTC Offset'          => '<span id="tz-offset"><span class="js-pending" style="color:var(--muted);font-style:italic">awaiting JS...</span></span>',
        'Client Date/Time'    => '<span id="tz-local"><span class="js-pending" style="color:var(--muted);font-style:italic">awaiting JS...</span></span>',
        'Locale'              => '<span id="tz-locale"><span class="js-pending" style="color:var(--muted);font-style:italic">awaiting JS...</span></span>',
        'Number Format'       => '<span id="tz-numfmt"><span class="js-pending" style="color:var(--muted);font-style:italic">awaiting JS...</span></span>',
    ];
    foreach ($timeRows as $label => $val): ?>
    <div class="row">
      <span class="row-label"><?= h($label) ?></span>
      <span class="row-value"><?= $val ?></span>
    </div>
    <?php endforeach; ?>
    <div class="row">
      <span class="row-label">Accept-Language</span>
      <span class="row-value" style="text-align:right">
        <?php foreach (array_slice($langs, 0, 4) as $lang => $q): ?>
          <span class="tag"><?= h($lang) ?><?= $q < 1 ? ' q=' . $q : '' ?></span>
        <?php endforeach; ?>
      </span>
    </div>
  </div>

  <!-- ── Network (JS) ── -->
  <div class="card">
    <div class="card-header"><span class="dot dot-yellow"></span> Connection Speed (JS)</div>
    <?php
    $connRows = [
        'Effective Type'    => 'id="net-type"',
        'Downlink (Mbps)'   => 'id="net-down"',
        'RTT (ms)'          => 'id="net-rtt"',
        'Save-Data Mode'    => 'id="net-save"',
        'Online Status'     => 'id="net-online"',
    ];
    foreach ($connRows as $label => $id): ?>
    <div class="row">
      <span class="row-label"><?= h($label) ?></span>
      <span class="row-value"><span <?= $id ?>><span class="js-pending" style="color:var(--muted);font-style:italic">awaiting JS...</span></span></span>
    </div>
    <?php endforeach; ?>
  </div>

  <!-- ── Browser Capabilities ── -->
  <div class="card">
    <div class="card-header"><span class="dot dot-purple"></span> Browser Capabilities</div>
    <?php
    $capRows = [
        'Cookies Enabled'     => 'id="cap-cookies"',
        'Local Storage'       => 'id="cap-ls"',
        'Session Storage'     => 'id="cap-ss"',
        'IndexedDB'           => 'id="cap-idb"',
        'Service Workers'     => 'id="cap-sw"',
        'WebAssembly'         => 'id="cap-wasm"',
        'WebGL'               => 'id="cap-webgl"',
        'WebGL Renderer'      => 'id="cap-webgl-renderer"',
        'Canvas Fingerprint'  => 'id="cap-canvas"',
        'WebRTC'              => 'id="cap-webrtc"',
        'Notifications'       => 'id="cap-notif"',
        'Geolocation API'     => 'id="cap-geo"',
        'Battery API'         => 'id="cap-batt"',
        'Clipboard API'       => 'id="cap-clip"',
        'Bluetooth API'       => 'id="cap-bt"',
        'USB API'             => 'id="cap-usb"',
        'Web Share'           => 'id="cap-share"',
        'Speech Synthesis'    => 'id="cap-speech"',
        'Media Devices'       => 'id="cap-media"',
        'AdBlocker (heuristic)'=> 'id="cap-adblock"',
    ];
    foreach ($capRows as $label => $id): ?>
    <div class="row">
      <span class="row-label"><?= h($label) ?></span>
      <span class="row-value"><span <?= $id ?>><span class="js-pending" style="color:var(--muted);font-style:italic">...</span></span></span>
    </div>
    <?php endforeach; ?>
  </div>

  <!-- ── Battery ── -->
  <div class="card">
    <div class="card-header"><span class="dot dot-green"></span> Battery</div>
    <?php
    $battRows = [
        'Level'      => 'id="batt-level"',
        'Charging'   => 'id="batt-charging"',
        'Charge Time'=> 'id="batt-chtime"',
        'Drain Time' => 'id="batt-dtime"',
    ];
    foreach ($battRows as $label => $id): ?>
    <div class="row">
      <span class="row-label"><?= h($label) ?></span>
      <span class="row-value"><span <?= $id ?>><span class="js-pending" style="color:var(--muted);font-style:italic">...</span></span></span>
    </div>
    <?php endforeach; ?>
  </div>

  <!-- ── User-Agent String ── -->
  <div class="card wide">
    <div class="card-header"><span class="dot dot-red"></span> Raw User-Agent String</div>
    <div class="row">
      <span class="row-value" style="text-align:left;word-break:break-all;color:var(--accent4);font-size:12px"><?= h($uaString ?: 'Not provided') ?></span>
    </div>
  </div>

  <!-- ── All HTTP Headers ── -->
  <div class="card wide">
    <div class="card-header"><span class="dot dot-cyan"></span> HTTP Request Headers (<?= count($headers) ?>)</div>
    <div class="headers-scroll">
      <?php foreach ($headers as $name => $val): ?>
      <div class="row">
        <span class="row-label" style="min-width:200px"><?= h($name) ?></span>
        <span class="row-value" style="font-size:12px;color:var(--text)"><?= h($val) ?></span>
      </div>
      <?php endforeach; ?>
    </div>
  </div>

  <!-- ── Server Variables ── -->
  <div class="card wide">
    <div class="card-header"><span class="dot dot-yellow"></span> Server Environment</div>
    <?php
    $serverKeys = [
        'SERVER_SOFTWARE', 'SERVER_NAME', 'SERVER_ADDR', 'SERVER_PORT',
        'DOCUMENT_ROOT', 'SCRIPT_NAME', 'REQUEST_URI', 'QUERY_STRING',
        'SERVER_PROTOCOL', 'PHP_SELF', 'GATEWAY_INTERFACE',
    ];
    foreach ($serverKeys as $k): ?>
    <div class="row">
      <span class="row-label" style="min-width:200px;font-family:var(--mono);font-size:12px"><?= h($k) ?></span>
      <span class="row-value" style="font-size:12px"><?= h((string)($_SERVER[$k] ?? '—')) ?></span>
    </div>
    <?php endforeach; ?>
    <div class="row">
      <span class="row-label" style="min-width:200px;font-family:var(--mono);font-size:12px">PHP_VERSION</span>
      <span class="row-value" style="font-size:12px"><?= h(PHP_VERSION) ?></span>
    </div>
    <div class="row">
      <span class="row-label" style="min-width:200px;font-family:var(--mono);font-size:12px">PHP_OS</span>
      <span class="row-value" style="font-size:12px"><?= h(PHP_OS) ?></span>
    </div>
    <div class="row">
      <span class="row-label" style="min-width:200px;font-family:var(--mono);font-size:12px">PHP_INT_SIZE</span>
      <span class="row-value" style="font-size:12px"><?= h((string)PHP_INT_SIZE) ?> bytes (<?= PHP_INT_SIZE === 8 ? '64-bit' : '32-bit' ?>)</span>
    </div>
  </div>

  <!-- ── Permissions (JS) ── -->
  <div class="card">
    <div class="card-header"><span class="dot dot-red"></span> Browser Permissions</div>
    <div id="permissions-list">
      <div class="row"><span class="row-label">Loading...</span></div>
    </div>
  </div>

  <!-- ── Installed Fonts (JS) ── -->
  <div class="card">
    <div class="card-header"><span class="dot dot-blue"></span> Font Probe</div>
    <div class="row">
      <span class="row-label">Detected system fonts</span>
      <span class="row-value"><span id="fonts-count">...</span></span>
    </div>
    <div style="padding:8px 16px 12px;font-size:11px;color:var(--muted)" id="fonts-list"></div>
  </div>

  <!-- ── Media Devices (JS) ── -->
  <div class="card">
    <div class="card-header"><span class="dot dot-green"></span> Media Devices</div>
    <div id="devices-list">
      <div class="row"><span class="row-label">Enumerating...</span></div>
    </div>
  </div>

</div>

<!-- the JS side fills in everything PHP can't see - screen, battery, fonts, etc. -->
<script>
(function () {
  "use strict";

  // little helper to avoid repeating getElementById + innerHTML everywhere
  function set(id, val) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = val ?? '<span style="color:var(--muted)">n/a</span>';
  }

  function yn(bool) {
    return bool
      ? '<span class="badge badge-green">Yes</span>'
      : '<span class="badge badge-red">No</span>';
  }

  function na() { return '<span style="color:var(--muted)">n/a</span>'; }

  // screen stuff is easy, all synchronous
  set('scr-resolution', screen.width + ' × ' + screen.height + ' px');
  set('scr-avail',      screen.availWidth + ' × ' + screen.availHeight + ' px');
  set('scr-window',     window.innerWidth + ' × ' + window.innerHeight + ' px');
  set('scr-color',      screen.colorDepth + '-bit');
  set('scr-dpr',        window.devicePixelRatio);
  set('scr-orient',     screen.orientation ? screen.orientation.type : (screen.width > screen.height ? 'landscape' : 'portrait'));
  set('scr-touch',      navigator.maxTouchPoints ?? 0);

  // hardware concurrency = logical CPU count, deviceMemory is rounded by design (privacy)
  set('hw-threads',  navigator.hardwareConcurrency ?? na());
  set('hw-memory',   navigator.deviceMemory ? navigator.deviceMemory + ' GB' : na());
  set('hw-platform', navigator.platform ?? na());

  // wrap timezone stuff in try/catch - Intl can throw on some older browsers
  try {
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    set('tz-name',   tz);
    set('tz-offset', 'UTC' + (new Date().getTimezoneOffset() > 0 ? '-' : '+') +
      String(Math.abs(new Date().getTimezoneOffset() / 60)).padStart(2, '0') + ':' +
      String(Math.abs(new Date().getTimezoneOffset() % 60)).padStart(2, '0'));
    set('tz-local',  new Date().toLocaleString());
    set('tz-locale', navigator.language + (navigator.languages ? ' [' + navigator.languages.join(', ') + ']' : ''));
    set('tz-numfmt', (12345.6).toLocaleString());
  } catch (e) {}

  // Network Information API - still not in Firefox/Safari so always check first
  const nc = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
  if (nc) {
    set('net-type',   nc.effectiveType ?? na());
    set('net-down',   nc.downlink ?? na());
    set('net-rtt',    nc.rtt ?? na());
    set('net-save',   yn(nc.saveData));
  } else {
    ['net-type','net-down','net-rtt','net-save'].forEach(id => set(id, na()));
  }
  set('net-online', yn(navigator.onLine));

  // check what the browser supports - some of these APIs are pretty new
  set('cap-cookies', yn(navigator.cookieEnabled));
  try { localStorage.setItem('_t','1'); localStorage.removeItem('_t'); set('cap-ls', yn(true)); } catch { set('cap-ls', yn(false)); }
  try { sessionStorage.setItem('_t','1'); sessionStorage.removeItem('_t'); set('cap-ss', yn(true)); } catch { set('cap-ss', yn(false)); }
  set('cap-idb',    yn('indexedDB' in window));
  set('cap-sw',     yn('serviceWorker' in navigator));
  set('cap-wasm',   yn(typeof WebAssembly === 'object'));
  set('cap-webrtc', yn(!!(window.RTCPeerConnection || window.webkitRTCPeerConnection)));
  set('cap-notif',  yn('Notification' in window));
  set('cap-geo',    yn('geolocation' in navigator));
  set('cap-batt',   yn('getBattery' in navigator));
  set('cap-clip',   yn('clipboard' in navigator));
  set('cap-bt',     yn('bluetooth' in navigator));
  set('cap-usb',    yn('usb' in navigator));
  set('cap-share',  yn('share' in navigator));
  set('cap-speech', yn('speechSynthesis' in window));
  set('cap-media',  yn(!!(navigator.mediaDevices && navigator.mediaDevices.enumerateDevices)));

  // WebGL renderer string can reveal the actual GPU model which is pretty cool,
  // though Firefox blocks it behind a flag now
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (gl) {
      set('cap-webgl', yn(true));
      const dbgInfo = gl.getExtension('WEBGL_debug_renderer_info');
      if (dbgInfo) {
        set('cap-webgl-renderer', gl.getParameter(dbgInfo.UNMASKED_RENDERER_WEBGL));
      } else {
        set('cap-webgl-renderer', 'Info blocked by browser');
      }
    } else {
      set('cap-webgl', yn(false));
      set('cap-webgl-renderer', na());
    }
  } catch { set('cap-webgl', yn(false)); }

  // draw some text on a hidden canvas and hash the pixel data - different
  // GPU/font rendering combos produce slightly different results, makes a decent fingerprint
  try {
    const c = document.createElement('canvas');
    c.width = 200; c.height = 50;
    const ctx = c.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('BrowserLeaks', 2, 15);
    ctx.fillStyle = 'rgba(102,204,0,0.7)';
    ctx.fillText('BrowserLeaks', 4, 17);
    const dataUrl = c.toDataURL();
    let h = 0;
    for (let i = 0; i < dataUrl.length; i++) {
      h = ((h << 5) - h) + dataUrl.charCodeAt(i);
      h |= 0;
    }
    set('cap-canvas', '0x' + Math.abs(h).toString(16).padStart(8, '0'));
  } catch { set('cap-canvas', na()); }

  // classic adblock detection trick - inject a div with a class that
  // ad blockers typically hide, then check if it got collapsed
  const adEl = document.createElement('div');
  adEl.className = 'adsbox';
  adEl.style.cssText = 'position:absolute;left:-9999px;top:-9999px;width:1px;height:1px';
  document.body.appendChild(adEl);
  setTimeout(() => {
    set('cap-adblock', yn(adEl.offsetHeight === 0));
    adEl.remove();
  }, 100);

  // Battery API returns a promise - most desktop browsers just return null/unsupported
  if (navigator.getBattery) {
    navigator.getBattery().then(b => {
      set('batt-level',    Math.round(b.level * 100) + '%');
      set('batt-charging', b.charging ? '<span class="badge badge-green">Charging</span>' : '<span class="badge badge-yellow">Discharging</span>');
      set('batt-chtime',   b.chargingTime   === Infinity ? 'N/A' : b.chargingTime + 's');
      set('batt-dtime',    b.dischargingTime === Infinity ? 'N/A' : b.dischargingTime + 's');
    }).catch(() => {
      ['batt-level','batt-charging','batt-chtime','batt-dtime'].forEach(id => set(id, na()));
    });
  } else {
    ['batt-level','batt-charging','batt-chtime','batt-dtime'].forEach(id => set(id, na()));
  }

  // permissions.query can reject for names the browser doesn't recognize, so catch per-permission
  const perms = [
    'camera','microphone','geolocation','notifications',
    'persistent-storage','clipboard-read','clipboard-write','midi',
    'payment-handler','background-sync',
  ];
  const permContainer = document.getElementById('permissions-list');
  if (navigator.permissions) {
    permContainer.innerHTML = '';
    let done = 0;
    perms.forEach(name => {
      navigator.permissions.query({ name }).then(res => {
        const row = document.createElement('div');
        row.className = 'row';
        const badge = res.state === 'granted' ? 'badge-green' : res.state === 'prompt' ? 'badge-yellow' : 'badge-red';
        row.innerHTML = `<span class="row-label">${name}</span><span class="row-value"><span class="badge ${badge}">${res.state}</span></span>`;
        permContainer.appendChild(row);
      }).catch(() => {
        const row = document.createElement('div');
        row.className = 'row';
        row.innerHTML = `<span class="row-label">${name}</span><span class="row-value" style="color:var(--muted)">n/a</span>`;
        permContainer.appendChild(row);
      });
    });
  } else {
    permContainer.innerHTML = '<div class="row"><span class="row-label">Permissions API not supported</span></div>';
  }

  // check which fonts are installed by asking the browser if it can render them
  // document.fonts.check is way cleaner than the old canvas text-width trick
  const probe = [
    'Arial','Arial Black','Arial Narrow','Calibri','Cambria','Comic Sans MS',
    'Consolas','Courier New','Georgia','Impact','Lucida Console','Lucida Sans Unicode',
    'Microsoft Sans Serif','Palatino Linotype','Segoe UI','Tahoma','Times New Roman',
    'Trebuchet MS','Verdana','Wingdings','Ubuntu','Roboto','Helvetica Neue','Helvetica',
    'Futura','Garamond','Gill Sans','Optima','Fira Code','JetBrains Mono','Source Code Pro',
  ];
  try {
    const found = [];
    probe.forEach(font => {
      if (document.fonts.check('12px "' + font + '"') ||
          document.fonts.check('16px ' + font)) {
        found.push(font);
      }
    });
    set('fonts-count', found.length + ' / ' + probe.length + ' probed');
    document.getElementById('fonts-list').innerHTML = found.map(f =>
      `<span class="tag" style="font-family:'${f}'">${f}</span>`
    ).join('');
  } catch {
    set('fonts-count', na());
  }

  // enumerateDevices works without permission but won't show device labels until granted
  const devContainer = document.getElementById('devices-list');
  if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
    navigator.mediaDevices.enumerateDevices().then(devices => {
      devContainer.innerHTML = '';
      if (!devices.length) {
        devContainer.innerHTML = '<div class="row"><span class="row-label">No devices found or permission denied</span></div>';
        return;
      }
      const counts = { audioinput: 0, audiooutput: 0, videoinput: 0 };
      devices.forEach(d => { if (d.kind in counts) counts[d.kind]++; });
      const labels = { audioinput: 'Microphones', audiooutput: 'Speakers/Headphones', videoinput: 'Cameras' };
      Object.entries(counts).forEach(([kind, n]) => {
        const row = document.createElement('div');
        row.className = 'row';
        row.innerHTML = `<span class="row-label">${labels[kind]}</span><span class="row-value">${n}</span>`;
        devContainer.appendChild(row);
      });
      devices.forEach((d, i) => {
        const row = document.createElement('div');
        row.className = 'row';
        const label = d.label || `Device ${i + 1} (unlabeled)`;
        row.innerHTML = `<span class="row-label" style="font-size:11px;color:var(--muted)">${d.kind}</span><span class="row-value" style="font-size:11px">${label}</span>`;
        devContainer.appendChild(row);
      });
    }).catch(() => {
      devContainer.innerHTML = '<div class="row"><span class="row-label">Permission denied</span></div>';
    });
  } else {
    devContainer.innerHTML = '<div class="row"><span class="row-label">API not supported</span></div>';
  }

})();
</script>
</body>
</html>
