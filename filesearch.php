<?php
/**
 * Server File Content Search
 * Recursively searches files for a text string with IP whitelisting,
 * file-type filtering, and timeout awareness.
 */

// ── Configuration ─────────────────────────────────────────────────────────────

// IPs allowed to use this script. Supports exact IPs and CIDR ranges.
const ALLOWED_IPS = [
    '127.0.0.1',
    '::1',
    // '203.0.113.10',
    // '10.0.0.0/8',
];

// Hard cap on execution time (seconds). Should be <= php.ini max_execution_time.
const MAX_EXECUTION_SECONDS = 55;

// Maximum individual file size to scan (bytes). Skips binary-heavy files.
const MAX_FILE_BYTES = 10 * 1024 * 1024; // 10 MB

// Maximum results before stopping early.
const MAX_RESULTS = 2000;

// ── IP Whitelist check ────────────────────────────────────────────────────────

function getClientIp(): string {
    foreach (['HTTP_CF_CONNECTING_IP','HTTP_X_REAL_IP','HTTP_X_FORWARDED_FOR','REMOTE_ADDR'] as $k) {
        if (!empty($_SERVER[$k])) {
            $ip = trim(explode(',', $_SERVER[$k])[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
        }
    }
    return '0.0.0.0';
}

function ipInCidr(string $ip, string $cidr): bool {
    if (!str_contains($cidr, '/')) return $ip === $cidr;
    [$subnet, $bits] = explode('/', $cidr);
    $bits = (int)$bits;
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) &&
        filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $mask = $bits === 0 ? 0 : (~0 << (32 - $bits));
        return (ip2long($ip) & $mask) === (ip2long($subnet) & $mask);
    }
    return false;
}

function isAllowedIp(string $ip): bool {
    foreach (ALLOWED_IPS as $allowed) {
        if (ipInCidr($ip, $allowed)) return true;
    }
    return false;
}

$clientIp = getClientIp();
if (!isAllowedIp($clientIp)) {
    http_response_code(403);
    die('403 Forbidden — your IP (' . htmlspecialchars($clientIp) . ') is not authorised.');
}

// ── File type definitions ──────────────────────────────────────────────────────

const FILE_TYPES = [
    'all'        => ['label' => 'All Files',           'exts' => []],
    'php'        => ['label' => 'PHP',                 'exts' => ['php','php3','php4','php5','phtml','inc']],
    'web'        => ['label' => 'Web (HTML/CSS/JS)',   'exts' => ['html','htm','xhtml','css','js','jsx','ts','tsx','vue','svelte']],
    'config'     => ['label' => 'Config / Env',        'exts' => ['xml','yaml','yml','json','ini','env','conf','cfg','toml','htaccess','htpasswd']],
    'text'       => ['label' => 'Plain Text / Docs',   'exts' => ['txt','md','log','rst','csv','tsv','nfo']],
    'template'   => ['label' => 'Templates',           'exts' => ['phtml','twig','blade','smarty','tpl','mustache','hbs']],
    'sql'        => ['label' => 'SQL',                 'exts' => ['sql','dump']],
    'shell'      => ['label' => 'Shell / Scripts',     'exts' => ['sh','bash','zsh','bat','cmd','ps1']],
    'python'     => ['label' => 'Python',              'exts' => ['py','pyw']],
    'ruby'       => ['label' => 'Ruby',                'exts' => ['rb','rake','gemspec']],
    'java'       => ['label' => 'Java / Kotlin',       'exts' => ['java','kt','kts','gradle']],
    'c'          => ['label' => 'C / C++',             'exts' => ['c','h','cpp','cxx','cc','hpp']],
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function h(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
}

function elapsed(float $start): float {
    return round(microtime(true) - $start, 2);
}

function isLikelyBinary(string $path): bool {
    $binaryExts = ['jpg','jpeg','png','gif','bmp','webp','svg','ico','pdf','zip','gz','tar',
                   'rar','7z','exe','dll','so','dylib','bin','dat','db','sqlite','woff','woff2',
                   'ttf','otf','eot','mp3','mp4','avi','mov','wmv','flv','ogg','wav','psd','ai'];
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    return in_array($ext, $binaryExts, true);
}

// ── Search logic ──────────────────────────────────────────────────────────────

/**
 * Recursively searches $rootPath for $needle in files matching $extensions.
 * Yields result arrays as it finds them.
 * Stops gracefully when approaching the time limit.
 */
function searchFiles(
    string $rootPath,
    string $needle,
    array  $extensions,
    bool   $caseSensitive,
    float  $startTime,
    array  &$stats
): Generator {
    $extsAll = empty($extensions);
    $extSet  = array_flip(array_map('strtolower', $extensions));

    $queue = [$rootPath];

    while (!empty($queue)) {
        // Timeout guard — leave a 3-second buffer for rendering
        if (elapsed($startTime) >= MAX_EXECUTION_SECONDS - 3) {
            $stats['timed_out'] = true;
            return;
        }

        $dir = array_shift($queue);

        $handle = @opendir($dir);
        if (!$handle) { $stats['unreadable_dirs']++; continue; }

        while (($entry = readdir($handle)) !== false) {
            if ($entry === '.' || $entry === '..') continue;

            $fullPath = rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $entry;

            if (is_link($fullPath)) { $stats['symlinks_skipped']++; continue; }

            if (is_dir($fullPath)) {
                $queue[] = $fullPath;
                $stats['dirs_scanned']++;
                continue;
            }

            if (!is_file($fullPath)) continue;

            $stats['files_scanned']++;

            // Extension filter
            if (!$extsAll) {
                $ext = strtolower(pathinfo($fullPath, PATHINFO_EXTENSION));
                if (!isset($extSet[$ext])) { $stats['files_skipped_type']++; continue; }
            }

            // Skip likely-binary files when scanning all types
            if ($extsAll && isLikelyBinary($fullPath)) {
                $stats['files_skipped_binary']++;
                continue;
            }

            // Size guard
            $size = @filesize($fullPath);
            if ($size === false || $size > MAX_FILE_BYTES) {
                $stats['files_skipped_size']++;
                continue;
            }

            $content = @file_get_contents($fullPath);
            if ($content === false) { $stats['files_unreadable']++; continue; }

            $searchFn  = $caseSensitive ? 'strpos' : 'stripos';
            if ($searchFn($content, $needle) === false) continue;

            // Count occurrences and collect matching line numbers
            $lines      = explode("\n", $content);
            $matchLines = [];
            foreach ($lines as $lineNo => $line) {
                if ($searchFn($line, $needle) !== false) {
                    $matchLines[] = [
                        'number'  => $lineNo + 1,
                        'content' => trim($line),
                    ];
                    if (count($matchLines) >= 5) break; // preview cap per file
                }
            }

            $stats['files_matched']++;
            yield [
                'path'       => $fullPath,
                'size'       => $size,
                'modified'   => @filemtime($fullPath),
                'matchLines' => $matchLines,
            ];

            if ($stats['files_matched'] >= MAX_RESULTS) {
                $stats['hit_result_cap'] = true;
                closedir($handle);
                return;
            }
        }
        closedir($handle);
    }
}

// ── Handle form submission ────────────────────────────────────────────────────

$results    = [];
$stats      = [];
$errors     = [];
$didSearch  = false;
$searchTime = 0;

$inputPath      = trim($_POST['path']      ?? '');
$inputNeedle    = $_POST['needle']         ?? '';
$inputType      = $_POST['filetype']       ?? 'all';
$inputCase      = isset($_POST['case_sensitive']);
$inputMatchPath = isset($_POST['match_path']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate
    if ($inputNeedle === '') {
        $errors[] = 'Search text cannot be empty.';
    }
    if ($inputPath === '') {
        $errors[] = 'Starting path cannot be empty.';
    } elseif (!is_dir($inputPath)) {
        $errors[] = 'Path does not exist or is not a directory: ' . h($inputPath);
    } elseif (!is_readable($inputPath)) {
        $errors[] = 'Path is not readable: ' . h($inputPath);
    }

    if (!array_key_exists($inputType, FILE_TYPES)) {
        $errors[] = 'Invalid file type selection.';
    }

    if (empty($errors)) {
        $exts      = FILE_TYPES[$inputType]['exts'];
        $startTime = microtime(true);
        $stats = [
            'dirs_scanned'        => 0,
            'files_scanned'       => 0,
            'files_matched'       => 0,
            'files_skipped_type'  => 0,
            'files_skipped_size'  => 0,
            'files_skipped_binary'=> 0,
            'files_unreadable'    => 0,
            'unreadable_dirs'     => 0,
            'symlinks_skipped'    => 0,
            'timed_out'           => false,
            'hit_result_cap'      => false,
        ];

        set_time_limit(MAX_EXECUTION_SECONDS + 5);

        foreach (searchFiles($inputPath, $inputNeedle, $exts, $inputCase, $startTime, $stats) as $result) {
            // Optional: also filter by path string
            if ($inputMatchPath && stripos($result['path'], $inputNeedle) === false &&
                !empty($result['matchLines'])) {
                // still include — matched content takes priority
            }
            $results[] = $result;
        }

        $searchTime = elapsed($startTime);
        $didSearch  = true;
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Server File Search</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --surface2: #21262d;
    --border: #30363d; --accent: #58a6ff; --accent2: #3fb950;
    --accent3: #f78166; --accent4: #e3b341; --text: #c9d1d9;
    --muted: #8b949e; --radius: 8px;
    --font: 'Segoe UI', system-ui, sans-serif;
    --mono: 'Cascadia Code', Consolas, monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font); font-size: 14px; line-height: 1.6; padding: 24px 16px 64px; }
  .wrap { max-width: 1100px; margin: 0 auto; }
  h1 { font-size: 1.5rem; font-weight: 700; color: #fff; margin-bottom: 4px; display: flex; align-items: center; gap: 10px; }
  .subtitle { color: var(--muted); font-size: 13px; margin-bottom: 28px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 20px 24px; margin-bottom: 20px; }
  label { display: block; font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; margin-bottom: 6px; }
  input[type=text], select {
    width: 100%; background: var(--surface2); border: 1px solid var(--border); border-radius: 6px;
    color: var(--text); font-family: var(--mono); font-size: 14px; padding: 8px 12px;
    outline: none; transition: border-color .15s;
  }
  input[type=text]:focus, select:focus { border-color: var(--accent); }
  .row2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .row3 { display: grid; grid-template-columns: 2fr 1fr 1fr; gap: 16px; }
  .checks { display: flex; gap: 24px; margin-top: 4px; }
  .checks label { display: flex; align-items: center; gap: 8px; text-transform: none; letter-spacing: 0; font-size: 13px; color: var(--text); cursor: pointer; }
  .checks input[type=checkbox] { accent-color: var(--accent); width: 15px; height: 15px; }
  .btn {
    display: inline-flex; align-items: center; gap: 8px;
    background: var(--accent); color: #0d1117; font-weight: 700; font-size: 14px;
    border: none; border-radius: 6px; padding: 10px 24px; cursor: pointer;
    transition: opacity .15s; margin-top: 16px;
  }
  .btn:hover { opacity: .85; }
  .btn:disabled { opacity: .4; cursor: not-allowed; }
  .btn-clear { background: var(--surface2); color: var(--text); border: 1px solid var(--border); }
  .error { background: rgba(247,129,102,.1); border: 1px solid var(--accent3); border-radius: 6px; padding: 10px 14px; color: var(--accent3); margin-bottom: 16px; font-size: 13px; }
  .stats-bar {
    display: flex; flex-wrap: wrap; gap: 12px; align-items: center;
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
    padding: 12px 18px; margin-bottom: 16px; font-size: 13px;
  }
  .stat { color: var(--muted); }
  .stat strong { color: #fff; font-family: var(--mono); }
  .stat-warn { color: var(--accent4); font-weight: 600; }
  .stat-good { color: var(--accent2); font-weight: 600; }
  .result-item {
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
    margin-bottom: 10px; overflow: hidden;
  }
  .result-header {
    display: flex; justify-content: space-between; align-items: flex-start;
    padding: 10px 16px; cursor: pointer; user-select: none;
    transition: background .1s; gap: 16px;
  }
  .result-header:hover { background: var(--surface2); }
  .result-path { font-family: var(--mono); font-size: 13px; color: var(--accent); word-break: break-all; }
  .result-meta { font-size: 11px; color: var(--muted); white-space: nowrap; text-align: right; flex-shrink: 0; }
  .result-meta span { display: block; }
  .result-lines { display: none; border-top: 1px solid var(--border); }
  .result-lines.open { display: block; }
  .result-line {
    display: flex; gap: 16px; align-items: baseline;
    padding: 5px 16px; border-bottom: 1px solid var(--border); font-size: 12px;
  }
  .result-line:last-child { border-bottom: none; }
  .line-no { color: var(--accent4); font-family: var(--mono); min-width: 40px; flex-shrink: 0; }
  .line-content { font-family: var(--mono); color: var(--text); word-break: break-all; white-space: pre-wrap; }
  .no-results { text-align: center; padding: 48px 16px; color: var(--muted); font-size: 15px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge-yellow { background: rgba(227,179,65,.2); color: var(--accent4); }
  .badge-red    { background: rgba(247,129,102,.2); color: var(--accent3); }
  .badge-green  { background: rgba(63,185,80,.2);   color: var(--accent2); }
  .toolbar { display: flex; gap: 10px; align-items: center; margin-bottom: 14px; flex-wrap: wrap; }
  .toolbar input[type=text] { max-width: 300px; font-size: 13px; }
  .export-btn { background: var(--surface2); border: 1px solid var(--border); color: var(--text); border-radius: 6px; padding: 6px 14px; font-size: 12px; cursor: pointer; }
  .export-btn:hover { border-color: var(--accent); color: var(--accent); }
  mark { background: rgba(227,179,65,.3); color: var(--accent4); border-radius: 2px; }
  @media (max-width: 640px) {
    .row2, .row3 { grid-template-columns: 1fr; }
    .toolbar { flex-direction: column; align-items: stretch; }
  }
</style>
</head>
<body>
<div class="wrap">

  <h1>&#128269; Server File Search</h1>
  <p class="subtitle">
    Searching as: <code style="color:var(--accent4)"><?= h($clientIp) ?></code>
    &nbsp;&bull;&nbsp; PHP <?= h(PHP_VERSION) ?>
    &nbsp;&bull;&nbsp; Time limit: <?= MAX_EXECUTION_SECONDS ?>s
    &nbsp;&bull;&nbsp; Max results: <?= number_format(MAX_RESULTS) ?>
  </p>

  <?php foreach ($errors as $err): ?>
  <div class="error">&#9888; <?= $err ?></div>
  <?php endforeach; ?>

  <!-- ── Search Form ── -->
  <div class="card">
    <form method="POST" id="searchForm">
      <div class="row3" style="margin-bottom:16px">
        <div>
          <label for="path">Starting Path</label>
          <input type="text" id="path" name="path"
                 value="<?= h($inputPath ?: ($_SERVER['DOCUMENT_ROOT'] ?? '/var/www')) ?>"
                 placeholder="/var/www/html" autocomplete="off" spellcheck="false">
        </div>
        <div>
          <label for="filetype">File Types</label>
          <select id="filetype" name="filetype">
            <?php foreach (FILE_TYPES as $key => $def): ?>
            <option value="<?= h($key) ?>" <?= $inputType === $key ? 'selected' : '' ?>>
              <?= h($def['label']) ?><?= !empty($def['exts']) ? ' (.' . implode(', .', $def['exts']) . ')' : '' ?>
            </option>
            <?php endforeach; ?>
          </select>
        </div>
        <div>
          <label for="needle">Search Text</label>
          <input type="text" id="needle" name="needle"
                 value="<?= h($inputNeedle) ?>"
                 placeholder="text to find..." autocomplete="off" spellcheck="false">
        </div>
      </div>

      <div class="checks">
        <label>
          <input type="checkbox" name="case_sensitive" <?= $inputCase ? 'checked' : '' ?>>
          Case-sensitive
        </label>
        <label>
          <input type="checkbox" name="match_path" <?= $inputMatchPath ? 'checked' : '' ?>>
          Also match filename/path
        </label>
      </div>

      <div style="display:flex;gap:10px">
        <button type="submit" class="btn" id="submitBtn">&#128270; Search</button>
        <button type="reset" class="btn btn-clear" onclick="document.getElementById('needle').value=''">Clear</button>
      </div>
    </form>
  </div>

  <?php if ($didSearch): ?>

  <!-- ── Stats bar ── -->
  <div class="stats-bar">
    <span class="stat">Found <strong><?= number_format(count($results)) ?></strong> file<?= count($results) !== 1 ? 's' : '' ?></span>
    <span class="stat">Scanned <strong><?= number_format($stats['files_scanned']) ?></strong> files</span>
    <span class="stat">in <strong><?= number_format($stats['dirs_scanned']) ?></strong> dirs</span>
    <span class="stat">Time: <strong><?= $searchTime ?>s</strong></span>
    <?php if ($stats['files_skipped_size']): ?>
    <span class="stat">Skipped (size): <strong><?= number_format($stats['files_skipped_size']) ?></strong></span>
    <?php endif; ?>
    <?php if ($stats['files_unreadable'] || $stats['unreadable_dirs']): ?>
    <span class="stat">Unreadable: <strong><?= number_format($stats['files_unreadable'] + $stats['unreadable_dirs']) ?></strong></span>
    <?php endif; ?>
    <?php if ($stats['timed_out']): ?>
    <span class="stat-warn">&#9201; Search stopped — time limit reached (<?= MAX_EXECUTION_SECONDS ?>s). Results are partial.</span>
    <?php elseif ($stats['hit_result_cap']): ?>
    <span class="stat-warn">&#9888; Result cap of <?= number_format(MAX_RESULTS) ?> reached. Narrow your search.</span>
    <?php else: ?>
    <span class="stat-good">&#10003; Search complete</span>
    <?php endif; ?>
  </div>

  <?php if (!empty($results)): ?>

  <!-- ── Toolbar ── -->
  <div class="toolbar">
    <input type="text" id="filterBox" placeholder="Filter results by path..." oninput="filterResults()" autocomplete="off">
    <button class="export-btn" onclick="exportTxt()">&#8659; Export .txt</button>
    <button class="export-btn" onclick="exportCsv()">&#8659; Export .csv</button>
    <button class="export-btn" onclick="toggleAll(true)">Expand all</button>
    <button class="export-btn" onclick="toggleAll(false)">Collapse all</button>
  </div>

  <!-- ── Results ── -->
  <div id="resultsList">
    <?php foreach ($results as $i => $r):
      $modDate  = $r['modified'] ? date('Y-m-d H:i', $r['modified']) : '—';
      $sizeKb   = $r['size'] < 1024 ? $r['size'] . ' B' : round($r['size'] / 1024, 1) . ' KB';
      $ext      = strtolower(pathinfo($r['path'], PATHINFO_EXTENSION));
      $lineCount= count($r['matchLines']);
    ?>
    <div class="result-item" data-path="<?= h(strtolower($r['path'])) ?>">
      <div class="result-header" onclick="toggle(this)">
        <span class="result-path"><?= h($r['path']) ?></span>
        <span class="result-meta">
          <span><?= $lineCount ?> match<?= $lineCount !== 1 ? 'es' : '' ?> shown</span>
          <span><?= h($sizeKb) ?> &bull; <?= h($ext ?: '?') ?></span>
          <span style="color:var(--muted)"><?= h($modDate) ?></span>
        </span>
      </div>
      <?php if (!empty($r['matchLines'])): ?>
      <div class="result-lines">
        <?php foreach ($r['matchLines'] as $line): ?>
        <div class="result-line">
          <span class="line-no">:<?= (int)$line['number'] ?></span>
          <span class="line-content"><?= h(mb_strimwidth($line['content'], 0, 300, '…')) ?></span>
        </div>
        <?php endforeach; ?>
        <?php if (count($r['matchLines']) >= 5): ?>
        <div class="result-line"><span style="color:var(--muted);font-size:11px;font-style:italic">Preview capped at 5 lines per file</span></div>
        <?php endif; ?>
      </div>
      <?php endif; ?>
    </div>
    <?php endforeach; ?>
  </div>

  <?php else: ?>
  <div class="no-results">&#128208; No files matched <strong><?= h($inputNeedle) ?></strong></div>
  <?php endif; ?>

  <?php endif; ?>

</div>

<script>
// Store all results for export
const allResults = <?= $didSearch ? json_encode(array_map(fn($r) => [
    'path'    => $r['path'],
    'size'    => $r['size'],
    'lines'   => array_map(fn($l) => $l['number'] . ': ' . $l['content'], $r['matchLines']),
], $results)) : '[]' ?>;

const needle = <?= json_encode($inputNeedle) ?>;

function toggle(header) {
  const lines = header.nextElementSibling;
  if (lines) lines.classList.toggle('open');
}

function toggleAll(open) {
  document.querySelectorAll('.result-lines').forEach(el => {
    el.classList.toggle('open', open);
  });
}

function filterResults() {
  const q = document.getElementById('filterBox').value.toLowerCase();
  document.querySelectorAll('#resultsList .result-item').forEach(el => {
    el.style.display = !q || el.dataset.path.includes(q) ? '' : 'none';
  });
}

function exportTxt() {
  let out = 'Search: ' + needle + '\nDate: ' + new Date().toISOString() + '\n' +
            'Results: ' + allResults.length + '\n\n' + '='.repeat(80) + '\n\n';
  allResults.forEach((r, i) => {
    out += (i + 1) + '. ' + r.path + '\n';
    r.lines.forEach(l => out += '   ' + l + '\n');
    out += '\n';
  });
  download('search-results.txt', out, 'text/plain');
}

function exportCsv() {
  let out = '"#","Path","Size (bytes)","Match Preview"\n';
  allResults.forEach((r, i) => {
    const preview = r.lines.join(' | ').replace(/"/g, '""');
    out += `${i+1},"${r.path.replace(/"/g,'""')}",${r.size},"${preview}"\n`;
  });
  download('search-results.csv', out, 'text/csv');
}

function download(filename, text, mime) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: mime }));
  a.download = filename;
  a.click();
}

// Disable submit button while searching
document.getElementById('searchForm').addEventListener('submit', () => {
  const btn = document.getElementById('submitBtn');
  btn.disabled = true;
  btn.textContent = '⏳ Searching…';
});
</script>
</body>
</html>
