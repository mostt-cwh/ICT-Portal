<?php
declare(strict_types=1);

session_name('ICTADMIN');
$https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
$cookiePath = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '')), '/');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => ($cookiePath === '' ? '/' : $cookiePath . '/'),
    'httponly' => true,
    'samesite' => 'Lax',
    'secure' => $https,
]);
session_start();

const CATEGORIES = [
    'A' => 'A',
    'B' => 'B',
    'C' => 'C',
    'D' => 'D',
    'E' => 'E',
    'ElectiveA' => 'Elective A',
    'ElectiveB' => 'Elective B',
    'ElectiveC' => 'Elective C',
    'DSE' => 'DSE',
    'Games' => 'Games',
];

const ICONS = [
    'fa-solid fa-book' => '書本',
    'fa-solid fa-magnifying-glass-chart' => '搜尋',
    'fa-solid fa-file-excel' => '試算表',
    'fa-solid fa-database' => '資料庫',
    'fa-solid fa-microchip' => '硬件',
    'fa-solid fa-memory' => '記憶體',
    'fa-solid fa-network-wired' => '網絡',
    'fa-solid fa-circle-nodes' => '節點',
    'fa-solid fa-diagram-project' => '流程',
    'fa-solid fa-code' => '程式',
    'fa-solid fa-building-shield' => '保安',
    'fa-solid fa-key' => '鑰匙',
    'fa-solid fa-shield-halved' => '防護',
    'fa-solid fa-layer-group' => '層級',
    'fa-solid fa-folder-tree' => '檔案',
    'fa-solid fa-arrow-down-short-wide' => '排序',
    'fa-solid fa-pen' => '筆試',
    'fa-regular fa-keyboard' => '鍵盤',
];

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function portal_path(): string
{
    return __DIR__ . '/index.html';
}

function auth_path(): string
{
    return __DIR__ . '/data/admin-auth.php';
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf']) || !is_string($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(16));
    }
    return $_SESSION['csrf'];
}

function check_csrf(): void
{
    $sent = $_POST['csrf'] ?? '';
    if (!is_string($sent) || !hash_equals(csrf_token(), $sent)) {
        http_response_code(400);
        exit('要求已過期，請返回再試一次。');
    }
}

function redirect(string $to = 'admin.php'): void
{
    header('Location: ' . $to);
    exit;
}

function flash(string $type, string $text, string $href = ''): void
{
    $_SESSION['flash'] = ['type' => $type, 'text' => $text, 'href' => $href];
}

function logged_in(): bool
{
    return !empty($_SESSION['admin']);
}

function auth_hash(): ?string
{
    $path = auth_path();
    if (!is_file($path)) {
        return null;
    }
    $hash = include $path;
    return is_string($hash) && $hash !== '' ? $hash : null;
}

function save_auth_hash(string $hash): void
{
    $dir = __DIR__ . '/data';
    if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
        throw new RuntimeException('未能建立 data 資料夾，所以不能儲存密碼。');
    }
    $content = "<?php\nreturn " . var_export($hash, true) . ";\n";
    $tmp = $dir . '/admin-auth.php.tmp';
    if (file_put_contents($tmp, $content, LOCK_EX) === false) {
        throw new RuntimeException('未能儲存密碼。');
    }
    @chmod($tmp, 0600);
    if (!rename($tmp, auth_path())) {
        @unlink($tmp);
        throw new RuntimeException('未能儲存密碼。');
    }
}

function text_length(string $value): int
{
    if (function_exists('mb_strlen')) {
        return mb_strlen($value, 'UTF-8');
    }
    return preg_match_all('/./u', $value) ?: 0;
}

function clean_text(string $value): string
{
    $value = str_replace(["\r\n", "\r"], "\n", $value);
    if (preg_match('//u', $value) !== 1) {
        return '';
    }
    $value = preg_replace('/[^\P{C}\n]+/u', '', $value) ?? '';
    return trim($value);
}

function valid_icon(string $icon): bool
{
    return (bool) preg_match('/^fa-(solid|regular|brands) fa-[a-z0-9-]+$/', $icon);
}

function valid_link(string $link): bool
{
    if (preg_match('#^https?://#i', $link)) {
        return filter_var($link, FILTER_VALIDATE_URL) !== false && !preg_match('/\s/', $link);
    }
    if (!preg_match('#^[A-Za-z0-9][A-Za-z0-9._/-]*\.(html|htm)$#', $link)) {
        return false;
    }
    if (str_contains($link, '..') || str_contains($link, '//')) {
        return false;
    }
    foreach (explode('/', $link) as $part) {
        if ($part === '' || $part === '.' || $part === '..') {
            return false;
        }
    }
    return true;
}

function valid_id(string $id): bool
{
    if (!preg_match('#^[A-Za-z0-9][A-Za-z0-9._/-]*$#', $id)) {
        return false;
    }
    if (str_contains($id, '..') || str_contains($id, '//')) {
        return false;
    }
    foreach (explode('/', $id) as $part) {
        if ($part === '' || $part === '.' || $part === '..') {
            return false;
        }
    }
    return true;
}

function is_remote(string $link): bool
{
    return (bool) preg_match('#^https?://#i', $link);
}

function card_id(array $card): string
{
    $id = trim((string) ($card['id'] ?? ''));
    return $id !== '' ? $id : (string) $card['link'];
}

function read_cards(): array
{
    $html = file_get_contents(portal_path());
    if ($html === false) {
        throw new RuntimeException('讀不到 index.html。');
    }
    if (!preg_match('/<script id="admin-card-data" type="application\/json">(.*?)<\/script>/s', $html, $match)) {
        throw new RuntimeException('index.html 裡找不到課題資料。');
    }
    $cards = json_decode($match[1], true);
    if (!is_array($cards)) {
        throw new RuntimeException('課題資料不是有效的 JSON。');
    }
    return $cards;
}

function encode_cards(array $cards): string
{
    $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_HEX_TAG;
    $lines = [];
    $last = count($cards) - 1;
    foreach ($cards as $index => $card) {
        $clean = [
            'title' => (string) $card['title'],
            'category' => (string) $card['category'],
            'icon' => (string) $card['icon'],
            'link' => (string) $card['link'],
        ];
        $id = trim((string) ($card['id'] ?? ''));
        if ($id !== '' && $id !== $clean['link']) {
            $clean['id'] = $id;
        }
        $clean['desc'] = (string) $card['desc'];
        $json = json_encode($clean, $flags);
        if ($json === false) {
            throw new RuntimeException('未能整理課題資料。');
        }
        $lines[] = '        ' . $json . ($index === $last ? '' : ',');
    }
    return "[\n" . implode("\n", $lines) . "\n    ]";
}

function write_cards(array $cards): void
{
    $path = portal_path();
    $html = file_get_contents($path);
    if ($html === false) {
        throw new RuntimeException('讀不到 index.html。');
    }
    $encoded = encode_cards($cards);
    $updated = preg_replace(
        '/<script id="admin-card-data" type="application\/json">.*?<\/script>/s',
        '<script id="admin-card-data" type="application/json">' . $encoded . '</script>',
        $html,
        1,
        $count
    );
    if ($count !== 1 || !is_string($updated)) {
        throw new RuntimeException('未能更新課題資料。');
    }
    $check = json_decode(trim(explode('</script>', explode('<script id="admin-card-data" type="application/json">', $updated, 2)[1], 2)[0]), true);
    if (!is_array($check) || count($check) !== count($cards)) {
        throw new RuntimeException('儲存前的課題資料未能通過檢查，沒有寫入。');
    }
    $tmp = $path . '.tmp';
    if (file_put_contents($tmp, $updated, LOCK_EX) === false) {
        throw new RuntimeException('未能寫入 index.html。請確認網站有權限修改這個檔案。');
    }
    if (!rename($tmp, $path)) {
        @unlink($tmp);
        throw new RuntimeException('未能儲存 index.html。');
    }
}

function split_desc(string $desc): array
{
    $parts = explode("\n", $desc, 2);
    if (count($parts) === 2) {
        return ['chapter' => $parts[0], 'detail' => $parts[1]];
    }
    return ['chapter' => '', 'detail' => $desc];
}

function blank_form(): array
{
    return [
        'title' => '',
        'category' => 'A',
        'icon' => 'fa-solid fa-book',
        'custom_icon' => '',
        'link' => '',
        'card_id' => '',
        'chapter' => '',
        'detail' => '',
        'index' => '',
    ];
}

function form_from_card(array $card, int $index): array
{
    $desc = split_desc((string) ($card['desc'] ?? ''));
    $icon = (string) ($card['icon'] ?? 'fa-solid fa-book');
    $known = array_key_exists($icon, ICONS);
    return [
        'title' => (string) ($card['title'] ?? ''),
        'category' => (string) ($card['category'] ?? 'A'),
        'icon' => $known ? $icon : '__custom__',
        'custom_icon' => $known ? '' : $icon,
        'link' => (string) ($card['link'] ?? ''),
        'card_id' => (($card['id'] ?? '') !== '' && ($card['id'] ?? '') !== ($card['link'] ?? '')) ? (string) $card['id'] : '',
        'chapter' => $desc['chapter'],
        'detail' => $desc['detail'],
        'index' => (string) $index,
    ];
}

function collect_card(array $post): array
{
    $errors = [];
    $title = clean_text((string) ($post['title'] ?? ''));
    $category = (string) ($post['category'] ?? '');
    $iconChoice = (string) ($post['icon'] ?? '');
    $customIcon = trim((string) ($post['custom_icon'] ?? ''));
    $link = trim((string) ($post['link'] ?? ''));
    $cardId = trim((string) ($post['card_id'] ?? ''));
    $chapter = clean_text((string) ($post['chapter'] ?? ''));
    $detail = clean_text((string) ($post['detail'] ?? ''));

    if ($title === '' || text_length($title) > 80) {
        $errors[] = '請填課題名稱，80 字以內。';
    }
    if (!isset(CATEGORIES[$category])) {
        $errors[] = '請選擇分類。';
    }
    $icon = $iconChoice === '__custom__' ? $customIcon : $iconChoice;
    if (!valid_icon($icon)) {
        $errors[] = '圖示格式要像 fa-solid fa-book。';
    }
    if (!valid_link($link)) {
        $errors[] = '連結要是 .html 檔名，或是 http(s) 網址。';
    }
    if ($cardId !== '' && !valid_id($cardId)) {
        $errors[] = '識別碼只可使用英文、數字、底線、減號和斜線。';
    }
    if (text_length($chapter) > 60 || text_length($detail) > 160) {
        $errors[] = '章節或說明太長。';
    }
    $desc = $chapter !== '' && $detail !== '' ? $chapter . "\n" . $detail : ($chapter !== '' ? $chapter : $detail);
    if ($desc === '') {
        $errors[] = '請填章節或說明，卡片上需要這一行。';
    }

    $card = [
        'title' => $title,
        'category' => $category,
        'icon' => $icon,
        'link' => $link,
        'desc' => $desc,
    ];
    if ($cardId !== '' && $cardId !== $link) {
        $card['id'] = $cardId;
    }
    return [$card, $errors];
}

function duplicate_index(array $cards, array $card, int $ignore): int
{
    $id = card_id($card);
    foreach ($cards as $index => $existing) {
        if ($index === $ignore) {
            continue;
        }
        if (($existing['category'] ?? '') === $card['category'] && card_id($existing) === $id) {
            return $index;
        }
    }
    return -1;
}

function insert_in_category(array $cards, array $card): array
{
    $last = -1;
    foreach ($cards as $index => $existing) {
        if (($existing['category'] ?? '') === $card['category']) {
            $last = $index;
        }
    }
    $place = $last + 1;
    array_splice($cards, $place, 0, [$card]);
    return [$cards, $place];
}

function local_file_missing(array $card): bool
{
    $link = (string) ($card['link'] ?? '');
    if ($link === '' || is_remote($link) || !valid_link($link)) {
        return false;
    }
    $root = realpath(__DIR__);
    if ($root === false) {
        return false;
    }
    $target = $root . '/' . $link;
    $dir = realpath(dirname($target));
    if ($dir === false || !str_starts_with($dir . DIRECTORY_SEPARATOR, $root . DIRECTORY_SEPARATOR)) {
        return true;
    }
    return !is_file($target);
}

function store_upload(string $link): ?string
{
    $file = $_FILES['lesson_file'] ?? null;
    if (!is_array($file) || ($file['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) {
        return null;
    }
    if (($file['error'] ?? UPLOAD_ERR_OK) !== UPLOAD_ERR_OK) {
        return '上傳失敗，請再試一次。';
    }
    if (!is_uploaded_file((string) $file['tmp_name'])) {
        return '上傳失敗，請再試一次。';
    }
    if (($file['size'] ?? 0) > 1500000) {
        return 'HTML 檔案不能超過 1.5 MB。';
    }
    if (is_remote($link) || !valid_link($link) || str_contains($link, '/')) {
        return '上傳的檔案只會存到網站根目錄。連結請填檔名，例如 topic.html。';
    }
    $root = realpath(__DIR__);
    $target = $root . '/' . $link;
    $dir = realpath(dirname($target));
    if ($root === false || $dir === false || !str_starts_with($dir . DIRECTORY_SEPARATOR, $root . DIRECTORY_SEPARATOR)) {
        return '不能把檔案存到這個位置。';
    }
    if (is_file($target)) {
        return '伺服器已有 ' . $link . '，沒有覆蓋。請換一個檔名。';
    }
    if (!move_uploaded_file((string) $file['tmp_name'], $target)) {
        return '未能儲存上傳的 HTML。';
    }
    @chmod($target, 0644);
    return null;
}

function portal_href(array $card): string
{
    return 'index.html#c=' . rawurlencode((string) $card['category']) . '&i=' . rawurlencode(card_id($card));
}

function too_many_logins(): bool
{
    return (int) ($_SESSION['login_wait'] ?? 0) > time();
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $action = (string) ($_POST['action'] ?? '');
    try {
        if ($action === 'setup') {
            check_csrf();
            if (auth_hash() !== null) {
                redirect();
            }
            $password = (string) ($_POST['password'] ?? '');
            $confirm = (string) ($_POST['confirm'] ?? '');
            if (text_length($password) < 6 || text_length($password) > 80) {
                flash('err', '密碼需要 6 至 80 個字元。');
                redirect();
            }
            if (!hash_equals($password, $confirm)) {
                flash('err', '兩次輸入的密碼不相同。');
                redirect();
            }
            save_auth_hash(password_hash($password, PASSWORD_DEFAULT));
            session_regenerate_id(true);
            $_SESSION['admin'] = true;
            flash('ok', '密碼已設定，可以開始新增課題。');
            redirect();
        }

        if ($action === 'login') {
            check_csrf();
            if (too_many_logins()) {
                flash('err', '嘗試太多次，請稍後再登入。');
                redirect();
            }
            $hash = auth_hash();
            $password = (string) ($_POST['password'] ?? '');
            if ($hash === null || !password_verify($password, $hash)) {
                $_SESSION['login_fails'] = (int) ($_SESSION['login_fails'] ?? 0) + 1;
                if ($_SESSION['login_fails'] >= 8) {
                    $_SESSION['login_wait'] = time() + 60;
                    $_SESSION['login_fails'] = 0;
                }
                flash('err', '密碼不正確。');
                redirect();
            }
            session_regenerate_id(true);
            $_SESSION['admin'] = true;
            $_SESSION['login_fails'] = 0;
            redirect();
        }

        if ($action === 'logout') {
            check_csrf();
            $_SESSION = [];
            session_destroy();
            redirect();
        }

        if (!logged_in()) {
            http_response_code(403);
            exit('請先登入。');
        }
        check_csrf();

        if ($action === 'password') {
            $current = (string) ($_POST['current_password'] ?? '');
            $password = (string) ($_POST['password'] ?? '');
            $confirm = (string) ($_POST['confirm'] ?? '');
            $hash = auth_hash();
            if ($hash === null || !password_verify($current, $hash)) {
                flash('err', '現時密碼不正確。');
                redirect();
            }
            if (text_length($password) < 6 || text_length($password) > 80) {
                flash('err', '新密碼需要 6 至 80 個字元。');
                redirect();
            }
            if (!hash_equals($password, $confirm)) {
                flash('err', '兩次輸入的新密碼不相同。');
                redirect();
            }
            save_auth_hash(password_hash($password, PASSWORD_DEFAULT));
            flash('ok', '密碼已更新。');
            redirect();
        }

        if ($action === 'delete') {
            $index = (int) ($_POST['index'] ?? -1);
            $cards = read_cards();
            if (!isset($cards[$index])) {
                flash('err', '找不到要刪除的課題。');
                redirect();
            }
            $title = (string) $cards[$index]['title'];
            array_splice($cards, $index, 1);
            write_cards($cards);
            flash('ok', '已刪除「' . $title . '」。');
            redirect();
        }

        if ($action === 'move') {
            $index = (int) ($_POST['index'] ?? -1);
            $direction = ($_POST['direction'] ?? '') === 'up' ? -1 : 1;
            $cards = read_cards();
            if (!isset($cards[$index])) {
                flash('err', '找不到要移動的課題。');
                redirect();
            }
            $target = null;
            if ($direction < 0) {
                for ($i = $index - 1; $i >= 0; $i--) {
                    if (($cards[$i]['category'] ?? '') === ($cards[$index]['category'] ?? '')) {
                        $target = $i;
                        break;
                    }
                }
            } else {
                for ($i = $index + 1; $i < count($cards); $i++) {
                    if (($cards[$i]['category'] ?? '') === ($cards[$index]['category'] ?? '')) {
                        $target = $i;
                        break;
                    }
                }
            }
            if ($target !== null) {
                [$cards[$index], $cards[$target]] = [$cards[$target], $cards[$index]];
                write_cards($cards);
            }
            redirect('admin.php#lesson-' . ($target ?? $index));
        }

        if ($action === 'save') {
            [$card, $errors] = collect_card($_POST);
            $editing = ($_POST['index'] ?? '') === '' ? -1 : (int) $_POST['index'];
            $cards = read_cards();
            if ($editing >= 0 && !isset($cards[$editing])) {
                $errors[] = '找不到要修改的課題。';
            }
            if (!$errors && duplicate_index($cards, $card, $editing) >= 0) {
                $errors[] = '這個分類已經有同一個連結。';
            }
            if (!$errors) {
                $uploadError = store_upload((string) $card['link']);
                if ($uploadError !== null) {
                    $errors[] = $uploadError;
                }
            }
            if ($errors) {
                $saveErrors = $errors;
                $form = [
                    'title' => clean_text((string) ($_POST['title'] ?? '')),
                    'category' => (string) ($_POST['category'] ?? 'A'),
                    'icon' => (string) ($_POST['icon'] ?? 'fa-solid fa-book'),
                    'custom_icon' => trim((string) ($_POST['custom_icon'] ?? '')),
                    'link' => trim((string) ($_POST['link'] ?? '')),
                    'card_id' => trim((string) ($_POST['card_id'] ?? '')),
                    'chapter' => clean_text((string) ($_POST['chapter'] ?? '')),
                    'detail' => clean_text((string) ($_POST['detail'] ?? '')),
                    'index' => $editing >= 0 ? (string) $editing : '',
                ];
            } else {
                if ($editing >= 0) {
                    $oldCategory = (string) ($cards[$editing]['category'] ?? '');
                    if ($oldCategory !== $card['category']) {
                        array_splice($cards, $editing, 1);
                        [$cards, $placed] = insert_in_category($cards, $card);
                    } else {
                        $cards[$editing] = $card;
                        $placed = $editing;
                    }
                    $verb = '已更新';
                } else {
                    [$cards, $placed] = insert_in_category($cards, $card);
                    $verb = '已新增';
                }
                write_cards($cards);
                flash('ok', $verb . '「' . $card['title'] . '」。', portal_href($card));
                redirect('admin.php#lesson-' . (int) $placed);
            }
        }
    } catch (RuntimeException $e) {
        flash('err', $e->getMessage());
        redirect();
    }
}

$hash = auth_hash();
$needsSetup = $hash === null;
$flashMessage = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);
$token = csrf_token();
$saveErrors = $saveErrors ?? [];
$form = $form ?? blank_form();
$cards = [];
$loadError = '';
$writable = is_writable(portal_path()) && is_writable(__DIR__);

if (!$needsSetup && logged_in()) {
    try {
        $cards = read_cards();
    } catch (RuntimeException $e) {
        $loadError = $e->getMessage();
    }
    if ($saveErrors === [] && isset($_GET['edit'])) {
        $editIndex = (int) $_GET['edit'];
        if (isset($cards[$editIndex])) {
            $form = form_from_card($cards[$editIndex], $editIndex);
        }
    }
}

$editing = $form['index'] !== '';
header('Content-Type: text/html; charset=UTF-8');
header('X-Frame-Options: DENY');
header('Referrer-Policy: same-origin');
?>
<!DOCTYPE html>
<html lang="zh-Hant">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex">
    <title>管理課題 — ICT Learning Portal</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Roboto+Mono:wght@400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --bg: #050510;
            --panel: rgba(16, 18, 32, 0.92);
            --line: rgba(255, 255, 255, 0.12);
            --cyan: #00f3ff;
            --text: #f4f7fb;
            --dim: #a0a8b8;
            --danger: #ff5d7a;
            --ok: #9dff6a;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            min-height: 100vh;
            color: var(--text);
            font-family: 'Roboto Mono', monospace;
            background: var(--bg);
            background-image:
                linear-gradient(rgba(0, 243, 255, 0.035) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 243, 255, 0.035) 1px, transparent 1px);
            background-size: 30px 30px;
        }
        a { color: var(--cyan); }
        button, input, select, textarea { font: inherit; color: inherit; }
        .wrap { width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 28px 0 64px; }
        .top {
            display: flex;
            justify-content: space-between;
            gap: 16px;
            align-items: flex-end;
            margin-bottom: 22px;
        }
        h1 {
            margin: 0 0 6px;
            font-family: 'Orbitron', sans-serif;
            font-size: clamp(1.4rem, 3vw, 2rem);
            letter-spacing: 1px;
            text-shadow: 0 0 12px rgba(0, 243, 255, 0.45);
        }
        .sub { margin: 0; color: var(--dim); line-height: 1.5; }
        .top-actions { display: flex; gap: 10px; align-items: center; }
        .ghost, .primary, .tiny, .danger {
            border-radius: 4px;
            cursor: pointer;
            text-decoration: none;
        }
        .ghost, .primary, .danger {
            border: 1px solid var(--cyan);
            background: transparent;
            color: var(--cyan);
            padding: 8px 14px;
        }
        .primary { background: var(--cyan); color: #041014; font-family: 'Orbitron', sans-serif; letter-spacing: 1px; }
        .danger { border-color: var(--danger); color: var(--danger); }
        .tiny {
            border: 1px solid var(--line);
            background: transparent;
            color: var(--text);
            padding: 5px 8px;
            font-size: 12px;
        }
        .ghost:hover, .tiny:hover, .danger:hover { border-color: var(--cyan); color: var(--cyan); }
        .primary:hover { box-shadow: 0 0 16px rgba(0, 243, 255, 0.45); }
        .layout { display: grid; grid-template-columns: minmax(280px, 390px) minmax(0, 1fr); gap: 22px; align-items: start; }
        .panel {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 18px;
        }
        .form-panel { position: sticky; top: 16px; }
        .form-panel h2, .gate h1 { font-family: 'Orbitron', sans-serif; letter-spacing: 1px; }
        .form-panel h2 { margin: 0; font-size: 1rem; }
        label { display: block; margin: 12px 0 6px; color: var(--dim); font-size: 12px; letter-spacing: 1px; }
        input[type="text"], input[type="password"], input[type="search"], select, textarea {
            width: 100%;
            background: #090b16;
            border: 1px solid var(--line);
            border-radius: 4px;
            padding: 9px 10px;
        }
        textarea { min-height: 68px; resize: vertical; }
        input:focus, select:focus, textarea:focus { outline: 1px solid var(--cyan); border-color: var(--cyan); }
        .hint { color: var(--dim); font-size: 12px; line-height: 1.45; margin-top: 6px; }
        .row-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
        .icon-row { display: grid; grid-template-columns: 1fr auto; gap: 10px; align-items: center; }
        .icon-preview {
            width: 42px; height: 42px; display: grid; place-items: center;
            border: 1px solid var(--line); border-radius: 4px; color: var(--cyan); font-size: 18px;
        }
        .actions { display: flex; gap: 8px; align-items: center; margin-top: 16px; }
        .flash, .errors {
            border-radius: 6px;
            padding: 10px 12px;
            margin-bottom: 16px;
            line-height: 1.5;
        }
        .flash.ok, .errors { background: rgba(0, 0, 0, 0.28); }
        .flash.ok { border: 1px solid rgba(157, 255, 106, 0.45); }
        .flash.err, .errors { border: 1px solid rgba(255, 93, 122, 0.5); color: #ffd0d8; }
        .gate { width: min(460px, calc(100% - 32px)); margin: 12vh auto; }
        .preview {
            margin-top: 16px;
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 16px 12px 14px;
            text-align: center;
            position: relative;
        }
        .preview .tag {
            position: absolute; top: 8px; right: 8px;
            font-family: 'Orbitron', sans-serif; font-size: 11px; letter-spacing: 1px;
            border: 1px solid var(--c, var(--cyan)); color: var(--c, var(--cyan));
            border-radius: 4px; padding: 3px 6px;
        }
        .preview .title { font-family: 'Orbitron', sans-serif; margin: 8px 0 6px; }
        .preview .desc { color: var(--dim); font-size: 13px; line-height: 1.4; }
        .cat-A { --c: #ff00ea; } .cat-B { --c: #aaff00; } .cat-C { --c: #00f3ff; }
        .cat-D { --c: #ffaa00; } .cat-E { --c: #ffff00; } .cat-ElectiveA { --c: #00ff88; }
        .cat-ElectiveB { --c: #bc13fe; } .cat-ElectiveC { --c: #4d4dff; }
        .cat-DSE { --c: #ff0055; } .cat-Games { --c: #c8c8c8; }
        .toolbar { display: flex; justify-content: space-between; gap: 12px; align-items: center; margin-bottom: 12px; }
        .toolbar h2 { margin: 0; font-size: 1rem; font-family: 'Orbitron', sans-serif; letter-spacing: 1px; }
        .lesson {
            display: grid;
            grid-template-columns: 36px minmax(0, 1fr) auto;
            gap: 12px;
            align-items: center;
            padding: 12px 0;
            border-top: 1px solid var(--line);
        }
        .lesson .name { font-family: 'Orbitron', sans-serif; font-size: 0.95rem; }
        .meta, .missing { color: var(--dim); font-size: 12px; line-height: 1.45; }
        .missing { color: #ffcf7a; }
        .lesson-actions { display: flex; flex-wrap: wrap; gap: 6px; justify-content: flex-end; }
        .group-label {
            margin: 18px 0 0;
            color: var(--c, var(--cyan));
            font-family: 'Orbitron', sans-serif;
            font-size: 13px;
            letter-spacing: 1px;
        }
        details { margin-top: 18px; color: var(--dim); }
        summary { cursor: pointer; color: var(--text); }
        .hidden { display: none !important; }
        @media (max-width: 860px) {
            .layout, .lesson, .row-2 { grid-template-columns: 1fr; }
            .form-panel { position: static; }
            .top { flex-direction: column; align-items: flex-start; }
            .lesson-actions { justify-content: flex-start; }
        }
    </style>
</head>
<body>
<?php if ($needsSetup || !logged_in()): ?>
    <main class="panel gate">
        <h1><?= $needsSetup ? '設定管理密碼' : '課題管理' ?></h1>
        <p class="sub"><?= $needsSetup ? '第一次使用請先設定密碼。密碼只存在這台伺服器。' : '輸入密碼後可以新增、修改和排列課題。' ?></p>
        <p class="sub"><a href="index.html">返回目錄</a></p>
        <?php if (is_array($flashMessage)): ?>
            <p class="flash <?= $flashMessage['type'] === 'ok' ? 'ok' : 'err' ?>"><?= h((string) $flashMessage['text']) ?></p>
        <?php endif; ?>
        <form method="post">
            <input type="hidden" name="csrf" value="<?= h($token) ?>">
            <input type="hidden" name="action" value="<?= $needsSetup ? 'setup' : 'login' ?>">
            <?php if ($needsSetup): ?>
                <label for="password">新密碼</label>
                <input id="password" name="password" type="password" autocomplete="new-password" required minlength="6">
                <label for="confirm">再輸入一次</label>
                <input id="confirm" name="confirm" type="password" autocomplete="new-password" required minlength="6">
                <div class="actions"><button class="primary" type="submit">設定密碼</button></div>
            <?php else: ?>
                <label for="password">密碼</label>
                <input id="password" name="password" type="password" autocomplete="current-password" required>
                <div class="actions"><button class="primary" type="submit">登入</button></div>
            <?php endif; ?>
        </form>
    </main>
<?php else: ?>
    <div class="wrap">
        <header class="top">
            <div>
                <h1>管理課題</h1>
                <p class="sub">新增後會寫入目錄。學生重新整理 ICT Learning Portal 就會看到。</p>
            </div>
            <div class="top-actions">
                <a class="ghost" href="index.html">返回目錄</a>
                <form method="post">
                    <input type="hidden" name="csrf" value="<?= h($token) ?>">
                    <input type="hidden" name="action" value="logout">
                    <button class="ghost" type="submit">登出</button>
                </form>
            </div>
        </header>

        <?php if (is_array($flashMessage)): ?>
            <p class="flash <?= $flashMessage['type'] === 'ok' ? 'ok' : 'err' ?>">
                <?= h((string) $flashMessage['text']) ?>
                <?php if (!empty($flashMessage['href'])): ?>
                    <a href="<?= h((string) $flashMessage['href']) ?>">在目錄查看</a>
                <?php endif; ?>
            </p>
        <?php endif; ?>
        <?php if (!$writable): ?>
            <p class="errors">index.html 目前不能寫入。請讓網站有權限修改這個檔案，否則不能儲存課題。</p>
        <?php endif; ?>
        <?php if ($loadError !== ''): ?>
            <p class="errors"><?= h($loadError) ?></p>
        <?php endif; ?>
        <?php if ($saveErrors): ?>
            <div class="errors"><?php foreach ($saveErrors as $error): ?><div><?= h($error) ?></div><?php endforeach; ?></div>
        <?php endif; ?>

        <div class="layout">
            <section class="panel form-panel">
                <h2><?= $editing ? '修改課題' : '新增課題' ?></h2>
                <form method="post" enctype="multipart/form-data" id="lessonForm">
                    <input type="hidden" name="csrf" value="<?= h($token) ?>">
                    <input type="hidden" name="action" value="save">
                    <input type="hidden" name="index" value="<?= h((string) $form['index']) ?>">

                    <label for="category">分類</label>
                    <select id="category" name="category" required>
                        <?php foreach (CATEGORIES as $id => $label): ?>
                            <option value="<?= h($id) ?>" <?= $form['category'] === $id ? 'selected' : '' ?>><?= h($label) ?></option>
                        <?php endforeach; ?>
                    </select>

                    <label for="title">課題名稱</label>
                    <input id="title" name="title" type="text" required maxlength="80" value="<?= h((string) $form['title']) ?>">

                    <div class="row-2">
                        <div>
                            <label for="chapter">章節</label>
                            <input id="chapter" name="chapter" type="text" maxlength="60" placeholder="例如 Ch.6" value="<?= h((string) $form['chapter']) ?>">
                        </div>
                        <div>
                            <label for="detail">說明</label>
                            <input id="detail" name="detail" type="text" maxlength="160" placeholder="顯示在卡片上" value="<?= h((string) $form['detail']) ?>">
                        </div>
                    </div>

                    <label for="link">連結</label>
                    <input id="link" name="link" type="text" required maxlength="300" placeholder="topic.html 或 https://..." value="<?= h((string) $form['link']) ?>">
                    <p class="hint">本機課題用 .html 檔名。外部網站用完整網址。</p>

                    <label for="lesson_file">上傳 HTML（可選）</label>
                    <input id="lesson_file" name="lesson_file" type="file" accept=".html,.htm,text/html">
                    <p class="hint">如果上傳檔案，會用上面的檔名存到網站根目錄，不會覆蓋已有檔案。</p>

                    <label for="icon">圖示</label>
                    <div class="icon-row">
                        <select id="icon" name="icon">
                            <?php foreach (ICONS as $class => $label): ?>
                                <option value="<?= h($class) ?>" <?= $form['icon'] === $class ? 'selected' : '' ?>><?= h($label) ?></option>
                            <?php endforeach; ?>
                            <option value="__custom__" <?= $form['icon'] === '__custom__' ? 'selected' : '' ?>>自訂</option>
                        </select>
                        <div class="icon-preview" id="iconPreview" aria-hidden="true"><i class="<?= h((string) ($form['icon'] === '__custom__' ? ($form['custom_icon'] ?: 'fa-solid fa-book') : $form['icon'])) ?>"></i></div>
                    </div>
                    <input id="custom_icon" name="custom_icon" type="text" maxlength="60" placeholder="fa-solid fa-book" value="<?= h((string) $form['custom_icon']) ?>" class="<?= $form['icon'] === '__custom__' ? '' : 'hidden' ?>">

                    <label for="card_id">識別碼（可留空）</label>
                    <input id="card_id" name="card_id" type="text" maxlength="120" placeholder="外部分站才需要，例如 sequentialaccess.html" value="<?= h((string) $form['card_id']) ?>">

                    <div class="preview cat-<?= h((string) $form['category']) ?>" id="preview">
                        <span class="tag" id="previewTag"><?= h(CATEGORIES[$form['category']] ?? $form['category']) ?></span>
                        <div class="title" id="previewTitle"><?= h((string) ($form['title'] !== '' ? $form['title'] : '課題名稱')) ?></div>
                        <div class="desc" id="previewDesc"><?= h((string) ($form['chapter'] !== '' ? $form['chapter'] : '章節')) ?><br><?= h((string) ($form['detail'] !== '' ? $form['detail'] : '說明')) ?></div>
                    </div>

                    <div class="actions">
                        <button class="primary" type="submit" <?= $writable ? '' : 'disabled' ?>><?= $editing ? '儲存修改' : '新增課題' ?></button>
                        <?php if ($editing): ?><a class="ghost" href="admin.php">取消</a><?php endif; ?>
                    </div>
                </form>

                <details>
                    <summary>更改密碼</summary>
                    <form method="post">
                        <input type="hidden" name="csrf" value="<?= h($token) ?>">
                        <input type="hidden" name="action" value="password">
                        <label for="current_password">現時密碼</label>
                        <input id="current_password" name="current_password" type="password" autocomplete="current-password" required>
                        <label for="new_password">新密碼</label>
                        <input id="new_password" name="password" type="password" autocomplete="new-password" required minlength="6">
                        <label for="new_confirm">再輸入一次</label>
                        <input id="new_confirm" name="confirm" type="password" autocomplete="new-password" required minlength="6">
                        <div class="actions"><button class="tiny" type="submit">更新密碼</button></div>
                    </form>
                </details>
            </section>

            <section class="panel">
                <div class="toolbar">
                    <h2>現有課題 <span id="lessonCount"><?= count($cards) ?></span></h2>
                    <input id="lessonSearch" type="search" placeholder="搜尋名稱或檔名" aria-label="搜尋課題">
                </div>
                <?php
                $previousCategory = null;
                foreach ($cards as $index => $card):
                    $category = (string) ($card['category'] ?? '');
                    $label = CATEGORIES[$category] ?? $category;
                    $search = strtolower($label . ' ' . ($card['title'] ?? '') . ' ' . ($card['link'] ?? '') . ' ' . ($card['desc'] ?? ''));
                    if ($category !== $previousCategory):
                        $previousCategory = $category;
                ?>
                    <h3 class="group-label cat-<?= h($category) ?>"><?= h($label) ?></h3>
                <?php endif; ?>
                    <article class="lesson" id="lesson-<?= $index ?>" data-search="<?= h($search) ?>">
                        <div class="icon-preview"><i class="<?= h(valid_icon((string) ($card['icon'] ?? '')) ? (string) $card['icon'] : 'fa-solid fa-book') ?>" aria-hidden="true"></i></div>
                        <div>
                            <div class="name"><?= h((string) ($card['title'] ?? '')) ?></div>
                            <div class="meta"><?= h((string) ($card['link'] ?? '')) ?><?php if (!empty($card['id'])): ?> · <?= h((string) $card['id']) ?><?php endif; ?></div>
                            <div class="meta"><?= nl2br(h((string) ($card['desc'] ?? ''))) ?></div>
                            <?php if (local_file_missing($card)): ?><div class="missing">檔案還未放上伺服器</div><?php endif; ?>
                        </div>
                        <div class="lesson-actions">
                            <form method="post">
                                <input type="hidden" name="csrf" value="<?= h($token) ?>">
                                <input type="hidden" name="action" value="move">
                                <input type="hidden" name="direction" value="up">
                                <input type="hidden" name="index" value="<?= $index ?>">
                                <button class="tiny" type="submit" aria-label="上移">上移</button>
                            </form>
                            <form method="post">
                                <input type="hidden" name="csrf" value="<?= h($token) ?>">
                                <input type="hidden" name="action" value="move">
                                <input type="hidden" name="direction" value="down">
                                <input type="hidden" name="index" value="<?= $index ?>">
                                <button class="tiny" type="submit" aria-label="下移">下移</button>
                            </form>
                            <a class="tiny" href="admin.php?edit=<?= $index ?>#lessonForm">修改</a>
                            <form method="post" onsubmit="return confirm(<?= h(json_encode('刪除「' . ($card['title'] ?? '') . '」？', JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT)) ?>);">
                                <input type="hidden" name="csrf" value="<?= h($token) ?>">
                                <input type="hidden" name="action" value="delete">
                                <input type="hidden" name="index" value="<?= $index ?>">
                                <button class="tiny danger" type="submit">刪除</button>
                            </form>
                        </div>
                    </article>
                <?php endforeach; ?>
            </section>
        </div>
    </div>
    <script>
        const icon = document.getElementById('icon');
        const customIcon = document.getElementById('custom_icon');
        const preview = document.getElementById('preview');
        const categories = <?= json_encode(CATEGORIES, JSON_UNESCAPED_UNICODE) ?>;

        function currentIcon() {
            if (icon.value === '__custom__') return customIcon.value.trim() || 'fa-solid fa-book';
            return icon.value;
        }
        function refreshPreview() {
            customIcon.classList.toggle('hidden', icon.value !== '__custom__');
            const iconClass = currentIcon();
            document.querySelector('#iconPreview i').className = /^fa-(solid|regular|brands) fa-[a-z0-9-]+$/.test(iconClass) ? iconClass : 'fa-solid fa-book';
            preview.className = 'preview cat-' + document.getElementById('category').value;
            document.getElementById('previewTag').textContent = categories[document.getElementById('category').value] || '';
            const title = document.getElementById('title').value.trim();
            const chapter = document.getElementById('chapter').value.trim();
            const detail = document.getElementById('detail').value.trim();
            document.getElementById('previewTitle').textContent = title || '課題名稱';
            document.getElementById('previewDesc').innerHTML = '';
            document.getElementById('previewDesc').append(chapter || '章節', document.createElement('br'), detail || '說明');
        }
        ['category', 'title', 'chapter', 'detail', 'icon', 'custom_icon'].forEach((id) => {
            document.getElementById(id).addEventListener('input', refreshPreview);
            document.getElementById(id).addEventListener('change', refreshPreview);
        });
        document.getElementById('lesson_file').addEventListener('change', (event) => {
            const link = document.getElementById('link');
            const file = event.target.files && event.target.files[0];
            if (!file || link.value.trim() !== '') return;
            const base = (file.name.split(/[/\\]/).pop() || '').replace(/\s+/g, '_').replace(/[^A-Za-z0-9._-]/g, '');
            if (/\.html?$/i.test(base)) link.value = base;
        });
        document.getElementById('lessonSearch').addEventListener('input', (event) => {
            const query = event.target.value.trim().toLowerCase();
            document.querySelectorAll('.lesson').forEach((row) => {
                row.classList.toggle('hidden', query !== '' && !row.dataset.search.includes(query));
            });
            document.querySelectorAll('.group-label').forEach((label) => {
                let node = label.nextElementSibling;
                let visible = false;
                while (node && !node.classList.contains('group-label')) {
                    if (node.classList.contains('lesson') && !node.classList.contains('hidden')) visible = true;
                    node = node.nextElementSibling;
                }
                label.classList.toggle('hidden', query !== '' && !visible);
            });
        });
    </script>
<?php endif; ?>
</body>
</html>
