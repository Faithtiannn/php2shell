package p2s;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/** 主界面：目标列表 + 四级检测 + 结果表 + 详情 + 导出 */
public class MainFrame extends JFrame {

    private static final String[] COLS = {"#", "目标", "版本", "指纹", "触发", "泄漏", "RCE", "耗时"};
    private static final String[] LEVEL_LABELS = {"版本指纹", "触发验证", "泄漏检测"};
    private static final String[] LEVEL_TIPS = {
            "读 banner 判版本（无破坏）",
            "发 multipart 让请求启动期 OOM（会打崩 worker）",
            "A/B 比对 cookie（会多次打崩 worker）"};

    private final JTextArea inputArea = new JTextArea(8, 40);
    private final DefaultTableModel model = new DefaultTableModel(COLS, 0) {
        @Override public boolean isCellEditable(int r, int c) { return false; }
    };
    private final JTable table = new JTable(model) {
        @Override public Component prepareRenderer(javax.swing.table.TableCellRenderer r, int row, int col) {
            Component c = super.prepareRenderer(r, row, col);
            String tag = row == 0 || results.isEmpty() ? "gray" : tagOf(results.get(row));
            switch (tag) {
                case "red" -> { c.setBackground(new Color(0xFDEBEA)); c.setForeground(new Color(0xC0392B)); }
                case "green" -> { c.setBackground(new Color(0xEEFAF1)); c.setForeground(new Color(0x1E7B45)); }
                case "orange" -> { c.setBackground(new Color(0xFFF4E6)); c.setForeground(new Color(0xD35400)); }
                default -> { c.setBackground(isRowSelected(row) ? new Color(0xDBEAFE) : Color.WHITE);
                             c.setForeground(new Color(0x4A5568)); }
            }
            if (isRowSelected(row)) c.setBackground(new Color(0xDBEAFE));
            return c;
        }
    };
    private final List<Probe.Result> results = new ArrayList<>();
    private final JCheckBox[] levelBoxes = new JCheckBox[3];
    private final JSpinner spWorkers = new JSpinner(new SpinnerNumberModel(4, 1, 32, 1));
    private final JSpinner spTimeout = new JSpinner(new SpinnerNumberModel(60, 5, 900, 5));
    private final JSpinner spRounds = new JSpinner(new SpinnerNumberModel(3, 1, 10, 1));
    private final JButton btnStart = new JButton("开始检测");
    private final JButton btnStop = new JButton("停止");
    private final JProgressBar progress = new JProgressBar();
    private final JLabel lblStat = new JLabel("就绪");
    private final JLabel lblCount = new JLabel("0 个目标");
    private final JTextArea detail = new JTextArea(7, 60);
    private ExecutorService pool;
    private final java.util.concurrent.atomic.AtomicBoolean stopped = new java.util.concurrent.atomic.AtomicBoolean();
    private final AtomicInteger done = new AtomicInteger();
    private int total;
    private JTabbedPane tabs;
    private RcePanel rcePanel;

    public MainFrame() {
        super("PHP2Shell 检测 · CVE-2026-109618 / CVE-2026-109619");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(1220, 840);
        setMinimumSize(new Dimension(980, 660));
        setLocationRelativeTo(null);
        buildUi();
        stopState();
    }

    private void buildUi() {
        JPanel root = new JPanel(new BorderLayout(10, 8));
        root.setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));

        /* 顶部：标题 + 目标 + 选项 + 进度 */
        JPanel top = new JPanel(new BorderLayout(0, 6));

        JPanel head = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JLabel t = new JLabel("PHP2Shell 检测");
        t.setFont(t.getFont().deriveFont(Font.BOLD, 18f));
        head.add(t);
        JLabel sub = new JLabel("CVE-2026-109618 / CVE-2026-109619 · 单目标或批量");
        sub.setForeground(new Color(0x6B7280));
        head.add(sub);
        top.add(head, BorderLayout.NORTH);

        JPanel mid = new JPanel(new BorderLayout(10, 0));

        /* 目标列表 */
        JPanel targetPanel = new JPanel(new BorderLayout(6, 0));
        targetPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "目标列表（每行一个，支持粘贴多行）",
                TitledBorder.LEFT, TitledBorder.TOP));
        inputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        inputArea.setText("http://127.0.0.1:8080/index.php" + System.lineSeparator());
        targetPanel.add(new JScrollPane(inputArea), BorderLayout.CENTER);

        JPanel tbtns = new JPanel(new GridLayout(5, 1, 0, 6));
        JButton bImport = new JButton("导入文件…");
        JButton bNorm = new JButton("去重/规范化");
        JButton bClear = new JButton("清空");
        bImport.addActionListener(e -> importFile());
        bNorm.addActionListener(e -> { inputArea.setText(String.join("\n", targets())); updateCount(); });
        bClear.addActionListener(e -> { inputArea.setText(""); updateCount(); });
        tbtns.add(bImport);
        tbtns.add(bNorm);
        tbtns.add(bClear);
        tbtns.add(lblCount);
        targetPanel.add(tbtns, BorderLayout.EAST);
        mid.add(targetPanel, BorderLayout.CENTER);
        top.add(mid, BorderLayout.CENTER);

        /* 选项 */
        JPanel opts = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        opts.add(new JLabel("检测级别:"));
        for (int i = 0; i < 3; i++) {
            JCheckBox cb = new JCheckBox(LEVEL_LABELS[i], i == 0);
            cb.setToolTipText(LEVEL_TIPS[i]);
            levelBoxes[i] = cb;
            opts.add(cb);
        }
        opts.add(Box.createHorizontalStrut(14));
        opts.add(new JLabel("并发"));
        opts.add(spWorkers);
        opts.add(new JLabel("超时(s)"));
        opts.add(spTimeout);
        opts.add(new JLabel("轮次"));
        opts.add(spRounds);
        opts.add(Box.createHorizontalStrut(20));
        btnStart.setFont(btnStart.getFont().deriveFont(Font.BOLD));
        btnStart.addActionListener(e -> start());
        btnStop.addActionListener(e -> stop());
        opts.add(btnStart);
        opts.add(btnStop);
        top.add(opts, BorderLayout.SOUTH);

        JPanel warn = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        JLabel w = new JLabel("⚠ 勾选「触发/泄漏/RCE」会故意让目标 worker 中止 —— 仅用于你拥有或获书面授权的目标");
        w.setForeground(new Color(0xC0392B));
        warn.add(w);

        JPanel prog = new JPanel(new BorderLayout(8, 0));
        prog.add(lblStat, BorderLayout.WEST);      // 状态放左侧，进度条吃掉剩余宽度，避免被裁
        prog.add(progress, BorderLayout.CENTER);

        JPanel northWrap = new JPanel(new BorderLayout(0, 4));
        northWrap.add(top, BorderLayout.CENTER);
        northWrap.add(warn, BorderLayout.SOUTH);
        root.add(northWrap, BorderLayout.NORTH);

        /* 中部：结果表 */
        JPanel center = new JPanel(new BorderLayout(0, 6));
        center.add(prog, BorderLayout.NORTH);
        table.setRowHeight(24);
        table.setFont(new Font("Microsoft YaHei UI", Font.PLAIN, 13));
        table.getTableHeader().setReorderingAllowed(false);
        table.getTableHeader().setFont(new Font("Microsoft YaHei UI", Font.BOLD, 13));
        table.getTableHeader().setPreferredSize(new Dimension(10, 32));
        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        int[] widths = {44, 360, 120, 100, 90, 120, 120, 80};
        for (int i = 0; i < widths.length; i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
            table.getColumnModel().getColumn(i).setMinWidth(Math.min(widths[i], 90));
        }
        table.addMouseListener(new MouseAdapter() {
            @Override public void mouseReleased(MouseEvent e) { showDetail(); }
        });
        center.add(new JScrollPane(table), BorderLayout.CENTER);
        root.add(center, BorderLayout.CENTER);

        /* 底部：详情 + 导出 */
        JPanel south = new JPanel(new BorderLayout(10, 0));
        JPanel detP = new JPanel(new BorderLayout());
        detP.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "详情", TitledBorder.LEFT, TitledBorder.TOP));
        detail.setEditable(false);
        detail.setFont(new Font("Microsoft YaHei UI", Font.PLAIN, 12));
        RcePanel.addTextPopup(detail);
        detP.add(new JScrollPane(detail), BorderLayout.CENTER);
        south.add(detP, BorderLayout.CENTER);

        JPanel exp = new JPanel(new GridLayout(3, 1, 0, 6));
        JButton bCsv = new JButton("导出 CSV");
        JButton bJson = new JButton("导出 JSON");
        JButton bClearLog = new JButton("清空日志");
        bCsv.addActionListener(e -> exportCsv());
        bJson.addActionListener(e -> exportJson());
        bClearLog.addActionListener(e -> detail.setText(""));
        exp.add(bCsv);
        exp.add(bJson);
        exp.add(bClearLog);
        south.add(exp, BorderLayout.EAST);
        root.add(south, BorderLayout.SOUTH);

        rcePanel = new RcePanel(this);
        tabs = new JTabbedPane();
        tabs.setBorder(javax.swing.BorderFactory.createEmptyBorder(6, 8, 0, 0));
        tabs.addTab("  检测  ", root);
        tabs.addTab("  RCE（内置全链）  ", rcePanel);
        setContentPane(tabs);
    }

    /* ------------------------------ 目标 ------------------------------ */
    List<String> targets() {
        LinkedHashSet<String> set = new LinkedHashSet<>();
        for (String line : inputArea.getText().split("\\R")) {
            String u = Probe.normalize(line);
            if (!u.isEmpty()) set.add(u);
        }
        return new ArrayList<>(set);
    }

    private void updateCount() { lblCount.setText(targets().size() + " 个目标"); }

    private void importFile() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("选择目标文件（每行一个，csv 取第一列）");
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        File f = fc.getSelectedFile();
        try {
            List<String> lines = new ArrayList<>();
            for (String line : Files.readAllLines(f.toPath(), StandardCharsets.UTF_8)) {
                String s = f.getName().toLowerCase().endsWith(".csv") && line.contains(",")
                        ? line.substring(0, line.indexOf(',')).trim() : line.trim();
                if (!s.isEmpty() && !s.startsWith("#")) lines.add(s);
            }
            inputArea.setText(String.join("\n", lines));
            updateCount();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "读取失败: " + ex.getMessage());
        }
    }

    /* ------------------------------ 执行 ------------------------------ */
    private void start() {
        List<String> ts = targets();
        if (ts.isEmpty()) { JOptionPane.showMessageDialog(this, "请粘贴目标（每行一个）或导入文件。"); return; }
        Set<String> levels = new LinkedHashSet<>();
        for (int i = 0; i < 3; i++) if (levelBoxes[i].isSelected()) levels.add(Probe.LEVELS[i]);
        if (levels.isEmpty()) { JOptionPane.showMessageDialog(this, "至少勾选一个检测级别。"); return; }
        if (levels.stream().anyMatch(l -> !l.equals("fingerprint"))) {
            int r = JOptionPane.showConfirmDialog(this,
                    "触发/泄漏/RCE 检测会故意让目标 worker 中止。\n\n"
                            + "请确认这些目标是你拥有或已获得书面授权的。\n继续？",
                    "确认授权", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (r != JOptionPane.YES_OPTION) return;
        }

        model.setRowCount(0);
        results.clear();
        done.set(0);
        stopped.set(false);
        total = ts.size();
        progress.setMaximum(ts.size());
        progress.setValue(0);
        lblStat.setText("0/" + total);
        btnStart.setEnabled(false);
        btnStop.setEnabled(true);

        int rounds = (Integer) spRounds.getValue();
        int timeout = (Integer) spTimeout.getValue();
        pool = Executors.newFixedThreadPool((Integer) spWorkers.getValue());
        for (int i = 0; i < ts.size(); i++) {
            String url = ts.get(i);
            model.addRow(new Object[]{i + 1, url, "…", "", "", "", "", ""});
            final int idx = i;
            pool.submit(() -> {
                if (stopped.get()) return;
                Probe.Result res;
                try {
                    res = Probe.probe(url, levels, rounds, timeout);
                } catch (Exception ex) {
                    res = new Probe.Result();
                    res.url = url;
                    res.error = ex.getClass().getSimpleName() + ": " + ex.getMessage();
                }
                Probe.Result f = res;
                SwingUtilities.invokeLater(() -> applyRow(idx, f));
            });
        }
    }

    private void applyRow(int idx, Probe.Result res) {
        while (results.size() < idx) results.add(null);
        if (results.size() == idx) results.add(res); else results.set(idx, res);

        String ver = res.fp != null && res.fp.version != null && !res.fp.version.isEmpty()
                ? res.fp.version.replace("PHP/", "") : "-";
        String fp = res.fp == null ? "-" : switch (res.fp.verdict) {
            case "vulnerable" -> "漏洞版";
            case "patched" -> "已修复";
            case "unknown-branch" -> "版本未知";
            default -> "无 banner";
        };
        String tr = res.tr == null ? "-" : (res.tr.hit ? "命中" : "未命中");
        String lk = res.lk == null ? "-" : switch (res.lk.verdict) {
            case "leak" -> "泄漏!";
            case "differential" -> "有差异";
            case "corruption-or-exit" -> "worker 死亡";
            case "error" -> "出错";
            default -> "无差异";
        };
        String rc = res.rc == null ? "-" : (res.rc.hit ? "RCE 成功!" : (res.rc.ok ? "未命中" : "未配置"));
        int r = idx;
        model.setValueAt(ver, r, 2);
        model.setValueAt(fp, r, 3);
        model.setValueAt(tr, r, 4);
        model.setValueAt(lk, r, 5);
        model.setValueAt(rc, r, 6);
        model.setValueAt(String.format("%.1fs", res.wall), r, 7);

        int d = done.incrementAndGet();
        progress.setValue(d);
        lblStat.setText(d + "/" + total);
        if (d >= total) finish();
    }

    private String tagOf(Probe.Result res) {
        if (res == null) return "gray";
        if ((res.rc != null && res.rc.hit) || (res.lk != null && "leak".equals(res.lk.verdict))
                || (res.tr != null && res.tr.hit) || (res.fp != null && "vulnerable".equals(res.fp.verdict))) return "red";
        if (res.fp != null && "patched".equals(res.fp.verdict)) return "green";
        if (res.fp != null && ("unknown".equals(res.fp.verdict) || "unknown-branch".equals(res.fp.verdict))) return "orange";
        return "gray";
    }

    private void finish() {
        btnStart.setEnabled(true);
        btnStop.setEnabled(false);
        if (pool != null) { pool.shutdown(); pool = null; }
        long bad = results.stream().filter(x -> x != null && "red".equals(tagOf(x))).count();
        lblStat.setText("完成 " + results.size() + " · 可疑 " + bad);
        table.repaint();
    }

    private void stop() {
        stopped.set(true);
        if (pool != null) { pool.shutdownNow(); pool = null; }
        btnStart.setEnabled(true);
        btnStop.setEnabled(false);
        lblStat.setText("已停止");
    }

    private void stopState() { btnStop.setEnabled(false); }

    /* ------------------------------ 详情 / 导出 ------------------------------ */
    private void showDetail() {
        int row = table.getSelectedRow();
        if (row < 0 || row >= results.size() || results.get(row) == null) return;
        Probe.Result res = results.get(row);
        StringBuilder sb = new StringBuilder();
        sb.append("目标: ").append(res.url).append('\n');
        sb.append("时间: ").append(res.ts).append("   总耗时: ").append(String.format("%.1fs", res.wall)).append("\n\n");
        if (res.fp != null) {
            sb.append("[指纹] ").append(res.fp.version.isEmpty() ? "无 banner" : res.fp.version)
              .append("  ").append(res.fp.server == null ? "" : res.fp.server).append('\n');
            sb.append("       ").append(res.fp.verdict).append(" — ").append(res.fp.note).append('\n');
        }
        if (res.tr != null) {
            sb.append("[触发] hit=").append(res.tr.hit).append("  worker存活=").append(res.tr.aliveAfter)
              .append(String.format("  %.1fs", res.tr.seconds)).append('\n');
            sb.append("       ").append(res.tr.fatal.isEmpty() ? res.tr.note : res.tr.fatal).append('\n');
        }
        if (res.lk != null) {
            sb.append("[泄漏] verdict=").append(res.lk.verdict).append("  control=").append(res.lk.control).append('\n');
            if (!res.lk.samples.isEmpty()) {
                List<String> tail = res.lk.samples.subList(Math.max(0, res.lk.samples.size() - 3), res.lk.samples.size());
                sb.append("       样本: ").append(String.join(", ", tail)).append('\n');
            }
            if (res.lk.decodedLen > 0) sb.append("       解码长度=").append(res.lk.decodedLen)
                    .append("  可读串=").append(res.lk.strings).append('\n');
            if (!res.lk.note.isEmpty()) sb.append("       ").append(res.lk.note).append('\n');
        }
        if (res.rc != null) {
            sb.append("[RCE] hit=").append(res.rc.hit).append(String.format("  %.1fs", res.rc.seconds)).append('\n');
            sb.append("      ").append(res.rc.detail).append('\n');
        }
        if (res.error != null) sb.append("[错误] ").append(res.error).append('\n');
        detail.setText(sb.toString());
    }

    private void exportCsv() {
        if (results.isEmpty()) return;
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File("p2s-detection-" + System.currentTimeMillis() + ".csv"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        try (PrintWriter w = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(fc.getSelectedFile()), StandardCharsets.UTF_8))) {
            w.print('\ufeff');
            w.println("目标,版本,指纹结论,触发,worker存活,泄漏判定,RCE,RCE详情,总耗时(s)");
            for (Probe.Result r : results) {
                if (r == null) continue;
                w.println(String.join(",",
                        q(r.url),
                        q(r.fp == null ? "" : r.fp.version),
                        q(r.fp == null ? "" : r.fp.verdict),
                        q(r.tr == null ? "" : String.valueOf(r.tr.hit)),
                        q(r.tr == null ? "" : String.valueOf(r.tr.aliveAfter)),
                        q(r.lk == null ? "" : r.lk.verdict),
                        q(r.rc == null ? "" : String.valueOf(r.rc.hit)),
                        q(r.rc == null ? "" : r.rc.detail),
                        q(String.format("%.1f", r.wall))));
            }
            JOptionPane.showMessageDialog(this, "已导出:\n" + fc.getSelectedFile());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "导出失败: " + ex.getMessage());
        }
    }

    /* ------------------------------ 供自检/截图使用 ------------------------------ */
    public void setTargets(String text) { inputArea.setText(text); updateCount(); }

    /** 给 RCE 页用：取检测页第一行目标 */
    public String firstTarget() {
        java.util.List<String> ts = targets();
        return ts.isEmpty() ? null : ts.get(0);
    }

    /** 截图/自检用：切到 RCE 页 */
    public void showRceTab() { if (tabs != null) tabs.setSelectedIndex(1); }

    public RcePanel rcePanel() { return rcePanel; }

    public void selectFingerprintOnly() { for (int i = 0; i < 3; i++) levelBoxes[i].setSelected(i == 0); }

    public void startFromCode() { start(); }

    public int resultCount() { return results.size(); }

    public void selectFirstRow() {
        if (model.getRowCount() > 0) { table.setRowSelectionInterval(0, 0); showDetail(); }
    }

    private static String q(String s) {
        if (s == null) return "\"\"";
        return "\"" + s.replace("\"", "\"\"") + "\"";
    }

    private void exportJson() {
        if (results.isEmpty()) return;
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File("p2s-detection-" + System.currentTimeMillis() + ".json"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        try (PrintWriter w = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(fc.getSelectedFile()), StandardCharsets.UTF_8))) {
            w.println(toJson(results));
            JOptionPane.showMessageDialog(this, "已导出:\n" + fc.getSelectedFile());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "导出失败: " + ex.getMessage());
        }
    }

    /** 手写最小 JSON（避免引入第三方库）。 */
    public static String toJson(List<Probe.Result> list) {
        StringBuilder sb = new StringBuilder("[\n");
        for (int i = 0; i < list.size(); i++) {
            Probe.Result r = list.get(i);
            if (r == null) continue;
            sb.append("  {")
              .append("\"url\":").append(js(r.url)).append(',')
              .append("\"ts\":").append(js(r.ts)).append(',')
              .append("\"wall\":").append(String.format("%.1f", r.wall)).append(',');
            if (r.fp != null) sb.append("\"fingerprint\":{\"version\":").append(js(r.fp.version))
                    .append(",\"verdict\":").append(js(r.fp.verdict))
                    .append(",\"note\":").append(js(r.fp.note))
                    .append(",\"server\":").append(js(r.fp.server)).append("},");
            if (r.tr != null) sb.append("\"trigger\":{\"hit\":").append(r.tr.hit)
                    .append(",\"alive_after\":").append(r.tr.aliveAfter)
                    .append(",\"fatal\":").append(js(r.tr.fatal))
                    .append(",\"seconds\":").append(String.format("%.1f", r.tr.seconds)).append("},");
            if (r.lk != null) sb.append("\"leak\":{\"verdict\":").append(js(r.lk.verdict))
                    .append(",\"control\":").append(js(r.lk.control))
                    .append(",\"decoded_len\":").append(r.lk.decodedLen).append("},");
            if (r.rc != null) sb.append("\"rce\":{\"hit\":").append(r.rc.hit)
                    .append(",\"detail\":").append(js(r.rc.detail)).append("},");
            if (sb.charAt(sb.length() - 1) == ',') sb.setLength(sb.length() - 1);
            sb.append("}").append(i == list.size() - 1 ? "" : ",").append('\n');
        }
        return sb.append("]").toString();
    }

    private static String js(String s) {
        if (s == null) return "\"\"";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "") + "\"";
    }
}
