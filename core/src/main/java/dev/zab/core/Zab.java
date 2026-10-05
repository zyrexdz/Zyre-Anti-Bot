package dev.zab.core;

import io.netty.util.concurrent.FastThreadLocal;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.IntSupplier;

public final class Zab {
    public static final String PREFIX = "\u00a7e\u00a7lZAB \u00a78| ";

    private static final int BUCKETS = 20;
    private static final long SECOND = 1_000_000_000L;
    private static final long BUCKET_NANOS = 50_000_000L;
    private static final List<String> SUBCOMMANDS = Arrays.asList("verbose", "antiafk", "blacklist", "barely", "peak", "stats", "reset", "unblock");

    private static final int C_CPS = 0, C_IPS = 1, C_LOGINS = 2, C_PINGS = 3, C_HANDSHAKES = 4, C_BLOCKED = 5, C_BYTES = 6, C_MOTDS = 7;
    private static final int NUM_COUNTERS = 8;

    private static final class ThreadCounters {
        final long[] current = new long[NUM_COUNTERS];
        final long[] drained = new long[NUM_COUNTERS];
    }

    private final ConcurrentLinkedQueue<ThreadCounters> allLocals = new ConcurrentLinkedQueue<>();
    private final FastThreadLocal<ThreadCounters> tracked = new FastThreadLocal<ThreadCounters>() {
        @Override
        protected ThreadCounters initialValue() {
            ThreadCounters tc = new ThreadCounters();
            allLocals.add(tc);
            return tc;
        }
    };

    private volatile long cachedNanos;
    private volatile long cachedMillis;
    private long lastTickNanos;

    private static final class Rate {
        final long[] buckets = new long[BUCKETS];
        final String label;
        int cur;
        long value;
        long peak;
        long announced;
        long pending;

        Rate(String label) {
            this.label = label;
        }

        void slide(long deltaNanos, boolean peakMode) {
            int next = (cur + 1) % BUCKETS;
            buckets[next] = pending;
            cur = next;

            long sum = 0;
            for (int i = 0; i < BUCKETS; i++) sum += buckets[i];

            if (peakMode && deltaNanos > 0) {
                long instant = pending * SECOND / deltaNanos;
                value = Math.max(sum, instant);
            } else {
                value = sum;
            }

            if (value > peak) peak = value;
            pending = 0;
        }
    }

    private static final class IpRecord {
        long windowStart;
        int count;
        long lastSeen;
    }

    private static final class BlacklistEntry {
        final long untilMillis;
        volatile long windowStart;

        BlacklistEntry(long untilMillis, long windowStart) {
            this.untilMillis = untilMillis;
            this.windowStart = windowStart;
        }
    }

    private final Rate cps = new Rate("Connections per second");
    private final Rate ips = new Rate("IP addresses per second");
    private final Rate logins = new Rate("Logins per second");
    private final Rate pings = new Rate("Pings per second");
    private final Rate motds = new Rate("MOTDs per second");
    private final Rate handshakes = new Rate("Handshakes per second");
    private final Rate blocked = new Rate("Blocked per second");
    private final Rate bytes = new Rate("Bytes per second");
    private final Rate[] shown = {cps, ips, logins, pings, motds, handshakes};
    private final Rate[] all = {cps, ips, logins, pings, motds, handshakes, blocked, bytes};

    private final ConcurrentHashMap<String, IpRecord> ipRecords = new ConcurrentHashMap<>(4096, 0.5f, 64);
    private final ConcurrentHashMap<String, BlacklistEntry> blacklist = new ConcurrentHashMap<>(1024, 0.5f, 32);
    private final Map<String, Long> pending = new ConcurrentHashMap<>();
    private final Set<String> verified = ConcurrentHashMap.newKeySet();
    private final ConcurrentLinkedQueue<String> events = new ConcurrentLinkedQueue<>();
    private final ScheduledExecutorService ticker = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "ZAB-Ticker");
        t.setDaemon(true);
        return t;
    });

    private final int maxPerIp;
    private final long blockMillis;
    private final int attackCps;
    private final long attackEnd;
    private final boolean attackVerify;
    private final int minPeak;
    private final Set<String> trusted;
    private final File verifiedFile;
    private final Consumer<String> log;
    private final AntiAfkBot antiAfk;

    private volatile boolean attack;
    private volatile boolean blacklistOn = true;
    private volatile boolean barelyMode = false;
    private volatile boolean peakMode = false;
    private long attackUntil;
    private int ticks;

    private volatile String cachedBar = "";
    private long lastBarCps = -1;
    private long lastBarIps, lastBarLogins, lastBarPings, lastBarMotds, lastBarHs, lastBarBlocked;
    private boolean lastBarAttack;

    public Zab(int maxPerIp, int blockMinutes, int attackCps, int attackEndSeconds, boolean attackVerify,
               int minPeak, Set<String> trusted, File dataDir, Consumer<String> log, IntSupplier defaultPort) {
        this.maxPerIp = maxPerIp;
        this.blockMillis = blockMinutes * 60_000L;
        this.attackCps = attackCps;
        this.attackEnd = attackEndSeconds * SECOND;
        this.attackVerify = attackVerify;
        this.minPeak = minPeak;
        this.trusted = trusted;
        this.verifiedFile = new File(dataDir, "verified.txt");
        this.log = log;
        this.antiAfk = new AntiAfkBot(log, defaultPort);
    }

    public void start() {
        try {
            if (verifiedFile.exists()) {
                verified.addAll(Files.readAllLines(verifiedFile.toPath(), StandardCharsets.UTF_8));
            }
        } catch (IOException err) {
            log.accept("Failed to load verified.txt: " + err.getMessage());
        }
        cachedNanos = System.nanoTime();
        cachedMillis = System.currentTimeMillis();
        lastTickNanos = cachedNanos;
        attackUntil = cachedNanos;
        tuneKernelIfRoot();
        ticker.scheduleAtFixedRate(this::tick, 50, 50, TimeUnit.MILLISECONDS);
    }

    private void tuneKernelIfRoot() {
        if (!System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("linux")) {
            return;
        }
        boolean isRoot = "root".equals(System.getProperty("user.name"));
        if (!isRoot) {
            try {
                File procSelf = new File("/proc/self/status");
                if (procSelf.exists()) {
                    for (String line : Files.readAllLines(procSelf.toPath())) {
                        if (line.startsWith("Uid:")) {
                            String[] parts = line.split("\\s+");
                            if (parts.length > 1 && "0".equals(parts[1])) {
                                isRoot = true;
                                break;
                            }
                        }
                    }
                }
            } catch (Throwable ignored) {
            }
        }
        if (!isRoot) {
            return;
        }

        int tuned = 0;
        tuned += writeProc("/proc/sys/net/core/somaxconn", "65535");
        tuned += writeProc("/proc/sys/net/ipv4/tcp_max_syn_backlog", "65535");
        tuned += writeProc("/proc/sys/net/ipv4/tcp_tw_reuse", "1");
        tuned += writeProc("/proc/sys/net/ipv4/tcp_fin_timeout", "15");
        if (tuned > 0) {
            log.accept("Root access detected: tuned " + tuned + " Linux kernel TCP socket parameter(s).");
        }
    }

    private static int writeProc(String path, String value) {
        try {
            File f = new File(path);
            if (f.canWrite()) {
                Files.write(f.toPath(), (value + "\n").getBytes(StandardCharsets.US_ASCII));
                return 1;
            }
        } catch (Throwable ignored) {
        }
        return 0;
    }

    public void stop() {
        ticker.shutdownNow();
        antiAfk.stop();
        try {
            verifiedFile.getParentFile().mkdirs();
            Files.write(verifiedFile.toPath(), verified, StandardCharsets.UTF_8);
        } catch (IOException err) {
            log.accept("Failed to save verified.txt: " + err.getMessage());
        }
    }

    public AntiAfkBot getAntiAfk() {
        return antiAfk;
    }

    public boolean checks(String ip) {
        return blacklistOn && !trusted.contains(ip);
    }

    public boolean isBlacklistOn() {
        return blacklistOn;
    }

    public boolean isBarely() {
        return barelyMode;
    }

    public void setBarely(boolean barely) {
        this.barelyMode = barely;
        if (barely) {
            this.blacklistOn = true;
        }
    }

    public boolean isPeak() {
        return peakMode;
    }

    public void setPeak(boolean peak) {
        this.peakMode = peak;
    }

    public boolean connect(String ip) {
        ThreadCounters tc = tracked.get();
        tc.current[C_CPS]++;

        if (!blacklistOn || trusted.contains(ip)) {
            return true;
        }

        long now = cachedNanos;
        BlacklistEntry bl = blacklist.get(ip);
        if (bl != null) {
            if (bl.untilMillis > cachedMillis) {
                if (now - bl.windowStart >= SECOND) {
                    bl.windowStart = now;
                    tc.current[C_IPS]++;
                }
                tc.current[C_BLOCKED]++;
                return false;
            }
            blacklist.remove(ip);
        }

        IpRecord rec = ipRecords.get(ip);
        if (rec == null) {
            rec = new IpRecord();
            rec.windowStart = now;
            rec.count = 1;
            rec.lastSeen = now;
            IpRecord existing = ipRecords.putIfAbsent(ip, rec);
            if (existing != null) {
                rec = existing;
                rec.count++;
                rec.lastSeen = now;
            }
            tc.current[C_IPS]++;
        } else {
            if (now - rec.windowStart >= SECOND) {
                rec.windowStart = now;
                rec.count = 1;
                tc.current[C_IPS]++;
            } else {
                rec.count++;
            }
            rec.lastSeen = now;
        }

        if (rec.count > maxPerIp) {
            punish(ip);
            return false;
        }
        return true;
    }

    public void punish(String ip) {
        blacklist.put(ip, new BlacklistEntry(cachedMillis + blockMillis, cachedNanos));
        ipRecords.remove(ip);
        tracked.get().current[C_BLOCKED]++;
    }

    public boolean needsReconnect(String ip) {
        if (!attack || !attackVerify || verified.contains(ip)) {
            return false;
        }
        long now = cachedNanos;
        Long first = pending.get(ip);
        if (first != null && now - first >= SECOND * 3 / 2 && now - first <= SECOND * 60) {
            pending.remove(ip);
            return false;
        }
        pending.put(ip, now);
        return true;
    }

    public void ping() {
        tracked.get().current[C_PINGS]++;
    }

    public void motd() {
        tracked.get().current[C_MOTDS]++;
    }

    public void handshake() {
        tracked.get().current[C_HANDSHAKES]++;
    }

    public void login() {
        tracked.get().current[C_LOGINS]++;
    }

    public void addBytes(int n) {
        tracked.get().current[C_BYTES] += n;
    }

    public void verify(String ip) {
        verified.add(ip);
        blacklist.remove(ip);
        pending.remove(ip);
    }

    public String pollEvent() {
        return events.poll();
    }

    private void tick() {
        try {
            long now = System.nanoTime();
            long delta = lastTickNanos == 0 ? BUCKET_NANOS : (now - lastTickNanos);
            lastTickNanos = now;

            cachedNanos = now;
            cachedMillis = System.currentTimeMillis();

            for (ThreadCounters tc : allLocals) {
                long curCps = tc.current[C_CPS];
                cps.pending += (curCps - tc.drained[C_CPS]);
                tc.drained[C_CPS] = curCps;

                long curIps = tc.current[C_IPS];
                ips.pending += (curIps - tc.drained[C_IPS]);
                tc.drained[C_IPS] = curIps;

                long curLogins = tc.current[C_LOGINS];
                logins.pending += (curLogins - tc.drained[C_LOGINS]);
                tc.drained[C_LOGINS] = curLogins;

                long curPings = tc.current[C_PINGS];
                pings.pending += (curPings - tc.drained[C_PINGS]);
                tc.drained[C_PINGS] = curPings;

                long curMotds = tc.current[C_MOTDS];
                motds.pending += (curMotds - tc.drained[C_MOTDS]);
                tc.drained[C_MOTDS] = curMotds;

                long curHs = tc.current[C_HANDSHAKES];
                handshakes.pending += (curHs - tc.drained[C_HANDSHAKES]);
                tc.drained[C_HANDSHAKES] = curHs;

                long curBlocked = tc.current[C_BLOCKED];
                blocked.pending += (curBlocked - tc.drained[C_BLOCKED]);
                tc.drained[C_BLOCKED] = curBlocked;

                long curBytes = tc.current[C_BYTES];
                bytes.pending += (curBytes - tc.drained[C_BYTES]);
                tc.drained[C_BYTES] = curBytes;
            }

            for (Rate r : all) r.slide(delta, peakMode);

            if (cps.value >= attackCps) {
                attackUntil = now + attackEnd;
            }
            boolean on = attackUntil - now > 0;
            if (on != attack) {
                attack = on;
                if (!on) {
                    pending.clear();
                    emit("\u00a7aAttack has ended.");
                } else if (blacklistOn && attackVerify) {
                    emit("\u00a7cUnder attack, new players must reconnect to verify.");
                } else {
                    emit("\u00a7cUnder attack.");
                }
            }

            if (cps.value != lastBarCps || ips.value != lastBarIps || logins.value != lastBarLogins
                    || pings.value != lastBarPings || motds.value != lastBarMotds || handshakes.value != lastBarHs
                    || blocked.value != lastBarBlocked || attack != lastBarAttack) {
                lastBarCps = cps.value;
                lastBarIps = ips.value;
                lastBarLogins = logins.value;
                lastBarPings = pings.value;
                lastBarMotds = motds.value;
                lastBarHs = handshakes.value;
                lastBarBlocked = blocked.value;
                lastBarAttack = attack;
                cachedBar = buildBar();
            }

            for (Rate r : shown) {
                long peak = r.peak;
                if (peak > r.announced && peak >= minPeak) {
                    emit("\u00a77" + r.label + " peak: " + color(r.announced) + fmt(r.announced)
                            + " \u00a77\u2192 " + color(peak) + fmt(peak));
                    r.announced = peak;
                }
            }

            if (++ticks % 20 != 0) {
                return;
            }

            long ms = cachedMillis;
            blacklist.values().removeIf(e -> e.untilMillis <= ms);
            pending.values().removeIf(t -> now - t > SECOND * 60);
            ipRecords.values().removeIf(r -> now - r.lastSeen > SECOND * 5);
        } catch (RuntimeException err) {
            log.accept("Tick error: " + err.getMessage());
        }
    }

    private void emit(String line) {
        events.add(PREFIX + line);
        log.accept((PREFIX + line).replaceAll("\u00a7.", ""));
    }

    private static String fmt(long n) {
        return String.format(Locale.US, "%,d", n);
    }

    private static String color(long n) {
        if (n < 10) return "\u00a7a";
        if (n < 100) return "\u00a7e";
        if (n < 1000) return "\u00a76";
        if (n < 10000) return "\u00a7c";
        return "\u00a74";
    }

    private static String stat(String name, long n) {
        return "\u00a77" + name + ": " + color(n) + fmt(n);
    }

    private static String onOff(boolean on) {
        return on ? "\u00a7aon" : "\u00a7coff";
    }

    private String buildBar() {
        StringBuilder sb = new StringBuilder(220).append(PREFIX)
                .append(stat("CPS", cps.value)).append(" \u00a78\u2022 ")
                .append(stat("IPSEC", ips.value)).append(" \u00a78\u2022 ")
                .append(stat("LOGINS", logins.value)).append(" \u00a78\u2022 ")
                .append(stat("PINGS", pings.value)).append(" \u00a78\u2022 ")
                .append(stat("MOTD'S", motds.value)).append(" \u00a78\u2022 ")
                .append(stat("HANDSHAKE/S", handshakes.value));
        if (blocked.value > 0) {
            sb.append(" \u00a78\u2022 ").append(stat("BLOCKED", blocked.value));
        }
        if (attack) {
            sb.append(" \u00a78\u2022 \u00a74\u00a7lATTACK");
        } else if (cps.value == 0 && ips.value == 0) {
            sb.append(" \u00a78\u2022 \u00a75Waiting for new attacks to arrive\u2026");
        }
        return sb.toString();
    }

    public String actionBar() {
        return cachedBar;
    }

    public List<String> command(String[] args) {
        String sub = args.length == 0 ? "" : args[0].toLowerCase(Locale.ROOT);
        String arg = args.length < 2 ? "" : args[1].toLowerCase(Locale.ROOT);
        switch (sub) {
            case "blacklist":
                if (!arg.equals("on") && !arg.equals("off") && !arg.equals("barely") && !arg.equals("peak")) {
                    String cur = !blacklistOn ? "\u00a7coff" : (barelyMode ? "\u00a7ebarely" : (peakMode ? "\u00a7cpeak" : "\u00a7aon"));
                    return Collections.singletonList(PREFIX + "\u00a77Blacklist is currently " + cur
                            + "\u00a77. Use \u00a7f/zab blacklist <on|off|barely|peak>");
                }
                if (arg.equals("peak")) {
                    blacklistOn = true;
                    barelyMode = false;
                    peakMode = true;
                    return Collections.singletonList(PREFIX + "\u00a77Blacklist is now \u00a7cpeak\u00a77. Fast micro-window peak analyzer enabled.");
                }
                if (arg.equals("barely")) {
                    blacklistOn = true;
                    barelyMode = true;
                    peakMode = false;
                    return Collections.singletonList(PREFIX + "\u00a77Blacklist is now \u00a7ebarely\u00a77. Probing packets before blocking to show raw handshakes/logins/pings.");
                }
                if (arg.equals("on")) {
                    blacklistOn = true;
                    barelyMode = false;
                    peakMode = false;
                    return Collections.singletonList(PREFIX + "\u00a77Blacklist is now \u00a7aon\u00a77. Standard high-burst mode (raw peak CPS).");
                }
                blacklistOn = false;
                barelyMode = false;
                peakMode = false;
                return Collections.singletonList(PREFIX + "\u00a77Blacklist is now \u00a7coff\u00a77. Connections will not be blocked.");
            case "barely":
                if (arg.equals("on")) {
                    blacklistOn = true;
                    barelyMode = true;
                    peakMode = false;
                } else if (arg.equals("off")) {
                    barelyMode = false;
                } else {
                    barelyMode = !barelyMode;
                    if (barelyMode) {
                        blacklistOn = true;
                        peakMode = false;
                    }
                }
                return Collections.singletonList(PREFIX + (barelyMode
                        ? "\u00a77Blacklist is now \u00a7ebarely\u00a77. Probing packets before blocking to show raw handshakes/logins/pings."
                        : "\u00a77Blacklist is now \u00a7aon\u00a77. Dropping bad connections instantly at accept for maximum CPS."));
            case "peak":
                if (arg.equals("on")) {
                    peakMode = true;
                } else if (arg.equals("off")) {
                    peakMode = false;
                } else {
                    peakMode = !peakMode;
                }
                return Collections.singletonList(PREFIX + (peakMode
                        ? "\u00a77Peak mode is now \u00a7con\u00a77. Fast micro-window peak analyzer enabled."
                        : "\u00a77Peak mode is now \u00a7coff\u00a77. Standard 1-second rolling window."));
            case "stats":
                List<String> lines = new ArrayList<>();
                for (Rate r : shown) {
                    lines.add(PREFIX + "\u00a77" + r.label + ": " + color(r.value) + fmt(r.value)
                            + " \u00a78(\u00a77peak " + color(r.peak) + fmt(r.peak) + "\u00a78)");
                }
                lines.add(PREFIX + "\u00a77Blocked/s: " + color(blocked.value) + fmt(blocked.value)
                        + " \u00a78(\u00a77peak " + color(blocked.peak) + fmt(blocked.peak) + "\u00a78)");
                lines.add(PREFIX + "\u00a77Bytes/s: " + color(bytes.value) + fmt(bytes.value));
                String bl = !blacklistOn ? "\u00a7coff" : (barelyMode ? "\u00a7ebarely" : (peakMode ? "\u00a7cpeak" : "\u00a7aon"));
                lines.add(PREFIX + "\u00a77Blacklist: " + bl
                        + " \u00a78| \u00a77Attack: " + (attack ? "\u00a7cyes" : "\u00a7ano")
                        + " \u00a78| \u00a77Blocked IPs: \u00a7f" + blacklist.size()
                        + " \u00a78| \u00a77Verified IPs: \u00a7f" + verified.size());
                return lines;
            case "reset":
                ticker.execute(() -> {
                    for (Rate r : shown) {
                        r.peak = r.value;
                        r.announced = 0;
                    }
                });
                return Collections.singletonList(PREFIX + "\u00a77Peaks have been reset.");
            case "unblock":
                if (arg.isEmpty()) {
                    return Collections.singletonList(PREFIX + "\u00a77Usage: \u00a7f/zab unblock <ip>");
                }
                return Collections.singletonList(PREFIX + (blacklist.remove(arg) != null
                        ? "\u00a7aUnblocked \u00a7f" + arg : "\u00a7f" + arg + " \u00a77is not blocked."));
            case "antiafk":
                if (arg.equals("off")) {
                    return Collections.singletonList(antiAfk.stop());
                }
                if (arg.equals("status")) {
                    return Collections.singletonList(PREFIX + "\u00a77Anti-AFK bot status: " + antiAfk.status());
                }
                int customPort = 0;
                for (int i = 1; i < args.length; i++) {
                    String a = args[i].toLowerCase(Locale.ROOT);
                    if (a.equals("on")) continue;
                    if (a.contains(".") || AntiAfkBot.versionToProtocol(a) > 0) {
                        antiAfk.setTargetVersion(a);
                        continue;
                    }
                    try {
                        int num = Integer.parseInt(a);
                        if (num > 1000) {
                            customPort = num;
                        } else if (num > 0) {
                            antiAfk.setTargetProtocol(num);
                        }
                    } catch (NumberFormatException ignored) {
                    }
                }
                if (arg.equals("on") || customPort > 0) {
                    return Collections.singletonList(antiAfk.start(customPort));
                }
                return Collections.singletonList(antiAfk.toggle());
            default:
                return Arrays.asList(
                        PREFIX + "\u00a7f/zab verbose [top|down] \u00a78- \u00a77toggle the live counter",
                        PREFIX + "\u00a7f/zab antiafk [on|off|status] [version] \u00a78- \u00a77keep server online with ZABAFK bot",
                        PREFIX + "\u00a7f/zab blacklist <on|off|barely|peak> \u00a78- \u00a77toggle bot blocking (peak: fast micro-window peak detection)",
                        PREFIX + "\u00a7f/zab stats \u00a78- \u00a77view current rates and peaks",
                        PREFIX + "\u00a7f/zab reset \u00a78- \u00a77reset all peak records",
                        PREFIX + "\u00a7f/zab unblock <ip> \u00a78- \u00a77unblock an IP address");
        }
    }

    public static List<String> complete(String[] args) {
        List<String> options;
        if (args.length == 1) {
            options = SUBCOMMANDS;
        } else if (args.length == 2 && args[0].equalsIgnoreCase("blacklist")) {
            options = Arrays.asList("on", "off", "barely", "peak");
        } else if (args.length == 2 && (args[0].equalsIgnoreCase("barely") || args[0].equalsIgnoreCase("peak"))) {
            options = Arrays.asList("on", "off");
        } else if (args.length == 2 && args[0].equalsIgnoreCase("antiafk")) {
            options = Arrays.asList("on", "off", "status", "1.16.5", "1.20.4", "1.8.8");
        } else if (args.length == 2 && args[0].equalsIgnoreCase("verbose")) {
            options = Arrays.asList("top", "down");
        } else {
            return Collections.emptyList();
        }
        String typed = args[args.length - 1].toLowerCase(Locale.ROOT);
        List<String> out = new ArrayList<>();
        for (String s : options) {
            if (s.startsWith(typed)) {
                out.add(s);
            }
        }
        return out;
    }
}
