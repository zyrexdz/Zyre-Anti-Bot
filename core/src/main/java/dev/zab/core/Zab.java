package dev.zab.core;

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
import java.util.concurrent.atomic.AtomicLongArray;
import java.util.function.Consumer;
import java.util.function.IntSupplier;

public final class Zab {
    public static final String PREFIX = "\u00a7e\u00a7lZAB \u00a78| ";

    private static final int BUCKETS = 20;
    private static final long SECOND = 1_000_000_000L;
    private static final List<String> SUBCOMMANDS = Arrays.asList("verbose", "antiafk", "blacklist", "stats", "reset", "unblock");

    private static final class Rate {
        final AtomicLongArray buckets = new AtomicLongArray(BUCKETS);
        final String label;
        volatile int cur;
        volatile long value;
        volatile long peak;
        long announced;

        Rate(String label) {
            this.label = label;
        }

        void add() {
            buckets.incrementAndGet(cur);
        }

        void slide() {
            int next = (cur + 1) % BUCKETS;
            buckets.set(next, 0);
            cur = next;
            long sum = 0;
            for (int i = 0; i < BUCKETS; i++) {
                sum += buckets.get(i);
            }
            value = sum;
            if (value > peak) {
                peak = value;
            }
        }
    }

    private static final class IpRecord {
        long windowStart;
        int count;
        long lastSeen;
    }

    private final Rate cps = new Rate("Connections per second");
    private final Rate ips = new Rate("IP addresses per second");
    private final Rate logins = new Rate("Logins per second");
    private final Rate pings = new Rate("Pings per second");
    private final Rate handshakes = new Rate("Handshakes per second");
    private final Rate blocked = new Rate("Blocked per second");
    private final Rate[] shown = {cps, ips, logins, pings, handshakes};

    private final Map<String, IpRecord> ipRecords = new ConcurrentHashMap<>();
    private final Map<String, Long> blacklist = new ConcurrentHashMap<>();
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
    private long attackUntil;
    private int ticks;

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
        attackUntil = System.nanoTime();
        ticker.scheduleAtFixedRate(this::tick, 50, 50, TimeUnit.MILLISECONDS);
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

    public boolean connect(String ip) {
        cps.add();

        boolean checking = blacklistOn && !trusted.contains(ip);

        // fast reject — skip all tracking for already-blacklisted IPs
        if (checking) {
            Long until = blacklist.get(ip);
            if (until != null) {
                if (until > System.currentTimeMillis()) {
                    blocked.add();
                    return false;
                }
                blacklist.remove(ip);
            }
        }

        long now = System.nanoTime();
        IpRecord rec = ipRecords.compute(ip, (k, v) -> {
            if (v == null) {
                v = new IpRecord();
                v.windowStart = now;
                ips.add();
            } else if (now - v.windowStart >= SECOND) {
                v.windowStart = now;
                v.count = 0;
                ips.add();
            }
            v.count++;
            v.lastSeen = now;
            return v;
        });

        if (!checking) {
            return true;
        }
        if (rec.count > maxPerIp) {
            punish(ip);
            return false;
        }
        return true;
    }

    public void punish(String ip) {
        blacklist.put(ip, System.currentTimeMillis() + blockMillis);
        blocked.add();
    }

    public boolean needsReconnect(String ip) {
        if (!attack || !attackVerify || verified.contains(ip)) {
            return false;
        }
        long now = System.nanoTime();
        Long first = pending.get(ip);
        if (first != null && now - first >= SECOND * 3 / 2 && now - first <= SECOND * 60) {
            pending.remove(ip);
            return false;
        }
        pending.put(ip, now);
        return true;
    }

    public void ping() {
        pings.add();
    }

    public void handshake() {
        handshakes.add();
    }

    public void login() {
        logins.add();
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
            cps.slide();
            ips.slide();
            logins.slide();
            pings.slide();
            handshakes.slide();
            blocked.slide();

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

            if (++ticks % 20 != 0) {
                return;
            }

            long ms = System.currentTimeMillis();
            blacklist.values().removeIf(t -> t <= ms);
            pending.values().removeIf(t -> now - t > SECOND * 60);
            ipRecords.values().removeIf(r -> now - r.lastSeen > SECOND * 5);

            for (Rate r : shown) {
                long peak = r.peak;
                if (peak > r.announced && peak >= minPeak) {
                    emit("\u00a77" + r.label + " peak: " + color(r.announced) + fmt(r.announced)
                            + " \u00a77\u2192 " + color(peak) + fmt(peak));
                    r.announced = peak;
                }
            }
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

    public String actionBar() {
        StringBuilder sb = new StringBuilder(160).append(PREFIX)
                .append(stat("CPS", cps.value)).append(" \u00a78\u2022 ")
                .append(stat("IPSEC", ips.value)).append(" \u00a78\u2022 ")
                .append(stat("LOGINS", logins.value)).append(" \u00a78\u2022 ")
                .append(stat("PINGS", pings.value)).append(" \u00a78\u2022 ")
                .append(stat("HANDSHAKE/S", handshakes.value));
        if (attack) {
            sb.append(" \u00a78\u2022 \u00a74\u00a7lATTACK");
        } else if (cps.value == 0 && ips.value == 0) {
            sb.append(" \u00a78\u2022 \u00a75Waiting for new attacks to arrive\u2026");
        }
        return sb.toString();
    }

    public List<String> command(String[] args) {
        String sub = args.length == 0 ? "" : args[0].toLowerCase(Locale.ROOT);
        String arg = args.length < 2 ? "" : args[1].toLowerCase(Locale.ROOT);
        switch (sub) {
            case "blacklist":
                if (!arg.equals("on") && !arg.equals("off")) {
                    return Collections.singletonList(PREFIX + "\u00a77Blacklist is currently " + onOff(blacklistOn)
                            + "\u00a77. Use \u00a7f/zab blacklist <on|off>");
                }
                blacklistOn = arg.equals("on");
                return Collections.singletonList(PREFIX + (blacklistOn
                        ? "\u00a77Blacklist is now \u00a7aon\u00a77. Bad connections will be blocked."
                        : "\u00a77Blacklist is now \u00a7coff\u00a77. Connections will not be blocked."));
            case "stats":
                List<String> lines = new ArrayList<>();
                for (Rate r : shown) {
                    lines.add(PREFIX + "\u00a77" + r.label + ": " + color(r.value) + fmt(r.value)
                            + " \u00a78(\u00a77peak " + color(r.peak) + fmt(r.peak) + "\u00a78)");
                }
                lines.add(PREFIX + "\u00a77Blacklist: " + onOff(blacklistOn)
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
                        PREFIX + "\u00a7f/zab blacklist <on|off> \u00a78- \u00a77toggle bot blocking",
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
