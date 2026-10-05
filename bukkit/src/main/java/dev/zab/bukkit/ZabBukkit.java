package dev.zab.bukkit;

import dev.zab.core.NettyHook;
import dev.zab.core.Zab;
import io.netty.channel.ChannelFuture;
import net.md_5.bungee.api.chat.BaseComponent;
import net.md_5.bungee.api.chat.TextComponent;
import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabExecutor;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerKickEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.scheduler.BukkitTask;

import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;
import java.util.logging.Filter;
import java.util.logging.Handler;
import java.util.logging.Logger;

public final class ZabBukkit extends JavaPlugin implements Listener, TabExecutor {
    private Zab zab;
    private NettyHook hook;
    private Collection<?> listeners;
    private BukkitTask injector;
    private BiConsumer<Player, String> bar;
    private final Set<UUID> viewersBottom = ConcurrentHashMap.newKeySet();
    private final Set<UUID> viewersTop = ConcurrentHashMap.newKeySet();
    private Object topBossBar;
    private Method barAddPlayer;
    private Method barRemovePlayer;
    private Method barSetTitle;
    private String lastTop = "";

    @Override
    public void onEnable() {
        saveDefaultConfig();
        zab = new Zab(
                getConfig().getInt("max-connections-per-ip", 6),
                getConfig().getInt("block-minutes", 5),
                getConfig().getInt("attack-cps", 40),
                getConfig().getInt("attack-end-seconds", 10),
                getConfig().getBoolean("attack-verify", getConfig().getBoolean("drop-unverified-during-attack", true)),
                getConfig().getInt("min-peak", 3),
                new HashSet<>(getConfig().getStringList("trusted-ips")),
                getDataFolder(),
                getLogger()::info,
                () -> {
                    int p = getConfig().getInt("antiafk-port", 0);
                    return p > 0 ? p : getServer().getPort();
                });
        zab.setMode(getConfig().getString("blacklist-mode", getConfig().getBoolean("peak-mode", false) ? "peak" : "on"));
        zab.start();
        zab.getAntiAfk().setPassword(getConfig().getString("antiafk-password", ""));
        hook = new NettyHook(zab);
        bar = initActionBar();
        initBossBar();

        String cfgVer = getConfig().getString("antiafk-version", "auto");
        if (cfgVer != null && !cfgVer.trim().isEmpty() && !cfgVer.equalsIgnoreCase("auto")) {
            zab.getAntiAfk().setTargetVersion(cfgVer);
        } else {
            zab.getAntiAfk().setTargetVersion(Bukkit.getBukkitVersion());
        }

        Filter logFilter = record -> {
            String m = record.getMessage();
            Throwable t = record.getThrown();
            return !(m != null && m.contains("Unexpected packet received during login process"))
                    && !(t != null && t.getMessage() != null && t.getMessage().contains("Unexpected packet received during login process"));
        };
        for (Handler h : Logger.getLogger("").getHandlers()) {
            h.setFilter(logFilter);
        }

        getServer().getPluginManager().registerEvents(this, this);
        if (getCommand("zab") != null) {
            getCommand("zab").setExecutor(this);
            getCommand("zab").setTabCompleter(this);
        }
        injector = getServer().getScheduler().runTaskTimer(this, this::inject, 1, 100);
        getServer().getScheduler().runTaskTimer(this, this::refresh, 2, 2);
    }

    @Override
    public void onDisable() {
        getServer().getScheduler().cancelTasks(this);
        hook.eject();
        zab.stop();
        if (topBossBar != null) {
            try {
                topBossBar.getClass().getMethod("removeAll").invoke(topBossBar);
            } catch (Throwable ignored) {
            }
        }
        viewersBottom.clear();
        viewersTop.clear();
    }

    private void inject() {
        try {
            if (listeners == null) {
                listeners = findListeners();
            }
            if (listeners == null) {
                getLogger().warning("Could not find server network listeners.");
                injector.cancel();
                return;
            }
            int count = hook.inject(listeners);
            if (count > 0) {
                getLogger().info("Injected listener hook into " + count + " channel(s).");
            }
        } catch (ReflectiveOperationException | RuntimeException err) {
            getLogger().warning("Hook injection failed: " + err.getMessage());
            injector.cancel();
        }
    }

    private Collection<?> findListeners() throws ReflectiveOperationException {
        Object craft = getServer();
        Object nms = craft.getClass().getMethod("getServer").invoke(craft);
        for (Class<?> c = nms.getClass(); c != null; c = c.getSuperclass()) {
            for (Field f : c.getDeclaredFields()) {
                if (!f.getType().getSimpleName().startsWith("ServerConnection")) {
                    continue;
                }
                f.setAccessible(true);
                Object conn = f.get(nms);
                for (Class<?> k = conn == null ? null : conn.getClass(); k != null; k = k.getSuperclass()) {
                    for (Field g : k.getDeclaredFields()) {
                        if (List.class.isAssignableFrom(g.getType()) && g.getGenericType() instanceof ParameterizedType
                                && ((ParameterizedType) g.getGenericType()).getActualTypeArguments()[0] == ChannelFuture.class) {
                            g.setAccessible(true);
                            return (Collection<?>) g.get(conn);
                        }
                    }
                }
            }
        }
        return null;
    }

    private void refresh() {
        String line;
        while ((line = zab.pollEvent()) != null) {
            for (UUID id : viewersBottom) {
                Player p = Bukkit.getPlayer(id);
                if (p != null) {
                    p.sendMessage(line);
                }
            }
            for (UUID id : viewersTop) {
                Player p = Bukkit.getPlayer(id);
                if (p != null && !viewersBottom.contains(id)) {
                    p.sendMessage(line);
                }
            }
        }
        for (Iterator<UUID> it = viewersBottom.iterator(); it.hasNext(); ) {
            if (Bukkit.getPlayer(it.next()) == null) {
                it.remove();
            }
        }
        for (Iterator<UUID> it = viewersTop.iterator(); it.hasNext(); ) {
            if (Bukkit.getPlayer(it.next()) == null) {
                it.remove();
            }
        }
        if (!viewersBottom.isEmpty()) {
            String text = zab.actionBar();
            for (UUID id : viewersBottom) {
                Player p = Bukkit.getPlayer(id);
                if (p != null) {
                    bar.accept(p, text);
                }
            }
        }
        if (!viewersTop.isEmpty() && topBossBar != null) {
            String text = zab.actionBar();
            if (!text.equals(lastTop)) {
                lastTop = text;
                try {
                    barSetTitle.invoke(topBossBar, text);
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private void initBossBar() {
        try {
            Class<?> bossBarClass = Class.forName("org.bukkit.boss.BossBar");
            Class<?> barColorClass = Class.forName("org.bukkit.boss.BarColor");
            Class<?> barStyleClass = Class.forName("org.bukkit.boss.BarStyle");
            Class<?> barFlagClass = Class.forName("org.bukkit.boss.BarFlag");
            Object color = barColorClass.getField("PURPLE").get(null);
            Object style = barStyleClass.getField("SOLID").get(null);
            Object flags = Array.newInstance(barFlagClass, 0);
            Method create = Bukkit.class.getMethod("createBossBar", String.class, barColorClass, barStyleClass, flags.getClass());
            topBossBar = create.invoke(null, "", color, style, flags);
            barAddPlayer = bossBarClass.getMethod("addPlayer", Player.class);
            barRemovePlayer = bossBarClass.getMethod("removePlayer", Player.class);
            barSetTitle = bossBarClass.getMethod("setTitle", String.class);
            Method setProgress = bossBarClass.getMethod("setProgress", double.class);
            setProgress.invoke(topBossBar, 1.0);
            Method setVisible = bossBarClass.getMethod("setVisible", boolean.class);
            setVisible.invoke(topBossBar, true);
        } catch (Throwable ignored) {
            topBossBar = null;
        }
    }

    private BiConsumer<Player, String> initActionBar() {
        try {
            Class<?> type = Class.forName("net.md_5.bungee.api.ChatMessageType");
            Object actionBar = type.getField("ACTION_BAR").get(null);
            Method send = Player.Spigot.class.getMethod("sendMessage", type, BaseComponent[].class);
            return (p, s) -> {
                try {
                    send.invoke(p.spigot(), actionBar, TextComponent.fromLegacyText(s));
                } catch (ReflectiveOperationException ignored) {
                }
            };
        } catch (ReflectiveOperationException ignored) {
        }
        try {
            Method sendActionBar = Player.class.getMethod("sendActionBar", String.class);
            return (p, s) -> {
                try {
                    sendActionBar.invoke(p, s);
                } catch (ReflectiveOperationException ignored) {
                }
            };
        } catch (ReflectiveOperationException ignored) {
        }
        try {
            String v = getServer().getClass().getPackage().getName().split("\\.")[3];
            String nms = "net.minecraft.server." + v + ".";
            Class<?> component = Class.forName(nms + "IChatBaseComponent");
            Method serialize = Class.forName(nms + "IChatBaseComponent$ChatSerializer").getMethod("a", String.class);
            Class<?> packet = Class.forName(nms + "Packet");
            Constructor<?> ctor = null;
            for (Constructor<?> c : Class.forName(nms + "PacketPlayOutChat").getConstructors()) {
                if (c.getParameterTypes().length == 2 && c.getParameterTypes()[0] == component) {
                    ctor = c;
                    break;
                }
            }
            Constructor<?> chat = ctor;
            Method getHandle = Class.forName("org.bukkit.craftbukkit." + v + ".entity.CraftPlayer").getMethod("getHandle");
            return (p, s) -> {
                try {
                    Object handle = getHandle.invoke(p);
                    Object conn = handle.getClass().getField("playerConnection").get(handle);
                    Object pkt = chat.newInstance(serialize.invoke(null, "{\"text\":\"" + s + "\"}"), (byte) 2);
                    conn.getClass().getMethod("sendPacket", packet).invoke(conn, pkt);
                } catch (ReflectiveOperationException ignored) {
                }
            };
        } catch (ReflectiveOperationException | RuntimeException err) {
            return Player::sendMessage;
        }
    }

    @EventHandler
    public void onJoin(PlayerJoinEvent e) {
        if (e.getPlayer().getAddress() != null && e.getPlayer().getAddress().getAddress() != null) {
            zab.verify(e.getPlayer().getAddress().getAddress().getHostAddress());
        }
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent e) {
        UUID id = e.getPlayer().getUniqueId();
        viewersBottom.remove(id);
        if (viewersTop.remove(id) && topBossBar != null) {
            try {
                barRemovePlayer.invoke(topBossBar, e.getPlayer());
            } catch (Throwable ignored) {
            }
        }
    }

    @EventHandler
    public void onKick(PlayerKickEvent e) {
        if ("ZABAFK".equalsIgnoreCase(e.getPlayer().getName())) {
            e.setCancelled(true);
        }
    }

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        if (args.length > 0 && args[0].equalsIgnoreCase("verbose")) {
            if (!(sender instanceof Player)) {
                sender.sendMessage(Zab.PREFIX + "\u00a7cOnly players can use this command.");
                return true;
            }
            Player p = (Player) sender;
            UUID id = p.getUniqueId();
            boolean top = args.length > 1 && args[1].equalsIgnoreCase("top");

            boolean wasTop = viewersTop.remove(id);
            if (wasTop && topBossBar != null) {
                try {
                    barRemovePlayer.invoke(topBossBar, p);
                } catch (Throwable ignored) {
                }
            }
            boolean wasBottom = viewersBottom.remove(id);

            String msg;
            if (top && wasTop) {
                msg = "\u00a77Top HUD \u00a7cdisabled\u00a77.";
            } else if (top) {
                if (topBossBar != null) {
                    try {
                        barAddPlayer.invoke(topBossBar, p);
                        barSetTitle.invoke(topBossBar, zab.actionBar());
                    } catch (Throwable ignored) {
                    }
                    viewersTop.add(id);
                    msg = "\u00a77Top HUD \u00a7aenabled\u00a77.";
                } else {
                    viewersBottom.add(id);
                    msg = "\u00a7cTop BossBar requires 1.9+. \u00a77Showing \u00a7aaction bar \u00a77instead.";
                }
            } else if (wasBottom) {
                msg = "\u00a77Action bar HUD \u00a7cdisabled\u00a77.";
            } else {
                viewersBottom.add(id);
                msg = "\u00a77Action bar HUD \u00a7aenabled\u00a77.";
            }
            p.sendMessage(Zab.PREFIX + msg);
            return true;
        }

        for (String msg : zab.command(args)) {
            sender.sendMessage(msg);
        }
        return true;
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command cmd, String alias, String[] args) {
        return Zab.complete(args);
    }
}
