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
    private final Set<UUID> viewers = ConcurrentHashMap.newKeySet();

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
        zab.start();
        zab.getAntiAfk().setPassword(getConfig().getString("antiafk-password", ""));
        hook = new NettyHook(zab);
        bar = initActionBar();

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
        viewers.clear();
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
            for (Iterator<UUID> it = viewers.iterator(); it.hasNext(); ) {
                Player p = Bukkit.getPlayer(it.next());
                if (p == null) {
                    it.remove();
                } else {
                    p.sendMessage(line);
                }
            }
        }
        if (viewers.isEmpty()) {
            return;
        }
        String text = zab.actionBar();
        for (UUID id : viewers) {
            Player p = Bukkit.getPlayer(id);
            if (p != null) {
                bar.accept(p, text);
            }
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
        viewers.remove(e.getPlayer().getUniqueId());
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
                sender.sendMessage(Zab.PREFIX + "\u00a7cOnly in-game players can view the action bar counter.");
                return true;
            }
            Player p = (Player) sender;
            if (viewers.remove(p.getUniqueId())) {
                p.sendMessage(Zab.PREFIX + "\u00a77You are \u00a7cno longer \u00a77viewing the counter.");
            } else {
                viewers.add(p.getUniqueId());
                p.sendMessage(Zab.PREFIX + "\u00a77You are \u00a7anow \u00a77viewing the counter.");
            }
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
