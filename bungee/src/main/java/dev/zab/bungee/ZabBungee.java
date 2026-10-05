package dev.zab.bungee;

import dev.zab.core.NettyHook;
import dev.zab.core.Zab;
import io.netty.channel.Channel;
import net.md_5.bungee.api.ChatMessageType;
import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.chat.BaseComponent;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.config.ListenerInfo;
import net.md_5.bungee.api.config.ServerInfo;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.event.PlayerDisconnectEvent;
import net.md_5.bungee.api.event.PostLoginEvent;
import net.md_5.bungee.api.event.ServerKickEvent;
import net.md_5.bungee.api.plugin.Command;
import net.md_5.bungee.api.plugin.Listener;
import net.md_5.bungee.api.plugin.Plugin;
import net.md_5.bungee.api.plugin.TabExecutor;
import net.md_5.bungee.config.Configuration;
import net.md_5.bungee.config.ConfigurationProvider;
import net.md_5.bungee.config.YamlConfiguration;
import net.md_5.bungee.event.EventHandler;
import net.md_5.bungee.protocol.packet.BossBar;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.ParameterizedType;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.logging.Filter;
import java.util.logging.Handler;
import java.util.logging.Logger;

public final class ZabBungee extends Plugin implements Listener {
    private static final int BAR_ADD = 0, BAR_REMOVE = 1, BAR_TITLE = 3;

    private Zab zab;
    private NettyHook hook;
    private Collection<?> listeners;
    private final Set<UUID> viewersBottom = ConcurrentHashMap.newKeySet();
    private final Map<UUID, UUID> viewersTop = new ConcurrentHashMap<>();
    private String lastTop = "";
    private boolean hookFailed;

    @Override
    public void onEnable() {
        File file = new File(getDataFolder(), "config.yml");
        Configuration cfg;
        try {
            getDataFolder().mkdirs();
            if (!file.exists()) {
                try (InputStream in = getResourceAsStream("config.yml")) {
                    Files.copy(in, file.toPath());
                }
            }
            cfg = ConfigurationProvider.getProvider(YamlConfiguration.class).load(file);
        } catch (IOException err) {
            getLogger().severe("Could not load config.yml: " + err.getMessage());
            return;
        }

        zab = new Zab(
                cfg.getInt("max-connections-per-ip", 6),
                cfg.getInt("block-minutes", 5),
                cfg.getInt("attack-cps", 40),
                cfg.getInt("attack-end-seconds", 10),
                cfg.getBoolean("attack-verify", cfg.getBoolean("drop-unverified-during-attack", true)),
                cfg.getInt("min-peak", 3),
                new HashSet<>(cfg.getStringList("trusted-ips")),
                getDataFolder(),
                getLogger()::info,
                () -> {
                    int p = cfg.getInt("antiafk-port", 0);
                    if (p > 0) {
                        return p;
                    }
                    for (ListenerInfo li : getProxy().getConfigurationAdapter().getListeners()) {
                        if (li.getHost() != null) {
                            return li.getHost().getPort();
                        }
                    }
                    return 25565;
                });
        zab.setMode(cfg.getString("blacklist-mode", cfg.getBoolean("peak-mode", false) ? "peak" : "on"));
        zab.start();
        zab.getAntiAfk().setPassword(cfg.getString("antiafk-password", ""));
        hook = new NettyHook(zab);

        String cfgVer = cfg.getString("antiafk-version", "auto");
        if (!cfgVer.trim().isEmpty() && !cfgVer.equalsIgnoreCase("auto")) {
            zab.getAntiAfk().setTargetVersion(cfgVer);
        } else {
            detectBackendVersion();
        }
        Filter logFilter = record -> {
            String m = record.getMessage();
            Throwable t = record.getThrown();
            return !(m != null && m.contains("Unexpected packet received during login process"))
                    && !(t != null && t.getMessage() != null && t.getMessage().contains("Unexpected packet received during login process"));
        };
        getProxy().getLogger().setFilter(logFilter);
        for (Handler h : Logger.getLogger("").getHandlers()) {
            h.setFilter(logFilter);
        }

        getProxy().getPluginManager().registerListener(this, this);
        getProxy().getPluginManager().registerCommand(this, new ZabCommand());
        getProxy().getScheduler().schedule(this, this::inject, 0, 5, TimeUnit.SECONDS);
        getProxy().getScheduler().schedule(this, this::refresh, 100, 100, TimeUnit.MILLISECONDS);
    }

    @Override
    public void onDisable() {
        if (zab == null) {
            return;
        }
        hook.eject();
        zab.stop();
        for (Map.Entry<UUID, UUID> entry : viewersTop.entrySet()) {
            ProxiedPlayer p = getProxy().getPlayer(entry.getKey());
            if (p != null) {
                p.unsafe().sendPacket(new BossBar(entry.getValue(), BAR_REMOVE));
            }
        }
        viewersBottom.clear();
        viewersTop.clear();
    }

    private void inject() {
        if (hookFailed) {
            return;
        }
        try {
            if (listeners == null) {
                listeners = findListeners();
            }
            if (listeners == null) {
                getLogger().warning("Could not find proxy network listeners.");
                hookFailed = true;
                return;
            }
            int count = hook.inject(listeners);
            if (count > 0) {
                getLogger().info("Injected listener hook into " + count + " channel(s).");
            }
        } catch (IllegalAccessException | RuntimeException err) {
            getLogger().warning("Hook injection failed: " + err.getMessage());
            hookFailed = true;
        }
    }

    private Collection<?> findListeners() throws IllegalAccessException {
        Object proxy = getProxy();
        for (Class<?> c = proxy.getClass(); c != null; c = c.getSuperclass()) {
            for (Field f : c.getDeclaredFields()) {
                if (Collection.class.isAssignableFrom(f.getType())) {
                    f.setAccessible(true);
                    Object val = f.get(proxy);
                    if (val instanceof Collection) {
                        Collection<?> col = (Collection<?>) val;
                        if (f.getGenericType() instanceof ParameterizedType
                                && ((ParameterizedType) f.getGenericType()).getActualTypeArguments()[0] == Channel.class) {
                            return col;
                        }
                        if (!col.isEmpty() && col.iterator().next() instanceof Channel) {
                            return col;
                        }
                        String name = f.getName().toLowerCase();
                        if (name.equals("listeners") || name.equals("channels")) {
                            return col;
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
            BaseComponent[] msg = TextComponent.fromLegacyText(line);
            for (Iterator<UUID> it = viewersBottom.iterator(); it.hasNext(); ) {
                ProxiedPlayer p = getProxy().getPlayer(it.next());
                if (p == null) {
                    it.remove();
                } else {
                    p.sendMessage(msg);
                }
            }
            for (Iterator<UUID> it = viewersTop.keySet().iterator(); it.hasNext(); ) {
                ProxiedPlayer p = getProxy().getPlayer(it.next());
                if (p == null) {
                    it.remove();
                } else {
                    p.sendMessage(msg);
                }
            }
        }
        if (viewersBottom.isEmpty() && viewersTop.isEmpty()) {
            return;
        }

        String text = zab.actionBar();
        TextComponent content = new TextComponent(TextComponent.fromLegacyText(text));

        for (UUID id : viewersBottom) {
            ProxiedPlayer p = getProxy().getPlayer(id);
            if (p != null) {
                p.sendMessage(ChatMessageType.ACTION_BAR, content);
            }
        }
        if (!viewersTop.isEmpty() && !text.equals(lastTop)) {
            lastTop = text;
            for (Map.Entry<UUID, UUID> entry : viewersTop.entrySet()) {
                ProxiedPlayer p = getProxy().getPlayer(entry.getKey());
                if (p != null) {
                    BossBar packet = new BossBar(entry.getValue(), BAR_TITLE);
                    packet.setTitle(content);
                    p.unsafe().sendPacket(packet);
                }
            }
        }
    }

    @EventHandler
    public void onJoin(PostLoginEvent e) {
        if (e.getPlayer().getSocketAddress() instanceof InetSocketAddress) {
            InetSocketAddress addr = (InetSocketAddress) e.getPlayer().getSocketAddress();
            if (addr.getAddress() != null) {
                zab.verify(addr.getAddress().getHostAddress());
            }
        }
    }

    @EventHandler
    public void onDisconnect(PlayerDisconnectEvent e) {
        viewersBottom.remove(e.getPlayer().getUniqueId());
        viewersTop.remove(e.getPlayer().getUniqueId());
    }

    @EventHandler
    public void onServerKick(ServerKickEvent e) {
        if ("ZABAFK".equalsIgnoreCase(e.getPlayer().getName()) && e.getKickReasonComponent() != null) {
            zab.getAntiAfk().checkKickString(BaseComponent.toLegacyText(e.getKickReasonComponent()));
        }
    }

    private void detectBackendVersion() {
        for (ListenerInfo li : getProxy().getConfigurationAdapter().getListeners()) {
            if (li.getServerPriority() == null || li.getServerPriority().isEmpty()) {
                continue;
            }
            String name = li.getServerPriority().get(0);
            ServerInfo si = getProxy().getServerInfo(name);
            if (si == null) {
                continue;
            }
            si.ping((result, error) -> {
                if (error == null && result != null && result.getVersion() != null && result.getVersion().getProtocol() > 0) {
                    int proto = result.getVersion().getProtocol();
                    zab.getAntiAfk().setTargetProtocol(proto);
                    getLogger().info("Anti-AFK auto-detected backend server '" + name + "': "
                            + result.getVersion().getName() + " (protocol " + proto + ")");
                }
            });
            return;
        }
    }

    private final class ZabCommand extends Command implements TabExecutor {
        ZabCommand() {
            super("zab", "zab.admin");
        }

        @Override
        public void execute(CommandSender sender, String[] args) {
            if (args.length == 0 || !args[0].equalsIgnoreCase("verbose")) {
                for (String msg : zab.command(args)) {
                    sender.sendMessage(TextComponent.fromLegacyText(msg));
                }
                return;
            }
            if (!(sender instanceof ProxiedPlayer)) {
                sender.sendMessage(TextComponent.fromLegacyText(Zab.PREFIX + "\u00a7cOnly players can use this command."));
                return;
            }
            ProxiedPlayer p = (ProxiedPlayer) sender;
            UUID id = p.getUniqueId();
            boolean top = args.length > 1 && args[1].toLowerCase(Locale.ROOT).equals("top");

            UUID bar = viewersTop.remove(id);
            if (bar != null) {
                p.unsafe().sendPacket(new BossBar(bar, BAR_REMOVE));
            }
            boolean wasBottom = viewersBottom.remove(id);

            String msg;
            if (top && bar != null) {
                msg = "\u00a77Top HUD \u00a7cdisabled\u00a77.";
            } else if (top) {
                bar = UUID.randomUUID();
                BossBar add = new BossBar(bar, BAR_ADD);
                add.setTitle(new TextComponent(TextComponent.fromLegacyText(zab.actionBar())));
                add.setHealth(1.0f);
                add.setColor(5);
                add.setDivision(0);
                p.unsafe().sendPacket(add);
                viewersTop.put(id, bar);
                msg = "\u00a77Top HUD \u00a7aenabled\u00a77.";
            } else if (wasBottom) {
                msg = "\u00a77Action bar HUD \u00a7cdisabled\u00a77.";
            } else {
                viewersBottom.add(id);
                msg = "\u00a77Action bar HUD \u00a7aenabled\u00a77.";
            }
            p.sendMessage(TextComponent.fromLegacyText(Zab.PREFIX + msg));
        }

        @Override
        public Iterable<String> onTabComplete(CommandSender sender, String[] args) {
            return Zab.complete(args);
        }
    }
}
