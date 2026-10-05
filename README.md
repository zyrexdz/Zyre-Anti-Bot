# ZAB (Zyre Anti Bot)

An antibot and live traffic monitor for BungeeCord, Waterfall, Paper, and Spigot. Inspired by Sonar Antibot.

<p align="center">
  <img src="assets/proof.png" alt="300k+ CPS Peak Proof" />
</p>

Most antibot plugins let thousands of connections in before checking them, which lags or crashes the server. ZAB closes blocked connections immediately so your server doesn't waste CPU or RAM decoding packets for them.

Supports Minecraft 1.8 through 26.2+ on Java 8 to 25+.

## Quick Setup

1. Download the jar for your server from [Releases](https://github.com/zyrexdz/Zyre-Anti-Bot/releases/latest):
   * **BungeeCord / Waterfall**: `ZAB-Bungee-1.0.0.jar`
   * **Paper / Spigot**: `ZAB-Bukkit-1.0.0.jar`
2. Drop it into your `plugins` folder and restart your server.
3. In-game, run `/zab verbose top` or `/zab verbose down` to watch live traffic.

## Commands

All commands need the `zab.admin` permission (server OPs have it automatically).

### `/zab verbose [top|down]`
Turns on the on-screen live traffic monitor so you can watch connections happen in real time.
* `/zab verbose top`: Shows a BossBar at the top of your screen.
* `/zab verbose down`: Shows the stats right above your hotbar on the Action Bar.
* Running it again or running just `/zab verbose` turns it off.
* Metrics are color-coded so you can spot spikes at a glance: CPS is blue, IPSEC is green, Logins are orange, Pings are yellow, MOTD is pink, Handshakes are purple, and Blocked is red. Numbers change from green to yellow, orange, and red depending on how heavy the traffic is.

### `/zab blacklist <on|off|barely|peak>`
Changes how ZAB treats blocked connections during attacks:
* `on`: The default mode. If an IP is blocked, ZAB shuts down its connection immediately before reading any Minecraft data. This gives you the best protection and saves the most CPU.
* `peak`: High-speed detection mode. It checks traffic every 50 milliseconds instead of waiting a full second, catching sudden bursts instantly so you see real peak numbers in chat even if an attack freezes the server. It also reads packet headers so you can still track what blocked bots were trying to do.
* `barely`: Probing mode. Instead of dropping blocked IPs right away, ZAB reads the first few bytes of their connection to see if they were trying to ping, grab the MOTD, or log in, then drops them. Useful if you want full statistics on blocked bots.
* `off`: Turns off all blocking. ZAB will only count connections and display stats without stopping anyone.

### `/zab peak [on|off]`
A quick shortcut to toggle peak mode on or off without having to type the full blacklist command.

### `/zab barely [on|off]`
A quick shortcut to toggle packet probing mode on or off.

### `/zab antiafk [on|off|status] [version]`
Spawns a fake local player named `ZABAFK` that connects to your server from localhost.
* Why use this: Many free or shared hosts automatically shut down or sleep servers when zero players are online. This keeps 1 player connected so your server stays running 24/7.
* The bot automatically jumps and looks around every 2 seconds so anti-AFK plugins do not kick it.
* You can set a specific Minecraft version like `/zab antiafk 1.20.4` or `/zab antiafk 26.2`, or leave it on auto.
* If your server uses a login plugin like AuthMe, you can set `antiafk-password` in `config.yml` and the bot will automatically run `/login` on join.

### `/zab stats`
Prints your current traffic rates and all-time peak numbers in chat. Shows CPS, unique IPs per second, logins, pings, MOTDs, handshakes, blocked connections, and bytes per second.

### `/zab reset`
Resets all peak numbers back to your current traffic rates so you can start fresh for a new test.

### `/zab unblock <ip>`
Immediately removes an IP address from the blacklist if a player or staff member got blocked by mistake.

## Config

Located in `plugins/ZAB/config.yml`:

```yaml
# Blacklist mode on startup: on, peak, barely, or off
blacklist-mode: "on"

# How many connections a single IP can make per second before getting blocked
max-connections-per-ip: 6

# How long a blocked IP stays blacklisted (in minutes)
block-minutes: 5

# Connections per second that trigger attack mode
attack-cps: 40
attack-end-seconds: 10

# Ask new players to rejoin once during attacks to verify they are real
attack-verify: true

# Minimum peak number to announce in chat
min-peak: 3

# Whitelisted IPs (put your proxy IP here if running on a backend Spigot)
trusted-ips:
  - 127.0.0.1

# Anti-AFK bot settings
antiafk-port: 0
antiafk-version: "auto"
antiafk-password: "" # AuthMe password if needed
```

## For Nerds

This section covers the low-level technical architecture for developers and sysadmins.

### 1. Raw Socket Interception
Most antibot plugins hook into Minecraft events (`AsyncPlayerPreLoginEvent`, `LoginEvent`) or place handlers inside the client pipeline. By that time, Netty has already allocated channel pipelines, ByteBuf buffers, VarInt length decoders, and Minecraft packet decoders, consuming CPU cycles for every malicious connection.

ZAB uses reflection on startup to locate the server listening channels (`ServerConnection` on Spigot, `NettyServerConnection` on BungeeCord) and injects a custom `ChannelInboundHandlerAdapter` (`zab-acceptor`) at index 0 of the `ServerSocketChannel`. It also bumps `SO_BACKLOG` to 65535.

When a client connects, the OS kernel completes the TCP three-way handshake and hands the newly accepted socket to Netty. ZAB intercepts the child channel before Bungee or Spigot registers any client pipeline handlers:
* In `on` mode: If the IP is blacklisted or exceeds rate limits, ZAB calls `ch.unsafe().closeForcibly()` immediately. The socket is terminated at the kernel layer without allocating ByteBuf memory or registering Minecraft decoders.
* In `barely` and `peak` modes: ZAB attaches a minimal `Probe` handler. It reads the raw initial VarInt header, determines the handshake state (status ping vs login), increments thread-local protocol counters, and immediately closes the connection in a `finally` block before passing it down the pipeline.

### 2. 100% Discrete Circular Telemetry
Standard connection monitoring often divides packet counts by elapsed nanoseconds to extrapolate an "instantaneous rate". Under sudden bursts, tiny time deltas cause massive false readings.

ZAB uses a fixed circular ring buffer of 20 discrete buckets (50 milliseconds per bucket = 1,000ms sliding window). Each Netty worker thread writes to an array of 8 monotonic counters inside a `FastThreadLocal` with zero lock contention. A dedicated single-threaded ticker drains monotonic deltas every 50ms and slides the bucket array. The current rate is the direct integer sum of the 20 buckets. Peak checks run every 50ms, allowing peak announcements to trigger immediately before a server can freeze or crash.

### 3. Reconnection Verification
When connection rates exceed `attack-cps`, attack mode activates. Connections from IPs not present in `verified.txt` receive a raw `LoginDisconnect` packet with a reconnect prompt. If the IP reconnects between 1.5 seconds and 60 seconds, ZAB marks the IP as verified and saves it to disk (autosaved every 60 seconds). Because bot scripts rarely handle stateful reconnect logic, attacks are absorbed while real players rejoin seamlessly.

### 4. Linux Kernel & File Descriptor Optimization
On Linux startup, ZAB reads `/proc/self/limits`. If the process soft limit for open files (`nofile`) is lower than the host hard limit, ZAB invokes `prlimit` on its own PID to unlock the full hard limit ceiling without needing root privileges. If root access is detected, it automatically writes optimal TCP parameters to `/proc/sys/net/core/somaxconn` (65535), `tcp_max_syn_backlog` (65535), `tcp_tw_reuse` (1), and `tcp_fin_timeout` (15).

### 5. Multi-Version Protocol Engine
The built-in Anti-AFK client handles Minecraft protocol states from 1.8 (protocol 47) up through 26.2 (protocol 776). It implements VarInt frame encoding, zlib packet compression, server teleport confirmation, keep-alive responses, position/rotation packets, and automatic protocol fallback detection based on server ping responses and disconnect messages.

## Building

Needs Java 8+ and Maven.

```bash
# Windows
build.bat

# Linux / macOS
mvn clean package
```

Jars will be in `bungee/target/` and `bukkit/target/`.

## Credits

Inspired by **Sonar Antibot**.

## License

[MIT](LICENSE)
