# ZAB (Zyre Anti Bot)

The best and strongest antibot protection for BungeeCord, Waterfall, Paper, and Spigot servers. Inspired by Sonar Antibot.

<p align="center">
  <img src="assets/proof.png" alt="300k+ CPS Peak Proof" />
</p>

If you run a Minecraft server, you know how annoying bot attacks are. Someone gets mad, grabs a free botting tool or proxy list, spams 50,000 fake accounts into your server, and suddenly your console is screaming, players are lagging out, or the whole server crashes.

ZAB is built to stop that completely.

While normal antibot plugins wait until bots are already inside Minecraft to kick them, ZAB drops malicious connections the microsecond they touch your port. It has been tested and verified against brutal floods over 300,000 connections per second with zero server lag, keeping your server running at a solid 20.0 TPS while real players keep playing like nothing happened.

Supports Minecraft 1.8 through 26.2+ on Java 8 to 25+.

## Why ZAB is the Best Protection

* **Crushes 300k+ CPS Floods**: Drops blocked bot sockets instantly before your server even has to process them. Zero CPU waste, zero memory leaks, zero lag.
* **Smart Reconnect Shield**: When an attack hits, ZAB makes joining players reconnect once. Real players get in with one quick click and never get asked again, while automated bot scripts fail immediately because they cannot handle the reconnect check.
* **20.0 TPS All Day**: Malicious connections are dropped so early at the network layer that your server never breaks a sweat. Your players won't even notice someone is trying to take your server down.
* **Instant IP Blacklisting**: Any IP that spams connections gets banned on the spot before it can do damage.
* **Linux Auto-Tuning**: Automatically unlocks your system's open file limits on Linux so your server will not crash when thousands of connections flood in at once.
* **Live Attack HUD**: Want to see your defense in action? Turn on the HUD and watch attacks get blocked live on your screen.

## Quick Setup

1. Download the jar for your server from [Releases](https://github.com/zyrexdz/Zyre-Anti-Bot/releases/latest):
   * **BungeeCord / Waterfall**: `ZAB-Bungee-1.0.0.jar`
   * **Paper / Spigot**: `ZAB-Bukkit-1.0.0.jar`
2. Drop the jar into your `plugins` folder and restart your server.
3. That is it. ZAB is active and protecting your server immediately with default settings.
4. (Optional) Run `/zab verbose top` or `/zab verbose down` in-game if you want to watch the attack stats live on your screen.

## Commands

All commands need the `zab.admin` permission (server OPs have it automatically).

### `/zab blacklist <on|off|barely|peak>`
Controls how aggressively ZAB defends your server against incoming connections:
* `on`: The recommended default protection mode. Instantly drops blocked IPs before reading any Minecraft data. Gives you maximum protection and saves the most CPU during attacks.
* `peak`: High-speed attack mode. Checks incoming traffic every 50 milliseconds to catch sudden bursts immediately, showing you real peak numbers in chat right before an attack can freeze the server. It also reads packet headers so you can see what blocked bots were trying to do.
* `barely`: Packet inspection mode. Reads the first few bytes of blocked connections to see whether bots were trying to ping, query the MOTD, or log in before dropping them. Great for logging full attack details.
* `off`: Turns off blocking. Only counts traffic without stopping anyone (not recommended during attacks).

### `/zab unblock <ip>`
Immediately unblocks an IP address if a player or staff member got blocked by mistake during a heavy attack.

### `/zab stats`
Prints your current traffic rates, how many bot connections have been blocked, and your all-time peak attack records in chat.

### `/zab reset`
Resets all peak records back to current rates so you can test how well ZAB holds up against a new attack from scratch.

### `/zab verbose [top|down]`
Turns on an on-screen live HUD so you can watch incoming attacks get blocked in real time.
* `/zab verbose top`: Shows a BossBar at the top of your screen.
* `/zab verbose down`: Shows stats right above your hotbar on the Action Bar.
* Running it again or typing just `/zab verbose` turns it off.
* Metrics are color-coded so you can spot attacks at a glance: CPS is blue, IPSEC is green, Logins are orange, Pings are yellow, MOTD is pink, Handshakes are purple, and Blocked is red. The numbers dynamically change from green to yellow, orange, and red depending on attack intensity.

### `/zab antiafk [on|off|status] [version]`
Spawns a fake local player named `ZABAFK` on localhost to keep your server alive.
* Why use this: Many free or budget hosts put servers to sleep or shut them down completely when zero players are online. Running this keeps 1 player connected so your server stays online 24/7.
* Automatically jumps and looks around every 2 seconds so anti-AFK plugins do not kick it.
* Supports custom versions like `/zab antiafk 1.20.4` or `/zab antiafk 26.2`, or leave it on auto.
* If your server uses a login plugin like AuthMe, set `antiafk-password` in `config.yml` and the bot will automatically log in.

### `/zab peak [on|off]`
Quick shortcut to toggle peak detection mode on or off without typing the whole command.

### `/zab barely [on|off]`
Quick shortcut to toggle packet probing mode on or off without typing the whole command.

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
