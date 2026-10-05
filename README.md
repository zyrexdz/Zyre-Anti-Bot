# Zyre Anti Bot (ZAB)

A Netty-level antibot and live traffic monitor for BungeeCord, Waterfall, Paper, and Spigot.

<p align="center">
  <img src="assets/proof.png" alt="300k+ CPS Peak Proof" />
</p>

Most antibot plugins struggle under heavy attacks because they let thousands of bot connections enter the proxy pipeline, wasting CPU decoding packets for IPs that should already be blocked. ZAB hooks directly into Netty's socket acceptor and drops blocked connections immediately with `closeForcibly()` before channel setup.

Supports Minecraft 1.8 through 1.21+ on Java 8 to 21+.

## Quickstart

1. Download the jar for your server from [Releases](https://github.com/zyrexdz/Zyre-Anti-Bot/releases/latest):
   - **BungeeCord / Waterfall**: `ZAB-Bungee-1.0.0.jar`
   - **Paper / Spigot**: `ZAB-Bukkit-1.0.0.jar`
2. Put the jar in your `plugins/` directory and restart.
3. In-game, run `/zab verbose top` (BossBar) or `/zab verbose down` (Action Bar) to view live traffic.

## Commands

All commands require the `zab.admin` permission (defaults to OP on Spigot).

- `/zab verbose [top|down]` - Toggle live traffic HUD (BossBar or Action Bar).
- `/zab blacklist <on|off|barely|peak>` - Set blacklist mode:
  - `on` - Drops blacklisted IPs instantly at socket accept.
  - `peak` - Micro-window tracking to capture instant CPS spikes before crashes.
  - `barely` - Probes packet headers before blocking (tracks handshakes/logins/pings).
  - `off` - Disables blocking (monitor only).
- `/zab peak [on|off]` - Toggle instant peak detection.
- `/zab barely [on|off]` - Toggle packet probing mode.
- `/zab antiafk [on|off|status] [version]` - Keep server alive with an internal client (`ZABAFK`).
- `/zab stats` - Print current rates and peak records in chat.
- `/zab reset` - Reset peak traffic records.
- `/zab unblock <ip>` - Manually unblock an IP.

## Config

Generated in `plugins/ZAB/config.yml`:

```yaml
# Startup blacklist mode: on, peak, barely, or off
blacklist-mode: "on"

# Max connections an IP can make per second before getting blocked
max-connections-per-ip: 6

# Block duration in minutes
block-minutes: 5

# CPS threshold to trigger attack mode
attack-cps: 40
attack-end-seconds: 10

# Require new players to reconnect once during attacks
attack-verify: true

# Minimum traffic peak to announce in chat
min-peak: 3

# Whitelisted IPs (add your backend proxy IP if running on Spigot)
trusted-ips:
  - 127.0.0.1

# Anti-AFK bot settings
antiafk-port: 0
antiafk-version: "auto"
antiafk-password: "" # AuthMe password if applicable
```

## How It Works

- **TCP-Level Drop**: Blacklisted IPs are aborted immediately at the Netty socket level (`closeForcibly()`) without creating channel pipelines or decoding packets.
- **Accurate Rates**: Tracks raw connection attempts (`CPS`) and unique IPs (`IPSEC`) before any filtering runs, so stats reflect actual incoming traffic.
- **Rejoin Verification**: When traffic exceeds `attack-cps`, unverified connections are dropped with a reconnect prompt. Real players rejoin and get cached in `verified.txt`, while one-shot bot proxies are dropped.
- **Anti-AFK Bot**: If your host shuts down empty servers, `/zab antiafk on` runs a lightweight local client on localhost that handles keep-alives and movement.

## Building

Requires Java 8+ and Maven.

```bash
# Windows
build.bat

# Linux / macOS
mvn clean package
```

Built jars will be in `bungee/target/` and `bukkit/target/`.

## License

[MIT](LICENSE)
