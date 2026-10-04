# Zyre Anti Bot (ZAB)

*Inspired by Sonar Antibot.*

A lightweight, high performance antibot and live connection monitor for **BungeeCord**, **Waterfall**, **Paper**, and **Spigot**.

### Supported Versions & Software
- **Minecraft Versions**: **1.8.8 up to 26.2+** (1.8 – 1.21.x, 26.1, 26.2, and future releases)
- **Server Platforms**: Paper, Purpur, Spigot (1.8.8 to 26.2+)
- **Proxy Platforms**: BungeeCord, Waterfall, FlameCord (1.8 to 26.2+)
- **Java Runtimes**: Java 8 up to Java 21+

Most antibots choke during real bot attacks because they let thousands of fake connections enter the proxy pipeline, wasting CPU decoding packets for IPs that should already be banned. ZAB hooks straight into Netty's socket acceptor and drops blocked connections on the spot—before your server or proxy even touches them.

## Why ZAB?

| | Standard Antibots | Sonar Antibot | Zyre Anti Bot (ZAB) |
|---|---|---|---|
| **Dropping bots** | Sends disconnect packet | Channel close | Instant TCP abort (`closeForcibly`) before channel setup |
| **CPU on 10k CPS attack** | High (decodes all packets) | Moderate | Minimal (0 allocations for banned IPs) |
| **Live HUD** | Chat spam or scoreboard | Action bar / BossBar | Real-time BossBar (`/zab verbose top`) or Action Bar (`/zab verbose down`) |
| **Metrics** | Periodic averages | Live stats | Raw CPS, IPSEC, Logins, Pings, Handshakes (50ms rolling window) |
| **Built-in Bot** | None | None | Virtual Anti-AFK bot with auto protocol negotiation (`/zab antiafk`) |

## Quickstart

1. Download the jar for your server from [Releases](https://github.com/zyrexdz/Zyre-Anti-Bot/releases/latest):
   - **BungeeCord / Waterfall**: `ZAB-Bungee-1.0.0.jar`
   - **Paper / Spigot**: `ZAB-Bukkit-1.0.0.jar`
2. Drop it into your `plugins/` folder and restart.
3. In-game, run `/zab verbose top` for the top BossBar or `/zab verbose down` for the bottom Action Bar.

## Commands

All commands require the `zab.admin` permission (OP by default on Spigot).

- `/zab verbose [top|down]` - Toggle the real-time HUD on your screen.
- `/zab blacklist <on|off>` - Turn bot blocking on or off. Metrics stay completely raw and live either way.
- `/zab antiafk [on|off|status] [version]` - Keep your server awake with an internal bot named ZABAFK.
- `/zab stats` - Show current rates and peak records in chat.
- `/zab reset` - Reset peak traffic records.
- `/zab unblock <ip>` - Manually unban an IP.

## Config

Generated automatically in `plugins/ZAB/config.yml`:

```yaml
# Max connections a single IP can make per second
max-connections-per-ip: 6

# Ban duration in minutes
block-minutes: 5

# CPS threshold that triggers attack mode
attack-cps: 40
attack-end-seconds: 10

# During attacks, new players get asked to rejoin once to verify
attack-verify: true

# Minimum traffic peak to announce in chat
min-peak: 3

# Never block these (add your proxy IP if running on backend Spigot)
trusted-ips:
  - 127.0.0.1

# Anti-AFK bot settings
antiafk-port: 0
antiafk-version: "auto"
antiafk-password: "" # Set your AuthMe password here if using a login plugin
```

## How It Works

- **Zero-Allocation Drop**: When an IP exceeds the rate limit or sends garbage, it gets blacklisted. Future connections from that IP get aborted immediately at the TCP socket layer with `closeForcibly()`. No packet decoding, no logger spam, no memory wasted.
- **Raw Metrics**: `CPS` and `IPSEC` track every single connection attempt before any blacklist logic runs. You always see the real attack volume hitting your box.
- **Attack Verification**: When incoming traffic spikes past `attack-cps`, unverified players get disconnected with a rejoin prompt. Real players reconnect and get whitelisted into `verified.txt`; one-shot bot proxies drop off and never come back.
- **Anti-AFK Bot**: Running on a host that stops your server when empty? `/zab antiafk on` logs in a local client directly over localhost to handle keep-alives, jump, and look around.

## Building from Source

Requires Java 8+ and Maven.

```bash
# Windows
build.bat

# Linux / macOS
mvn clean package
```

Jars will be generated in `bungee/target/` and `bukkit/target/`.

## License

This project is licensed under the [MIT License](LICENSE).

---

*If this saved your server from getting lagged out, leave a ⭐ to help others find it!*
