# ZAB (Zyre Anti Bot)

Antibot and live traffic monitor for BungeeCord, Waterfall, Paper, and Spigot.

<p align="center">
  <img src="assets/proof.png" alt="300k+ CPS Peak Proof" />
</p>

Most antibot plugins let thousands of connections in before checking them, which lags or crashes the server. ZAB closes blocked connections immediately so your server doesn't waste CPU or RAM decoding packets for them.

Runs on Minecraft 1.8 through 1.21+ (Java 8 to 21+).

## Quick Setup

1. Download the jar for your server setup from [Releases](https://github.com/zyrexdz/Zyre-Anti-Bot/releases/latest):
   * **BungeeCord / Waterfall**: `ZAB-Bungee-1.0.0.jar`
   * **Paper / Spigot**: `ZAB-Bukkit-1.0.0.jar`
2. Drop it into your `plugins` folder and restart.
3. In-game, run `/zab verbose top` (BossBar) or `/zab verbose down` (Action Bar) to watch live traffic.

## Commands

All commands need the `zab.admin` permission (OPs have it automatically).

* `/zab verbose [top|down]`: Turn on the traffic HUD (BossBar at the top, or Action Bar above your hotbar).
* `/zab blacklist <on|off|barely|peak>`: Set how ZAB deals with blocked connections:
  * `on`: Normal mode. Drops blocked IPs immediately.
  * `peak`: Catches fast traffic spikes right away so you see the real peak before a server freezes.
  * `barely`: Reads the packet header first so you can still track handshakes, logins, and pings from blocked bots.
  * `off`: Disables blocking and only monitors traffic.
* `/zab peak [on|off]`: Toggle peak mode.
* `/zab barely [on|off]`: Toggle packet probing mode.
* `/zab antiafk [on|off|status] [version]`: Runs a local bot (`ZABAFK`) so free hosts don't turn off an empty server.
* `/zab stats`: Prints current traffic rates and peak records in chat.
* `/zab reset`: Resets peak numbers back to current rates.
* `/zab unblock <ip>`: Unblock an IP address.

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

## How It Works

* **Socket-level drops**: Blocked IPs get closed instantly at the Netty socket layer. The server doesn't allocate memory or decode Minecraft packets for them.
* **Real numbers**: Counts actual packets in 50ms buckets without guessing or multiplying. If 40 bots connect, you see 40.
* **Reconnection check**: During attacks, players who never joined before get asked to rejoin once. Real players reconnect and get saved to `verified.txt`, while one-shot bot tools get blocked.
* **Anti-AFK**: If your host shuts down empty servers, `/zab antiafk on` keeps a dummy player connected on localhost to keep the server running.

## Building

Needs Java 8+ and Maven.

```bash
# Windows
build.bat

# Linux / macOS
mvn clean package
```

Jars will be in `bungee/target/` and `bukkit/target/`.

## License

[MIT](LICENSE)
