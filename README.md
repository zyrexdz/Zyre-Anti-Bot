# Zyre Anti Bot (ZAB)

*Inspired by Sonar Antibot.*

Most Minecraft antibots let malicious traffic register into the pipeline, instantiate packet decoders, and spam proxy worker threads with garbage. **Zyre Anti Bot** intercepts connections at the raw Netty transport layer—instantly aborting blacklisted IPs with zero protocol overhead and zero memory allocation.

![Demo](demo.gif)

```bash
git clone https://github.com/your-username/zyre-anti-bot.git && cd zyre-anti-bot && mvn clean package
```

---

## Comparison

| Feature | Generic Antibots | Sonar Antibot | Zyre Anti Bot (ZAB) |
| :--- | :--- | :--- | :--- |
| **Blacklist Drop** | Disconnect packet in pipeline | Netty channel kick | Instant TCP abort (`closeForcibly`) before channel registration |
| **Inspection Overhead** | Decodes full packet wrappers | Partial packet decode | In-place zero-copy `ByteBuf` byte inspection |
| **Memory under attack** | High (allocates per session) | Low | Near-zero (banned IPs allocate 0 objects) |
| **Metrics Calculation** | Lock-heavy / Periodic scans | Rolling counters | Non-blocking `AtomicLongArray` ring buckets (50ms slide) |
| **Attack Verification** | Captcha maps / falling anvils | Reconnect / ping check | Non-intrusive 1.5s rejoin token + handshake integrity |
| **Anti-AFK Simulation** | Separate standalone bot tools | None | Built-in auto-negotiating protocol bot (`/zab antiafk`) |

---

## Quickstart

1. Drop `ZAB-Bungee-1.0.0.jar` into your BungeeCord/Waterfall `plugins/` folder, or `ZAB-Bukkit-1.0.0.jar` into your Paper/Spigot `plugins/` folder.
2. Restart your proxy or server to generate `config.yml`.
3. Join and run `/zab verbose top` or `/zab verbose down` to monitor live traffic.

---

## Commands

All commands require the `zab.admin` permission (defaults to OP on Spigot).

| Command | Description |
| :--- | :--- |
| `/zab verbose [top\|down]` | Toggle the real-time HUD (BossBar on top or Action Bar on bottom). |
| `/zab blacklist <on\|off>` | Toggle bot blocking on or off. Metrics stay 100% active either way. |
| `/zab antiafk [on\|off\|status] [version]` | Toggle or configure the built-in bot to keep the server/proxy awake. |
| `/zab stats` | Print real-time CPS, IPSEC, logins, pings, handshakes, and all-time peaks. |
| `/zab reset` | Reset all peak metric counters. |
| `/zab unblock <ip>` | Manually remove an IP from the temporary blacklist. |

---

## How it Works

```
Incoming TCP SYN
       │
       ▼
[Netty Acceptor] ──(IP Blacklisted?)──► YES ──► ch.unsafe().closeForcibly()  (0 allocations)
       │ NO
       ▼
 [Probe Handler] ──(Strict L7 Validation)
       ├─ VarInt overflow / malformed lengths? ──► Punish & Close
       ├─ HTTP proxy scanning (GET/POST/HEAD)? ──► Punish & Close
       ├─ Invalid username characters / length? ──► Punish & Close
       ├─ Under attack & unverified? ────────────► Reconnect Challenge (Rejoin in 1.5s)
       ▼ Validated
[Minecraft Pipeline] (Spigot / Bungee normal handling)
```

1. **TCP-Level Dropping**: When an IP is blacklisted, it is closed before child channel registration completes. BungeeCord and Spigot never see the connection, no logger lines are generated, and zero memory is retained.
2. **Layer 7 Sanitization**: The probe validates handshake structure, target protocol sanity, and username formatting (`[a-zA-Z0-9_]`, 1-16 chars, Floodgate/Geyser prefixes). Malformed packets immediately punish the sender.
3. **Attack Mode Reconnect**: When CPS exceeds the threshold, unverified players receive a fast disconnect token asking them to rejoin. Regular bots flood once and move on; genuine players automatically reconnect after 1.5s and are immediately whitelisted into `verified.txt`.

---

## Configuration

```yaml
# Connections a single IP can open per second before it gets blacklisted
max-connections-per-ip: 6

# How long a blacklisted IP stays blocked (in minutes)
block-minutes: 5

# Total CPS that triggers attack mode
attack-cps: 40

# Seconds below attack-cps before attack mode turns off
attack-end-seconds: 10

# During attacks, require first-time players to reconnect once to verify
attack-verify: true

# Minimum CPS peak to broadcast in chat alerts
min-peak: 3

# Never blocked (e.g. backend proxy IP, TCPShield, local host)
trusted-ips:
  - 127.0.0.1

# Anti-AFK bot settings
antiafk-port: 0
antiafk-version: "auto"
antiafk-password: "" # Set this if your server uses AuthMe
```

---

## Building from Source

Requirements: Java 8+ and Apache Maven.

```bash
# Windows
build.bat

# Linux / macOS
mvn clean package
```

Output jars will be located in:
- `bungee/target/ZAB-Bungee-1.0.0.jar`
- `bukkit/target/ZAB-Bukkit-1.0.0.jar`

---

*If this saved your server from bot attacks, leave a ⭐ to help others find it!*
