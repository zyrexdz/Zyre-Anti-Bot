package dev.zab.core;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.IntSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public final class AntiAfkBot {
    private static final Pattern VERSION_PATTERN = Pattern.compile("(?i)(?:use|on|version|client|server|requires|with|minecraft)[^0-9]*([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)");
    private static final Pattern FALLBACK_PATTERN = Pattern.compile("([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)");
    private static final Pattern PROTOCOL_PATTERN = Pattern.compile("\"protocol\"\\s*:\\s*(\\d+)");

    private final Consumer<String> logger;
    private final IntSupplier defaultPortSupplier;
    private volatile boolean active;
    private volatile Socket socket;
    private Thread thread;
    private volatile String lastStatus = "\u00a7cOffline";
    private int targetPort;
    private String targetHost = "127.0.0.1";
    private volatile int targetProtocol = 754;
    private volatile String password = "";

    public AntiAfkBot(Consumer<String> logger, IntSupplier defaultPortSupplier) {
        this.logger = logger;
        this.defaultPortSupplier = defaultPortSupplier;
    }

    public synchronized void setTargetProtocol(int proto) {
        if (proto > 0) {
            targetProtocol = proto;
            logger.accept("Anti-AFK bot protocol set to " + proto + " (" + protocolToVersion(proto) + ")");
        }
    }

    public void setPassword(String password) {
        this.password = password == null ? "" : password.trim();
    }

    public synchronized void setTargetVersion(String version) {
        int proto = versionToProtocol(version);
        if (proto > 0) {
            targetProtocol = proto;
            logger.accept("Anti-AFK bot version set to " + version + " (protocol " + proto + ")");
        }
    }

    public synchronized String start(int port) {
        if (active) {
            return Zab.PREFIX + "\u00a7eAnti-AFK bot is already running on port " + targetPort + ".";
        }
        if (port <= 0) {
            port = defaultPortSupplier.getAsInt();
        }
        if (port <= 0) {
            port = 25565;
        }
        targetPort = port;
        active = true;
        thread = new Thread(this::runLoop, "ZAB-AntiAFK");
        thread.setDaemon(true);
        thread.start();
        return Zab.PREFIX + "\u00a7aStarted Anti-AFK bot \u00a7fZABAFK \u00a77(" + protocolToVersion(targetProtocol)
                + ") on port \u00a7f" + port + "\u00a7a.";
    }

    public synchronized String stop() {
        if (!active) {
            return Zab.PREFIX + "\u00a77Anti-AFK bot is not running.";
        }
        active = false;
        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        } catch (IOException ignored) {
        }
        if (thread != null) {
            thread.interrupt();
        }
        lastStatus = "\u00a7cOffline";
        return Zab.PREFIX + "\u00a7cAnti-AFK bot \u00a7fZABAFK \u00a7cstopped.";
    }

    public synchronized String toggle() {
        return active ? stop() : start(0);
    }

    public String status() {
        return lastStatus + " \u00a78(" + protocolToVersion(targetProtocol) + "\u00a78)";
    }

    private void runLoop() {
        while (active) {
            boolean fastReconnect = false;
            try {
                lastStatus = "\u00a7eConnecting (" + protocolToVersion(targetProtocol) + ")\u2026";
                int detectedProto = pingProtocol(targetHost, targetPort);
                int protocol = targetProtocol > 0 ? targetProtocol : (detectedProto > 0 ? detectedProto : 754);

                socket = new Socket();
                socket.connect(new InetSocketAddress(targetHost, targetPort), 5000);
                socket.setTcpNoDelay(true);
                socket.setSoTimeout(100);

                InputStream in = new BufferedInputStream(socket.getInputStream());
                OutputStream out = new BufferedOutputStream(socket.getOutputStream());

                ByteArrayOutputStream hsb = new ByteArrayOutputStream();
                writeVarInt(hsb, protocol);
                writeString(hsb, targetHost);
                hsb.write((targetPort >> 8) & 0xFF);
                hsb.write(targetPort & 0xFF);
                writeVarInt(hsb, 2);
                sendPacket(out, 0x00, hsb.toByteArray(), -1);

                ByteArrayOutputStream lsb = new ByteArrayOutputStream();
                writeString(lsb, "ZABAFK");
                if (protocol >= 761 && protocol <= 763) {
                    lsb.write(0);
                } else if (protocol >= 764) {
                    ByteBuffer bb = ByteBuffer.allocate(16);
                    UUID u = UUID.nameUUIDFromBytes("ZABAFK".getBytes(StandardCharsets.UTF_8));
                    bb.putLong(u.getMostSignificantBits());
                    bb.putLong(u.getLeastSignificantBits());
                    lsb.write(bb.array());
                }
                sendPacket(out, 0x00, lsb.toByteArray(), -1);

                int compression = -1;
                boolean inPlay = false;
                boolean inConfig = false;

                double x = 0, y = 64, z = 0;
                float yaw = 0, pitch = 0;
                long lastAction = System.currentTimeMillis();
                boolean jumpUp = false;
                boolean loginSent = false;
                long inPlayTime = 0;

                lastStatus = "\u00a7aConnected as ZABAFK (" + protocolToVersion(protocol) + ")";
                logger.accept("Anti-AFK bot ZABAFK connected to " + targetHost + ":" + targetPort + " using " + protocolToVersion(protocol));

                while (active && !socket.isClosed()) {
                    try {
                        Packet pkt = readPacket(in, compression);
                        if (pkt != null) {
                            if (!inPlay && !inConfig) {
                                if (pkt.id == 0x03) {
                                    compression = readVarInt(new ByteArrayInputStream(pkt.data));
                                } else if (pkt.id == 0x02) {
                                    if (protocol >= 764) {
                                        inConfig = true;
                                        sendPacket(out, 0x03, new byte[0], compression);
                                    } else {
                                        inPlay = true;
                                        inPlayTime = System.currentTimeMillis();
                                    }
                                } else if (pkt.id == 0x00) {
                                    if (checkKickMessage(pkt.data)) {
                                        fastReconnect = true;
                                    }
                                    break;
                                }
                            } else if (inConfig) {
                                if (pkt.id == 0x02) {
                                    sendPacket(out, 0x02, new byte[0], compression);
                                    inConfig = false;
                                    inPlay = true;
                                    inPlayTime = System.currentTimeMillis();
                                } else if (pkt.id == 0x01) {
                                    sendPacket(out, 0x01, pkt.data, compression);
                                }
                            } else {
                                if (checkKickMessage(pkt.data)) {
                                    fastReconnect = true;
                                    break;
                                }
                                if (isServerKeepAlive(protocol, pkt.id, pkt.data.length)) {
                                    int cKaId = getClientKeepAliveId(protocol);
                                    sendPacket(out, cKaId, pkt.data, compression);
                                }
                                if (isServerTeleport(protocol, pkt.id, pkt.data.length)) {
                                    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(pkt.data));
                                    try {
                                        x = dis.readDouble();
                                        y = dis.readDouble();
                                        z = dis.readDouble();
                                        yaw = dis.readFloat();
                                        pitch = dis.readFloat();
                                        dis.readByte();
                                        if (protocol >= 107) {
                                            int tpId = readVarInt(dis);
                                            ByteArrayOutputStream tpBuf = new ByteArrayOutputStream();
                                            writeVarInt(tpBuf, tpId);
                                            sendPacket(out, 0x00, tpBuf.toByteArray(), compression);
                                        }
                                    } catch (Exception ignored) {
                                    }
                                }
                            }
                        }
                    } catch (java.net.SocketTimeoutException ignored) {
                    }

                    long now = System.currentTimeMillis();
                    if (inPlay && !loginSent && !password.isEmpty() && inPlayTime > 0 && now - inPlayTime > 1500) {
                        loginSent = true;
                        sendChat(out, protocol, "/register " + password + " " + password, compression);
                        sendChat(out, protocol, "/login " + password, compression);
                    }
                    if (inPlay && now - lastAction >= 2000) {
                        lastAction = now;
                        jumpUp = !jumpUp;
                        yaw = (yaw + 25f) % 360f;
                        double curY = jumpUp ? (y + 0.42) : y;
                        boolean onGround = !jumpUp;

                        sendPlayerPosLook(out, protocol, x, curY, z, yaw, pitch, onGround, compression);
                        sendSwingArm(out, protocol, compression);
                    }
                }
            } catch (Exception ignored) {
            } finally {
                try {
                    if (socket != null && !socket.isClosed()) {
                        socket.close();
                    }
                } catch (IOException ignored) {
                }
                if (active) {
                    long sleepMs = fastReconnect ? 500 : 4000;
                    lastStatus = "\u00a7eReconnecting in " + (sleepMs / 1000.0) + "s\u2026";
                    try {
                        Thread.sleep(sleepMs);
                    } catch (InterruptedException ignored) {
                    }
                } else {
                    lastStatus = "\u00a7cOffline";
                }
            }
        }
    }

    public boolean checkKickMessage(byte[] data) {
        if (data == null || data.length == 0) return false;
        try {
            String text = new String(data, StandardCharsets.UTF_8);
            return checkKickString(text);
        } catch (Exception ignored) {
        }
        return false;
    }

    public boolean checkKickString(String text) {
        if (text == null || text.isEmpty()) return false;
        try {
            String clean = text.replaceAll("\u00a7[0-9a-fk-orA-FK-OR]", "");
            if (clean.contains("Outdated") || clean.contains("Please use") || clean.contains("still on")
                    || clean.contains("version") || clean.contains("client") || clean.contains("server")) {
                Matcher m = VERSION_PATTERN.matcher(clean);
                if (m.find()) {
                    String ver = m.group(1);
                    int proto = versionToProtocol(ver);
                    if (proto > 0 && proto != targetProtocol) {
                        logger.accept("Anti-AFK detected required server version: " + ver + " (protocol " + proto + "). Auto-switching\u2026");
                        targetProtocol = proto;
                        return true;
                    }
                }
                Matcher fallback = FALLBACK_PATTERN.matcher(clean);
                while (fallback.find()) {
                    String ver = fallback.group(1);
                    int proto = versionToProtocol(ver);
                    if (proto > 0 && proto != targetProtocol) {
                        logger.accept("Anti-AFK detected required server version: " + ver + " (protocol " + proto + "). Auto-switching\u2026");
                        targetProtocol = proto;
                        return true;
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    private int pingProtocol(String host, int port) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), 2500);
            s.setSoTimeout(2500);
            OutputStream out = s.getOutputStream();
            InputStream in = s.getInputStream();

            ByteArrayOutputStream hsb = new ByteArrayOutputStream();
            int sendProto = targetProtocol > 0 ? targetProtocol : 754;
            writeVarInt(hsb, sendProto);
            writeString(hsb, host);
            hsb.write((port >> 8) & 0xFF);
            hsb.write(port & 0xFF);
            writeVarInt(hsb, 1);
            sendPacket(out, 0x00, hsb.toByteArray(), -1);

            sendPacket(out, 0x00, new byte[0], -1);

            int len = readVarInt(in);
            byte[] data = new byte[len];
            int r = 0;
            while (r < len) {
                int n = in.read(data, r, len - r);
                if (n == -1) break;
                r += n;
            }
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            int id = readVarInt(bais);
            if (id == 0x00) {
                String json = readString(bais, 32767);
                Matcher m = PROTOCOL_PATTERN.matcher(json);
                if (m.find()) {
                    return Integer.parseInt(m.group(1));
                }
            }
        } catch (Exception ignored) {
        }
        return 0;
    }

    public static int versionToProtocol(String ver) {
        if (ver == null) return 0;
        ver = ver.trim();
        if (ver.contains("-")) {
            ver = ver.split("-")[0];
        }
        if (ver.startsWith("v") || ver.startsWith("V")) {
            ver = ver.substring(1);
        }
        try {
            int direct = Integer.parseInt(ver);
            if (direct > 0 && direct < 1000) return direct;
        } catch (NumberFormatException ignored) {
        }
        switch (ver) {
            case "1.8": case "1.8.8": case "1.8.9": return 47;
            case "1.9": return 107;
            case "1.9.1": return 108;
            case "1.9.2": return 109;
            case "1.9.4": return 110;
            case "1.10": case "1.10.1": case "1.10.2": return 210;
            case "1.11": return 315;
            case "1.11.1": case "1.11.2": return 316;
            case "1.12": return 335;
            case "1.12.1": return 338;
            case "1.12.2": return 340;
            case "1.13": return 393;
            case "1.13.1": return 401;
            case "1.13.2": return 404;
            case "1.14": return 477;
            case "1.14.1": return 480;
            case "1.14.2": return 485;
            case "1.14.3": return 490;
            case "1.14.4": return 498;
            case "1.15": return 573;
            case "1.15.1": return 575;
            case "1.15.2": return 578;
            case "1.16": return 735;
            case "1.16.1": return 736;
            case "1.16.2": return 751;
            case "1.16.3": return 753;
            case "1.16.4": case "1.16.5": return 754;
            case "1.17": return 755;
            case "1.17.1": return 756;
            case "1.18": case "1.18.1": return 757;
            case "1.18.2": return 758;
            case "1.19": case "1.19.1": case "1.19.2": return 760;
            case "1.19.3": return 761;
            case "1.19.4": return 762;
            case "1.20": case "1.20.1": return 763;
            case "1.20.2": return 764;
            case "1.20.3": case "1.20.4": return 765;
            case "1.20.5": case "1.20.6": return 766;
            case "1.21": case "1.21.1": return 767;
            case "1.21.2": case "1.21.3": return 768;
            case "1.21.4": return 769;
            case "26.1": case "1.26.1": return 775;
            case "26.2": case "1.26.2": return 776;
            case "26.3": case "1.26.3": return 777;
            default:
                if (ver.startsWith("26.2") || ver.startsWith("1.26.2")) return 776;
                if (ver.startsWith("26.1") || ver.startsWith("1.26.1")) return 775;
                if (ver.startsWith("26") || ver.startsWith("1.26")) return 776;
                if (ver.startsWith("1.21")) return 767;
                if (ver.startsWith("1.20")) return 765;
                if (ver.startsWith("1.19")) return 762;
                if (ver.startsWith("1.18")) return 758;
                if (ver.startsWith("1.17")) return 756;
                if (ver.startsWith("1.16")) return 754;
                if (ver.startsWith("1.15")) return 578;
                if (ver.startsWith("1.14")) return 498;
                if (ver.startsWith("1.12")) return 340;
                if (ver.startsWith("1.8")) return 47;
                return 0;
        }
    }

    public static String protocolToVersion(int proto) {
        if (proto == 776) return "26.2";
        if (proto == 775) return "26.1";
        if (proto == 767) return "1.21";
        if (proto == 765) return "1.20.4";
        if (proto == 754) return "1.16.5";
        if (proto == 340) return "1.12.2";
        if (proto == 47) return "1.8.x";
        return "protocol " + proto;
    }

    private static void sendPlayerPosLook(OutputStream out, int protocol, double x, double y, double z,
                                          float yaw, float pitch, boolean onGround, int compression) throws IOException {
        int id;
        if (protocol <= 47) id = 0x06;
        else if (protocol <= 316) id = 0x0D;
        else if (protocol <= 340) id = 0x10;
        else if (protocol <= 404) id = 0x12;
        else if (protocol <= 578) id = 0x12;
        else if (protocol <= 754) id = 0x13;
        else if (protocol <= 758) id = 0x12;
        else if (protocol <= 763) id = 0x15;
        else if (protocol <= 765) id = 0x18;
        else id = 0x1B;

        ByteArrayOutputStream b = new ByteArrayOutputStream();
        DataOutputStream d = new DataOutputStream(b);
        d.writeDouble(x);
        d.writeDouble(y);
        d.writeDouble(z);
        d.writeFloat(yaw);
        d.writeFloat(pitch);
        d.writeBoolean(onGround);
        sendPacket(out, id, b.toByteArray(), compression);
    }

    private static void sendSwingArm(OutputStream out, int protocol, int compression) throws IOException {
        int id;
        if (protocol <= 47) id = 0x0A;
        else if (protocol <= 316) id = 0x1A;
        else if (protocol <= 340) id = 0x1D;
        else if (protocol <= 578) id = 0x2A;
        else if (protocol <= 758) id = 0x2C;
        else if (protocol <= 763) id = 0x2F;
        else if (protocol <= 765) id = 0x36;
        else id = 0x38;

        ByteArrayOutputStream b = new ByteArrayOutputStream();
        if (protocol > 47) {
            writeVarInt(b, 0);
        }
        sendPacket(out, id, b.toByteArray(), compression);
    }

    private static void sendChat(OutputStream out, int protocol, String msg, int compression) throws IOException {
        int id;
        if (protocol <= 47) id = 0x01;
        else if (protocol <= 404) id = 0x02;
        else if (protocol <= 758) id = 0x03;
        else return;

        ByteArrayOutputStream b = new ByteArrayOutputStream();
        writeString(b, msg);
        sendPacket(out, id, b.toByteArray(), compression);
    }

    private static boolean isServerKeepAlive(int protocol, int id, int len) {
        if (protocol <= 47) return id == 0x00 && len <= 5;
        if (protocol <= 316) return id == 0x1F && len <= 5;
        if (len != 8) return false;
        if (protocol <= 340) return id == 0x1F;
        if (protocol <= 404) return id == 0x21;
        if (protocol <= 578) return id == 0x20;
        if (protocol <= 736) return id == 0x20;
        if (protocol <= 754) return id == 0x1F;
        if (protocol <= 758) return id == 0x21;
        if (protocol <= 760) return id == 0x1E;
        if (protocol <= 761) return id == 0x1F;
        if (protocol <= 763) return id == 0x23;
        if (protocol <= 765) return id == 0x24;
        return id == 0x26;
    }

    private static int getClientKeepAliveId(int protocol) {
        if (protocol <= 47) return 0x00;
        if (protocol <= 316) return 0x0B;
        if (protocol <= 340) return 0x0C;
        if (protocol <= 404) return 0x0E;
        if (protocol <= 578) return 0x0F;
        if (protocol <= 754) return 0x10;
        if (protocol <= 758) return 0x0F;
        if (protocol <= 760) return 0x11;
        if (protocol <= 763) return 0x12;
        if (protocol <= 765) return 0x15;
        return 0x18;
    }

    private static boolean isServerTeleport(int protocol, int id, int len) {
        if (len < 33) return false;
        if (protocol <= 47) return id == 0x08;
        if (protocol <= 340) return id == 0x2F;
        if (protocol <= 404) return id == 0x32;
        if (protocol <= 498) return id == 0x35;
        if (protocol <= 578) return id == 0x36;
        if (protocol <= 754) return id == 0x34;
        if (protocol <= 758) return id == 0x38;
        if (protocol <= 761) return id == 0x36;
        if (protocol <= 763) return id == 0x38;
        if (protocol <= 765) return id == 0x3E;
        return id == 0x40;
    }

    private static final class Packet {
        final int id;
        final byte[] data;

        Packet(int id, byte[] data) {
            this.id = id;
            this.data = data;
        }
    }

    private static Packet readPacket(InputStream in, int compressionThreshold) throws IOException {
        int packetLength = readVarInt(in);
        byte[] packetData = new byte[packetLength];
        int r = 0;
        while (r < packetLength) {
            int n = in.read(packetData, r, packetLength - r);
            if (n == -1) throw new EOFException();
            r += n;
        }
        ByteArrayInputStream bais = new ByteArrayInputStream(packetData);
        byte[] actualPayload;
        if (compressionThreshold >= 0) {
            int dataLength = readVarInt(bais);
            if (dataLength == 0) {
                actualPayload = new byte[bais.available()];
                bais.read(actualPayload);
            } else {
                Inflater inflater = new Inflater();
                byte[] compBytes = new byte[bais.available()];
                bais.read(compBytes);
                inflater.setInput(compBytes);
                actualPayload = new byte[dataLength];
                try {
                    inflater.inflate(actualPayload);
                } catch (Exception ex) {
                    throw new IOException(ex);
                } finally {
                    inflater.end();
                }
            }
        } else {
            actualPayload = packetData;
        }
        ByteArrayInputStream pktIn = new ByteArrayInputStream(actualPayload);
        int packetId = readVarInt(pktIn);
        byte[] body = new byte[pktIn.available()];
        pktIn.read(body);
        return new Packet(packetId, body);
    }

    private static void sendPacket(OutputStream out, int packetId, byte[] payload, int compressionThreshold) throws IOException {
        ByteArrayOutputStream pkt = new ByteArrayOutputStream();
        writeVarInt(pkt, packetId);
        if (payload != null && payload.length > 0) {
            pkt.write(payload);
        }
        byte[] uncompressed = pkt.toByteArray();

        if (compressionThreshold < 0) {
            writeVarInt(out, uncompressed.length);
            out.write(uncompressed);
        } else {
            if (uncompressed.length < compressionThreshold) {
                ByteArrayOutputStream frame = new ByteArrayOutputStream();
                writeVarInt(frame, 0);
                frame.write(uncompressed);
                byte[] frameBytes = frame.toByteArray();
                writeVarInt(out, frameBytes.length);
                out.write(frameBytes);
            } else {
                Deflater deflater = new Deflater();
                deflater.setInput(uncompressed);
                deflater.finish();
                ByteArrayOutputStream compOut = new ByteArrayOutputStream();
                byte[] buf = new byte[512];
                while (!deflater.finished()) {
                    int count = deflater.deflate(buf);
                    compOut.write(buf, 0, count);
                }
                deflater.end();
                byte[] compressed = compOut.toByteArray();

                ByteArrayOutputStream frame = new ByteArrayOutputStream();
                writeVarInt(frame, uncompressed.length);
                frame.write(compressed);
                byte[] frameBytes = frame.toByteArray();
                writeVarInt(out, frameBytes.length);
                out.write(frameBytes);
            }
        }
        out.flush();
    }

    private static void writeVarInt(OutputStream out, int value) throws IOException {
        while ((value & 0xFFFFFF80) != 0) {
            out.write((value & 0x7F) | 0x80);
            value >>>= 7;
        }
        out.write(value & 0x7F);
    }

    private static int readVarInt(InputStream in) throws IOException {
        int out = 0;
        int bytes = 0;
        byte inByte;
        while (true) {
            int b = in.read();
            if (b == -1) throw new EOFException();
            inByte = (byte) b;
            out |= (inByte & 0x7F) << (bytes++ * 7);
            if (bytes > 5) throw new IOException("VarInt too big");
            if ((inByte & 0x80) != 0x80) break;
        }
        return out;
    }

    private static void writeString(OutputStream out, String s) throws IOException {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        writeVarInt(out, b.length);
        out.write(b);
    }

    private static String readString(InputStream in, int maxLen) throws IOException {
        int len = readVarInt(in);
        if (len > maxLen * 4 || len < 0) throw new IOException("String too long");
        byte[] b = new byte[len];
        int read = 0;
        while (read < len) {
            int r = in.read(b, read, len - read);
            if (r == -1) throw new EOFException();
            read += r;
        }
        return new String(b, StandardCharsets.UTF_8);
    }
}
