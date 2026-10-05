package dev.zab.core;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.CompositeByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelOption;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public final class NettyHook {
    private static final String ACCEPTOR = "zab-acceptor";
    private static final String PROBE = "zab-probe";
    private static final int MAX_BUFFER = 4096;
    private static final int WAIT = 0, PASS = 1, DROP = 2, RECONNECT = 3;
    private static final byte[] RECONNECT_KICK = loginDisconnect("{\"text\":\"ZAB Anti Bot\",\"bold\":true,\"color\":\"yellow\",\"extra\":["
            + "{\"text\":\"\\n\\nVerifying connection\\u2026\\n\",\"color\":\"gray\",\"bold\":false},"
            + "{\"text\":\"Please reconnect to join.\",\"color\":\"green\"}]}");

    private final Zab zab;
    private final Acceptor acceptor = new Acceptor();
    private final Set<Channel> hooked = new HashSet<>();

    public NettyHook(Zab zab) {
        this.zab = zab;
    }

    public synchronized int inject(Collection<?> listeners) {
        List<Object> copy;
        synchronized (listeners) {
            copy = new ArrayList<>(listeners);
        }
        int added = 0;
        for (Object o : copy) {
            Channel ch = o instanceof ChannelFuture ? ((ChannelFuture) o).channel() : (Channel) o;
            try {
                ch.config().setOption(ChannelOption.SO_BACKLOG, 65535);
            } catch (Throwable ignored) {
            }
            if (ch.pipeline().get(ACCEPTOR) != null) {
                continue;
            }
            ch.pipeline().addFirst(ACCEPTOR, acceptor);
            hooked.add(ch);
            added++;
        }
        return added;
    }

    public synchronized void eject() {
        for (Channel ch : hooked) {
            if (ch.pipeline().get(ACCEPTOR) != null) {
                ch.pipeline().remove(ACCEPTOR);
            }
        }
        hooked.clear();
    }

    private static byte[] loginDisconnect(String json) {
        byte[] text = json.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0x00);
        writeVarInt(body, text.length);
        body.write(text, 0, text.length);
        ByteArrayOutputStream frame = new ByteArrayOutputStream();
        writeVarInt(frame, body.size());
        frame.write(body.toByteArray(), 0, body.size());
        return frame.toByteArray();
    }

    private static void writeVarInt(ByteArrayOutputStream out, int v) {
        while ((v & ~0x7F) != 0) {
            out.write((v & 0x7F) | 0x80);
            v >>>= 7;
        }
        out.write(v);
    }

    @ChannelHandler.Sharable
    private final class Acceptor extends ChannelInboundHandlerAdapter {
        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            if (msg instanceof Channel) {
                Channel ch = (Channel) msg;
                SocketAddress addr = ch.remoteAddress();
                String ip = "";
                if (addr instanceof InetSocketAddress) {
                    InetAddress ia = ((InetSocketAddress) addr).getAddress();
                    ip = ia != null ? ia.getHostAddress() : ((InetSocketAddress) addr).getHostString();
                } else if (addr != null) {
                    ip = addr.toString();
                }
                boolean allowed = zab.connect(ip);
                if (!allowed) {
                    if (zab.isBarely() || zab.isPeak()) {
                        ch.pipeline().addLast(PROBE, new Probe(ip, true));
                    } else {
                        ch.unsafe().closeForcibly();
                        return;
                    }
                } else {
                    ch.pipeline().addLast(PROBE, new Probe(ip, false));
                }
            }
            ctx.fireChannelRead(msg);
        }
    }

    private final class Probe extends ChannelInboundHandlerAdapter {
        private final String ip;
        private final boolean blocked;
        private CompositeByteBuf held;
        private ScheduledFuture<?> timeout;
        private int pos;
        private int state;
        private int vi;
        private boolean done;

        Probe(String ip, boolean blocked) {
            this.ip = ip;
            this.blocked = blocked;
        }

        @Override
        public void channelActive(ChannelHandlerContext ctx) {
            if (blocked) {
                timeout = ctx.executor().schedule((Runnable) ctx::close, 1, TimeUnit.SECONDS);
            } else if (zab.isBlacklistOn() && zab.checks(ip)) {
                timeout = ctx.executor().schedule(() -> {
                    if (zab.isBlacklistOn() && zab.checks(ip)) {
                        ctx.close();
                    } else {
                        pass(ctx);
                    }
                }, 5, TimeUnit.SECONDS);
            }
            ctx.fireChannelActive();
        }

        @Override
        public void handlerRemoved(ChannelHandlerContext ctx) {
            if (timeout != null) {
                timeout.cancel(false);
            }
            if (held != null) {
                held.release();
                held = null;
            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            ctx.close();
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            if (!(msg instanceof ByteBuf)) {
                ctx.fireChannelRead(msg);
                return;
            }
            ByteBuf buf = (ByteBuf) msg;
            zab.addBytes(buf.readableBytes());

            if (blocked) {
                try {
                    inspectHandshake(buf);
                } finally {
                    buf.release();
                    ctx.close();
                }
                return;
            }

            if (!zab.isBlacklistOn()) {
                if (!done) {
                    inspectNonBlocking(buf);
                    if (done) {
                        ctx.pipeline().remove(this);
                    }
                }
                ctx.fireChannelRead(buf);
                return;
            }

            if (held == null) {
                held = ctx.alloc().compositeBuffer();
            }
            held.addComponent(true, buf);

            int verdict = parse();
            if (verdict == WAIT && held.readableBytes() > MAX_BUFFER) {
                verdict = DROP;
            }
            if (verdict == DROP && !zab.checks(ip)) {
                verdict = PASS;
            }
            if (verdict == DROP) {
                zab.punish(ip);
                ctx.close();
            } else if (verdict == RECONNECT) {
                ctx.writeAndFlush(Unpooled.wrappedBuffer(RECONNECT_KICK)).addListener(ChannelFutureListener.CLOSE);
            } else if (verdict == PASS) {
                pass(ctx);
            }
        }

        private void inspectHandshake(ByteBuf buf) {
            try {
                int r = buf.readerIndex();
                int len = buf.readableBytes();
                if (len <= 0) return;

                if (buf.getUnsignedByte(r) == 0xFE) {
                    zab.ping();
                    zab.motd();
                    return;
                }

                int idx = r;
                int pktLen = 0, bytes = 0;
                while (bytes < 5 && idx < r + len) {
                    byte b = buf.getByte(idx++);
                    pktLen |= (b & 0x7F) << (bytes * 7);
                    bytes++;
                    if ((b & 0x80) == 0) break;
                }
                if (bytes == 0 || bytes > 5) return;

                int id = 0, idBytes = 0;
                while (idBytes < 5 && idx < r + len) {
                    byte b = buf.getByte(idx++);
                    id |= (b & 0x7F) << (idBytes * 7);
                    idBytes++;
                    if ((b & 0x80) == 0) break;
                }
                if (idBytes == 0 || idBytes > 5) return;

                if (pktLen == 1 && id == 0) {
                    zab.motd();
                    return;
                }
                if (pktLen == 9 && id == 1) {
                    zab.ping();
                    return;
                }
                if (id != 0 || pktLen < 6) return;

                zab.handshake();

                int protoBytes = 0;
                boolean protoOk = false;
                while (protoBytes < 5 && idx < r + len) {
                    byte b = buf.getByte(idx++);
                    protoBytes++;
                    if ((b & 0x80) == 0) {
                        protoOk = true;
                        break;
                    }
                }
                if (!protoOk) return;

                int strLen = 0, strLenBytes = 0;
                boolean strLenOk = false;
                while (strLenBytes < 5 && idx < r + len) {
                    byte b = buf.getByte(idx++);
                    strLen |= (b & 0x7F) << (strLenBytes * 7);
                    strLenBytes++;
                    if ((b & 0x80) == 0) {
                        strLenOk = true;
                        break;
                    }
                }
                if (!strLenOk || strLen < 0 || strLen > 32767) return;

                idx += strLen + 2;
                if (idx >= r + len) return;

                int nextState = 0, nsBytes = 0;
                boolean nsOk = false;
                while (nsBytes < 5 && idx < r + len) {
                    byte b = buf.getByte(idx++);
                    nextState |= (b & 0x7F) << (nsBytes * 7);
                    nsBytes++;
                    if ((b & 0x80) == 0) {
                        nsOk = true;
                        break;
                    }
                }
                if (!nsOk) return;

                if (nextState == 1) {
                    zab.ping();
                    zab.motd();
                } else if (nextState == 2 || nextState == 3) {
                    zab.login();
                }
            } catch (Exception ignored) {
            }
        }

        private void inspectNonBlocking(ByteBuf buf) {
            try {
                int r = buf.readerIndex();
                int len = buf.readableBytes();
                if (len <= 0) return;

                if (state == 0) {
                    if (buf.getUnsignedByte(r) == 0xFE) {
                        zab.ping();
                        zab.motd();
                        done = true;
                        return;
                    }
                    int idx = r;
                    int pktLen = 0, bytes = 0;
                    while (bytes < 5 && idx < r + len) {
                        byte b = buf.getByte(idx++);
                        pktLen |= (b & 0x7F) << (bytes * 7);
                        bytes++;
                        if ((b & 0x80) == 0) break;
                    }
                    if (bytes == 0 || bytes > 5) return;

                    int id = 0, idBytes = 0;
                    while (idBytes < 5 && idx < r + len) {
                        byte b = buf.getByte(idx++);
                        id |= (b & 0x7F) << (idBytes * 7);
                        idBytes++;
                        if ((b & 0x80) == 0) break;
                    }
                    if (pktLen == 1 && id == 0) {
                        zab.motd();
                        done = true;
                        return;
                    }
                    if (pktLen == 9 && id == 1) {
                        zab.ping();
                        done = true;
                        return;
                    }
                    if (id != 0 || pktLen < 6) {
                        done = true;
                        return;
                    }

                    zab.handshake();

                    int protoBytes = 0;
                    boolean protoOk = false;
                    while (protoBytes < 5 && idx < r + len) {
                        byte b = buf.getByte(idx++);
                        protoBytes++;
                        if ((b & 0x80) == 0) {
                            protoOk = true;
                            break;
                        }
                    }
                    if (!protoOk) return;

                    int strLen = 0, strLenBytes = 0;
                    boolean strLenOk = false;
                    while (strLenBytes < 5 && idx < r + len) {
                        byte b = buf.getByte(idx++);
                        strLen |= (b & 0x7F) << (strLenBytes * 7);
                        strLenBytes++;
                        if ((b & 0x80) == 0) {
                            strLenOk = true;
                            break;
                        }
                    }
                    if (!strLenOk || strLen < 0 || strLen > 32767) return;

                    idx += strLen + 2;
                    if (idx >= r + len) return;

                    int nextState = 0, nsBytes = 0;
                    boolean nsOk = false;
                    while (nsBytes < 5 && idx < r + len) {
                        byte b = buf.getByte(idx++);
                        nextState |= (b & 0x7F) << (nsBytes * 7);
                        nsBytes++;
                        if ((b & 0x80) == 0) {
                            nsOk = true;
                            break;
                        }
                    }
                    if (!nsOk) return;

                    if (nextState == 1) {
                        state = 1;
                        zab.ping();
                    } else if (nextState == 2 || nextState == 3) {
                        state = 2;
                    } else {
                        done = true;
                        return;
                    }

                    int nextPkt = r + bytes + pktLen;
                    if (nextPkt < r + len) {
                        inspectSecondPacket(buf, nextPkt, r + len);
                    }
                    return;
                }

                if (state == 1 || state == 2) {
                    inspectSecondPacket(buf, r, r + len);
                }
            } catch (Exception ignored) {
                done = true;
            }
        }

        private void inspectSecondPacket(ByteBuf buf, int start, int limit) {
            if (start >= limit) return;
            int idx = start;
            int pktLen = 0, bytes = 0;
            while (bytes < 5 && idx < limit) {
                byte b = buf.getByte(idx++);
                pktLen |= (b & 0x7F) << (bytes * 7);
                bytes++;
                if ((b & 0x80) == 0) break;
            }
            if (bytes == 0 || bytes > 5) return;

            int id = 0, idBytes = 0;
            while (idBytes < 5 && idx < limit) {
                byte b = buf.getByte(idx++);
                id |= (b & 0x7F) << (idBytes * 7);
                idBytes++;
                if ((b & 0x80) == 0) break;
            }

            if (state == 2) {
                zab.login();
                done = true;
            } else if (state == 1) {
                if (id == 0) {
                    zab.motd();
                }
                done = true;
            }
        }

        private void pass(ChannelHandlerContext ctx) {
            if (timeout != null) {
                timeout.cancel(false);
            }
            ByteBuf out = held;
            held = null;
            ctx.pipeline().remove(this);
            if (out != null) {
                ctx.fireChannelRead(out);
            }
        }

        private int varInt(int at, int limit) {
            int v = 0;
            for (int i = 0; i < 5; i++) {
                if (at + i >= limit) {
                    return 0;
                }
                byte b = held.getByte(at + i);
                v |= (b & 0x7F) << (7 * i);
                if (b >= 0) {
                    vi = v;
                    return i + 1;
                }
            }
            return -1;
        }

        private int parse() {
            int len = held.writerIndex();
            if (len == 0) {
                return WAIT;
            }
            if (state == 0 && pos == 0 && held.getUnsignedByte(0) == 0xFE && (len == 1 || held.getByte(1) == 0x01)) {
                zab.ping();
                zab.motd();
                return PASS;
            }
            while (true) {
                int n = varInt(pos, len);
                if (n == 0) {
                    return WAIT;
                }
                int size = vi;
                if (n < 0 || size <= 0 || size > MAX_BUFFER) {
                    return DROP;
                }
                int start = pos + n;
                int end = start + size;
                if (end > len) {
                    return WAIT;
                }
                n = varInt(start, end);
                if (n <= 0) {
                    return DROP;
                }
                int id = vi;
                int at = start + n;

                if (state == 1) {
                    if (id == 0) {
                        zab.motd();
                        return PASS;
                    }
                    if (id == 1) {
                        return PASS;
                    }
                    return DROP;
                }
                if (state == 2) {
                    zab.login();
                    if (id != 0 || !validName(at, end)) {
                        return DROP;
                    }
                    return zab.checks(ip) && zab.needsReconnect(ip) ? RECONNECT : PASS;
                }

                if (id != 0) {
                    return DROP;
                }
                n = varInt(at, end);
                if (n <= 0) {
                    return DROP;
                }
                at += n;
                n = varInt(at, end);
                if (n <= 0 || vi < 0 || vi > 32767) {
                    return DROP;
                }
                at += n + vi + 2;
                n = varInt(at, end);
                if (n <= 0 || at + n != end) {
                    return DROP;
                }
                if (vi == 1) {
                    state = 1;
                    zab.handshake();
                    zab.ping();
                } else if (vi == 2 || vi == 3) {
                    state = 2;
                    zab.handshake();
                } else {
                    return DROP;
                }
                pos = end;
            }
        }

        private boolean validName(int at, int end) {
            int n = varInt(at, end);
            if (n <= 0) {
                return false;
            }
            int nameLen = vi;
            at += n;
            if (nameLen < 1 || nameLen > 16 || at + nameLen > end) {
                return false;
            }
            for (int i = 0; i < nameLen; i++) {
                int c = held.getByte(at + i);
                boolean ok = c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                        || (i == 0 && (c == '.' || c == '*'));
                if (!ok) {
                    return false;
                }
            }
            return true;
        }
    }
}
