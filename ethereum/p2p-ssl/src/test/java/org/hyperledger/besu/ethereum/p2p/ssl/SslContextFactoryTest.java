/*
 * Copyright ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.ethereum.p2p.ssl;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.ethereum.p2p.ssl.keystore.HardwareKeyStoreWrapper;
import org.hyperledger.besu.ethereum.p2p.ssl.keystore.KeyStoreWrapper;
import org.hyperledger.besu.ethereum.p2p.ssl.keystore.SoftwareKeyStoreWrapper;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.springframework.util.SocketUtils;

@RunWith(Parameterized.class)
public class SslContextFactoryTest {

  private static final String JKS = "JKS";
  private static final String validKeystorePassword = "test123";
  private static final String partner1client1PKCS11Config =
      "/keys/partner1client1/partner1client1.cfg";
  private static final String partner1client1JKSKeystore =
      "/keys/partner1client1/partner1client1.jks";
  private static final String partner1client1JKSTruststore =
      "/keys/partner1client1/partner1client1-truststore.jks";
  private static final String partner2client1JKSKeystore =
      "/keys/partner2client1/partner2client1.jks";
  private static final String partner2client1JKSTruststore =
      "/keys/partner2client1/partner2client1-truststore.jks";
  private static final String invalidPartner1client1JKSKeystore =
      "/keys/invalidpartner1client1/invalidpartner1client1.jks";
  private static final String invalidPartner1client1JKSTruststore =
      "/keys/invalidpartner1client1/invalidpartner1client1-truststore.jks";

  private static final Logger LOG = LogManager.getLogger();

  private static final int MAX_NUMBER_MESSAGES = 10;

  private static int port;
  private Server server;
  private Client client;

  @Parameterized.Parameter public String keyStoreWrapperDescription;

  @Parameterized.Parameter(1)
  public boolean testSuccess;

  @Parameterized.Parameter(2)
  public KeyStoreWrapper serverKeyStoreWrapper;

  @Parameterized.Parameter(3)
  public KeyStoreWrapper clientKeyStoreWrapper;

  @Parameterized.Parameters(name = "{index}: {0}")
  public static Collection<Object[]> data() {
    return Arrays.asList(
        new Object[][] {
          {
            "JKS serverPartner1Client1 -> JKS clientPartner2Client1 SuccessfulConnection",
            true,
            getSoftwareKeyStoreWrapper(partner1client1JKSKeystore, partner1client1JKSTruststore),
            getSoftwareKeyStoreWrapper(partner2client1JKSKeystore, partner2client1JKSTruststore)
          },
          {
            "JKS serverPartner2Client1 -> JKS clientPartner1Client1 SuccessfulConnection",
            true,
            getSoftwareKeyStoreWrapper(partner2client1JKSKeystore, partner2client1JKSTruststore),
            getSoftwareKeyStoreWrapper(partner1client1JKSKeystore, partner1client1JKSTruststore)
          },
          {
            "PKCS11 serverPartner1Client1 -> JKS clientPartner2Client1 SuccessfulConnection",
            true,
            getHardwareKeyStoreWrapper(partner1client1PKCS11Config),
            getSoftwareKeyStoreWrapper(partner2client1JKSKeystore, partner2client1JKSTruststore)
          },
          {
            "JKS serverPartner1Client1 -> JKS clientInvalidPartner1Client1 FailedConnection",
            false,
            getSoftwareKeyStoreWrapper(partner1client1JKSKeystore, partner1client1JKSTruststore),
            getSoftwareKeyStoreWrapper(
                invalidPartner1client1JKSKeystore, invalidPartner1client1JKSTruststore)
          },
          {
            "JKS serverInvalidPartner1Client1 -> JKS clientPartner1Client1 FailedConnection",
            false,
            getSoftwareKeyStoreWrapper(
                invalidPartner1client1JKSKeystore, invalidPartner1client1JKSTruststore),
            getSoftwareKeyStoreWrapper(partner1client1JKSKeystore, partner1client1JKSTruststore)
          },
          {
            "PKCS11 serverPartner1Client1 -> JKS clientInvalidPartner1Client1 FailedConnection",
            false,
            getHardwareKeyStoreWrapper(partner1client1PKCS11Config),
            getSoftwareKeyStoreWrapper(
                invalidPartner1client1JKSKeystore, invalidPartner1client1JKSTruststore)
          }
        });
  }

  @Before
  public void init() throws IOException, InterruptedException {
    port = SocketUtils.findAvailableTcpPort(49152);
  }

  @After
  public void tearDown() {
    port = SocketUtils.findAvailableTcpPort(49152);
    if (client != null) {
      client.stop();
    }
    if (server != null) {
      server.stop();
    }
  }

  private static Path toPath(final String path) throws Exception {
    return Path.of(SslContextFactoryTest.class.getResource(path).toURI());
  }

  private static KeyStoreWrapper getHardwareKeyStoreWrapper(final String config) {
    try {
      return new HardwareKeyStoreWrapper(validKeystorePassword, toPath(config));
    } catch (Exception e) {
      throw new CryptoRuntimeException("Failed to initialize hardware keystore", e);
    }
  }

  private static KeyStoreWrapper getSoftwareKeyStoreWrapper(
      final String jksKeyStore, final String trustStore) {
    try {
      return new SoftwareKeyStoreWrapper(
          JKS, toPath(jksKeyStore), validKeystorePassword, JKS, toPath(trustStore), null);
    } catch (Exception e) {
      throw new CryptoRuntimeException("Failed to initialize software keystore", e);
    }
  }

  @Test
  public void testConnection() throws Exception {
    final CountDownLatch serverLatch = new CountDownLatch(MAX_NUMBER_MESSAGES);
    final CountDownLatch clientLatch = new CountDownLatch(MAX_NUMBER_MESSAGES);
    server = startServer(port, serverKeyStoreWrapper, serverLatch);
    client = startClient(port, clientKeyStoreWrapper, clientLatch);

    if (testSuccess) {
      client.getChannelFuture().channel().writeAndFlush(Unpooled.copyInt(0));
      final boolean allMessagesServerExchanged = serverLatch.await(10, TimeUnit.SECONDS);
      final boolean allMessagesClientExchanged = clientLatch.await(10, TimeUnit.SECONDS);
      assertThat(allMessagesClientExchanged && allMessagesServerExchanged).isTrue();
    } else {
      try {
        client.getChannelFuture().channel().writeAndFlush(Unpooled.copyInt(0)).sync();
        serverLatch.await(2, TimeUnit.SECONDS);
        assertThat(client.getChannelFuture().channel().isActive()).isFalse();
      } catch (Exception e) {
        // NOOP
      }
    }
  }

  private Server startServer(
      final int port, final KeyStoreWrapper keyStoreWrapper, final CountDownLatch latch)
      throws Exception {

    final Server nettyServer = new Server(port, validKeystorePassword, keyStoreWrapper, latch);
    nettyServer.start();
    return nettyServer;
  }

  private Client startClient(
      final int port, final KeyStoreWrapper keyStoreWrapper, final CountDownLatch latch)
      throws Exception {

    final Client nettyClient = new Client(port, validKeystorePassword, keyStoreWrapper, latch);
    nettyClient.start();
    return nettyClient;
  }

  static class MessageHandler extends ChannelInboundHandlerAdapter {
    private final String id;
    private final CountDownLatch latch;

    public MessageHandler(final String id, final CountDownLatch latch) {
      this.id = id;
      this.latch = latch;
    }

    @Override
    public void channelRead(final ChannelHandlerContext ctx, final Object msg)
        throws InterruptedException {
      final int message = ((ByteBuf) msg).readInt();
      LOG.info("[" + id + "] Received message: " + message);

      if (message < 2 * MAX_NUMBER_MESSAGES) {
        final int replyMessage = message + 1;
        ctx.writeAndFlush(Unpooled.copyInt(replyMessage)).sync();
        LOG.info("[" + id + "] Sent message: " + replyMessage);
        this.latch.countDown();
        LOG.info("Remaining {}", this.latch.getCount());
      }
    }
  }

  static class Client {
    int port;
    private final String keystorePassword;
    private final KeyStoreWrapper keyStoreWrapper;
    private final CountDownLatch latch;

    private ChannelFuture channelFuture;
    private final EventLoopGroup group = new NioEventLoopGroup();

    public ChannelFuture getChannelFuture() {
      return channelFuture;
    }

    Client(
        final int port,
        final String keystorePassword,
        final KeyStoreWrapper keyStoreWrapper,
        final CountDownLatch latch) {
      this.port = port;
      this.keystorePassword = keystorePassword;
      this.keyStoreWrapper = keyStoreWrapper;
      this.latch = latch;
    }

    void start() throws Exception {
      final Bootstrap b = new Bootstrap();
      b.group(group);
      b.channel(NioSocketChannel.class);
      b.handler(
          new ChannelInitializer<SocketChannel>() {
            @Override
            protected void initChannel(final SocketChannel socketChannel) throws Exception {
              SslContext sslContext =
                  SslContextFactory.getInstance(keystorePassword, keyStoreWrapper, null, null, null)
                      .createNettyClientSslContext();

              final SslHandler sslHandler = sslContext.newHandler(socketChannel.alloc());
              socketChannel.pipeline().addFirst("ssl", sslHandler);

              socketChannel.pipeline().addLast(new MessageHandler("Client", latch));
            }
          });

      final ChannelFuture cf = b.connect("127.0.0.1", this.port).sync();
      this.channelFuture = cf;
    }

    public void stop() {
      group.shutdownGracefully();
    }
  }

  static class Server {
    private final int port;
    private final String keystorePassword;
    private final KeyStoreWrapper keyStoreWrapper;
    private final CountDownLatch latch;

    private Channel channel;
    private ChannelFuture channelFuture;

    private final EventLoopGroup parentGroup = new NioEventLoopGroup();
    private final EventLoopGroup childGroup = new NioEventLoopGroup();

    Server(
        final int port,
        final String keystorePassword,
        final KeyStoreWrapper keyStoreWrapper,
        final CountDownLatch latch) {
      this.port = port;
      this.keystorePassword = keystorePassword;
      this.keyStoreWrapper = keyStoreWrapper;
      this.latch = latch;
    }

    public ChannelFuture getChannelFuture() {
      return channelFuture;
    }

    void start() throws Exception {
      final ServerBootstrap sb = new ServerBootstrap();
      sb.group(parentGroup, childGroup)
          .channel(NioServerSocketChannel.class)
          .childHandler(
              new ChannelInitializer<SocketChannel>() {
                @Override
                public void initChannel(final SocketChannel socketChannel) throws Exception {
                  SslContext sslContext =
                      SslContextFactory.getInstance(
                              keystorePassword, keyStoreWrapper, null, null, null)
                          .createNettyServerSslContext();
                  final SslHandler sslHandler = sslContext.newHandler(channel.alloc());
                  socketChannel.pipeline().addFirst("ssl", sslHandler);

                  socketChannel.pipeline().addLast(new MessageHandler("Server", latch));
                }
              });

      final ChannelFuture cf = sb.bind(port).sync();
      this.channel = cf.channel();
      this.channelFuture = cf;
    }

    public void stop() {
      childGroup.shutdownGracefully();
      parentGroup.shutdownGracefully();
    }
  }
}
