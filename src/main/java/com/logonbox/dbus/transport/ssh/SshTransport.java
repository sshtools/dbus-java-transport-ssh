package com.logonbox.dbus.transport.ssh;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketOption;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Supplier;

import org.freedesktop.dbus.connections.BusAddress;
import org.freedesktop.dbus.connections.SASL;
import org.freedesktop.dbus.connections.config.TransportConfig;
import org.freedesktop.dbus.connections.config.TransportConfigBuilder;
import org.freedesktop.dbus.connections.transports.AbstractTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sshtools.client.ClientAuthenticator;
import com.sshtools.client.PasswordAuthenticator;
import com.sshtools.client.PrivateKeyFileAuthenticator;
import com.sshtools.client.SshClient;
import com.sshtools.client.SshClient.SshClientBuilder;
import com.sshtools.client.SshClientContext;
import com.sshtools.client.jdk16.UnixDomainSocketClientChannelFactory;
import com.sshtools.client.jdk16.UnixDomainSocketClientForwardingFactory;
import com.sshtools.client.jdk16.UnixDomainSocketRemoteForwardRequestHandler;
import com.sshtools.common.forwarding.ForwardingPolicy;
import com.sshtools.common.logger.Log;
import com.sshtools.common.logger.Log.Level;
import com.sshtools.common.logger.RootLoggerContext;
import com.sshtools.common.nio.WriteOperationRequest;
import com.sshtools.common.ssh.ChannelOpenException;
import com.sshtools.common.ssh.SshConnection;
import com.sshtools.common.ssh.SshException;
import com.sshtools.common.util.ByteArrayWriter;
import com.sshtools.synergy.jdk16.UnixDomainSockets;
import com.sshtools.synergy.ssh.ForwardingChannel;
import com.sshtools.synergy.ssh.SocketForwardingChannel;

public class SshTransport extends AbstractTransport {

	static abstract class DbusLocalForwardingChannel extends ForwardingChannel<SshClientContext> {

		private boolean out = true;
		private final Semaphore sem;
		private final int timeout;

		public DbusLocalForwardingChannel(String channelType, SshConnection con, int timeout) {
			super(channelType, con.getContext().getPolicy(ForwardingPolicy.class).getForwardingMaxPacketSize(),
					con.getContext().getPolicy(ForwardingPolicy.class).getForwardingMaxWindowSize(),
					con.getContext().getPolicy(ForwardingPolicy.class).getForwardingMaxWindowSize(),
					con.getContext().getPolicy(ForwardingPolicy.class).getForwardingMinWindowSize());
			this.timeout = timeout;
			sem = new Semaphore(1);
			try {
				sem.acquire();
			} catch (InterruptedException e) {
				throw new IllegalStateException(e);
			}
		}

		public abstract SocketChannel getSocketChannel();

		public void waitForChannelOpenConfirmation() throws IOException {
			try {
				if (!sem.tryAcquire(1, timeout, TimeUnit.MILLISECONDS))
					throw new IOException("Timed out waiting for channel.");
			} catch (InterruptedException e) {
				throw new IOException("Interrupted.");
			} finally {
				sem.release();
			}
		}

		protected SocketChannel createSocketChannel(SocketAddress localAddr, SocketAddress remoteAddr) {
			return new SocketChannel(null) {

				@Override
				public SocketChannel bind(SocketAddress local) throws IOException {
					throw new UnsupportedOperationException();
				}

				@Override
				public boolean connect(SocketAddress remote) throws IOException {
					throw new UnsupportedOperationException();
				}

				@Override
				public boolean finishConnect() throws IOException {
					throw new UnsupportedOperationException();
				}

				@Override
				public SocketAddress getLocalAddress() throws IOException {
					return localAddr;
				}

				@Override
				public <T> T getOption(SocketOption<T> name) throws IOException {
					throw new IOException("No such option " + name);
				}

				@Override
				public SocketAddress getRemoteAddress() throws IOException {
					return remoteAddr;
				}

				@Override
				public boolean isConnected() {
					return DbusLocalForwardingChannel.this.isConnected();
				}

				@Override
				public boolean isConnectionPending() {
					return false;
				}

				@Override
				public int read(ByteBuffer dst) throws IOException {
					int sz = dst.remaining();
					byte[] b = new byte[sz];
					int r = getInputStream().read(b);
					if (r > -1) {
						dst.put(b, 0, r);
					}
					return r;
				}

				@Override
				public long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
					throw new UnsupportedOperationException();
				}

				@Override
				public <T> SocketChannel setOption(SocketOption<T> name, T value) throws IOException {
					throw new UnsupportedOperationException();
				}

				@Override
				public SocketChannel shutdownInput() throws IOException {
					getInputStream().close();
					return this;
				}

				@Override
				public SocketChannel shutdownOutput() throws IOException {
					out = false;
					return this;
				}

				@Override
				public Socket socket() {
					throw new UnsupportedOperationException();
				}

				@Override
				public Set<SocketOption<?>> supportedOptions() {
					return Collections.emptySet();
				}

				@Override
				public int write(ByteBuffer src) throws IOException {
					if (!out)
						throw new IOException("Closed.");
					int w = src.limit();
					sendChannelDataAndBlock(src);
					return w;
				}

				@Override
				public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
					throw new UnsupportedOperationException();
				}

				@Override
				protected void implCloseSelectableChannel() throws IOException {
					DbusLocalForwardingChannel.this.close();
				}

				@Override
				protected void implConfigureBlocking(boolean block) throws IOException {
					if (!block)
						throw new UnsupportedOperationException();
				}
			};
		}

		@Override
		protected void onChannelClosed() {
		}

		@Override
		protected void onChannelClosing() {
			out = false;
		}

		@Override
		protected void onChannelFree() {
		}

		@Override
		protected void onChannelOpen() {
		}

		@Override
		protected void onChannelOpenConfirmation() {
			sem.release();
		}

		@Override
		protected void onChannelRequest(String arg0, boolean arg1, byte[] arg2) {
			throw new UnsupportedOperationException();
		}

		@Override
		protected void onLocalEOF() {
		}

		@Override
		protected void onRemoteEOF() {
		}

		@Override
		protected byte[] openChannel(byte[] arg0) throws WriteOperationRequest, ChannelOpenException {
			throw new UnsupportedOperationException();
		}
	}

	static class DbusTCPLocalForwardingChannel extends DbusLocalForwardingChannel {

		public DbusTCPLocalForwardingChannel(SshConnection con, String host, int port, int timeout) {
			super(SocketForwardingChannel.LOCAL_FORWARDING_CHANNEL_TYPE, con, timeout);
			hostToConnect = host;
			portToConnect = port;
		}

		@Override
        public SocketChannel getSocketChannel() {
			var localAddr = InetSocketAddress.createUnresolved("localhost", 0);
			var remoteAddr = InetSocketAddress.createUnresolved(hostToConnect, portToConnect);
			return createSocketChannel(localAddr, remoteAddr);
		}

		@Override
        protected byte[] createChannel() throws IOException {
			try(var baw = new ByteArrayWriter()) {
				baw.writeString(hostToConnect);
				baw.writeInt(portToConnect);
				baw.writeString("localhost");
				baw.writeInt(0);
				return baw.toByteArray();
			}
		}
	}

	static class DbusUnixDomainSocketLocalForwardingChannel extends DbusLocalForwardingChannel {

		private final String path;

		public DbusUnixDomainSocketLocalForwardingChannel(SshConnection con, String path, int timeout) {
			super(UnixDomainSockets.DIRECT_STREAM_LOCAL_CHANNEL, con, timeout);
			this.path = path;
		}

		@Override
        public SocketChannel getSocketChannel() {
			var localAddr = UnixDomainSocketAddress.of("/dbus.socket");
			var remoteAddr = UnixDomainSocketAddress.of(path);
			return createSocketChannel(localAddr, remoteAddr);
		}

		@Override
		protected byte[] createChannel() throws IOException {
			try(var baw = new ByteArrayWriter()) {
				baw.writeString(path);
				baw.writeString(""); // Reserved
				baw.writeInt(0); // Reserved
				return baw.toByteArray();
			}
		}
	}

	final static Logger LOG = LoggerFactory.getLogger(SshTransport.class);

	static final String AUTHENTICATOR = "authenticator";
	static final String CONTEXT = "context";
	static final String CLIENT = "client";

	static {
		Log.setDefaultContext(new RootLoggerContext() {

			private Level level;

			@Override
			public void close() {
			}

			@Override
			public void enableConsole(Level level) {
				throw new UnsupportedOperationException();
			}

			@Override
			public void enableFile(Level level, File logFile) {
				throw new UnsupportedOperationException();
			}

			@Override
			public void enableFile(Level level, File logFile, int maxFiles, long maxSize) {
				throw new UnsupportedOperationException();
			}

			@Override
			public void enableFile(Level level, String logFile) {
				throw new UnsupportedOperationException();
			}

			@Override
			public String getProperty(String key, String defaultValue) {
				return defaultValue;
			}

			@Override
			public boolean isLogging(Level level) {
				if (this.level == null) {
					this.level = calcLevel();
				}
				return this.level.compareTo(level) >= 0;
			}

			@Override
			public void log(Level level, String msg, Throwable e, Object... args) {
				switch (level) {
				case DEBUG:
					LOG.debug(format(msg, args), e);
					break;
				case ERROR:
					LOG.error(format(msg, args), e);
					break;
				case INFO:
					LOG.info(format(msg, args), e);
					break;
				case TRACE:
					LOG.trace(format(msg, args), e);
					break;
				case WARN:
					LOG.warn(format(msg, args), e);
					break;
				default:
					break;
				}

			}

			@Override
			public void newline() {
				LOG.info("");
			}

			@Override
			public void raw(Level level, String msg) {
				switch (level) {
				case DEBUG:
					LOG.debug(msg);
					break;
				case ERROR:
					LOG.error(msg);
					break;
				case INFO:
					LOG.info(msg);
					break;
				case TRACE:
					LOG.trace(msg);
					break;
				case WARN:
					LOG.warn(msg);
					break;
				default:
					break;
				}
			}

			@Override
			public void reset() {
			}

			@Override
			public void shutdown() {
			}

			Level calcLevel() {
				if (LOG.isTraceEnabled())
					return Level.TRACE;
				else if (LOG.isDebugEnabled())
					return Level.DEBUG;
				else if (LOG.isInfoEnabled())
					return Level.INFO;
				else if (LOG.isWarnEnabled())
					return Level.WARN;
				else if (LOG.isErrorEnabled())
					return Level.ERROR;
				else
					return Level.NONE;
			}

			String format(String msg, Object... args) {
				int idx = 0;
				while (true) {
					var nmsg = msg.replaceFirst("\\{\\}", "{" + (idx++) + "}");
					if (nmsg.equals(msg))
						break;
					msg = nmsg;
				}
				return MessageFormat.format(msg, args);
			}
		});
	}

	private ServerSocketChannel serverSocket;
	private SocketChannel socket;
	private SshClient ssh;
	private final TransportConfig config;

	SshTransport(BusAddress _address, TransportConfig _config) {
		super(_address, _config);
		config = _config;
		getSaslConfig().setAuthMode(SASL.AUTH_EXTERNAL);
	}

	@Override
	protected void closeTransport() throws IOException {
		getLogger().debug("Disconnecting Transport");
		if (socket != null && socket.isOpen()) {
			socket.close();
		}

		if (serverSocket != null && serverSocket.isOpen()) {
			serverSocket.close();
		}
		
	}

	/**
	 * Connect to DBus using SSH.
	 *
	 * @returns socket channel connected to the remote service (either a TCP socket or a Unix Domain Socket)
	 * @throws IOException on error
	 */
	@Override
	public SocketChannel connectImpl() throws IOException {
		try {
			try {
				var path = getAddress().getParameterValue("path");
				
				var client = getClient(getTransportConfig());
				if(client == null)  {
					createNewClient(path);
				}
				else {
					ssh = client.get();
				}

				DbusLocalForwardingChannel channel;
				if(path == null)
					channel = new DbusTCPLocalForwardingChannel(ssh.getConnection(), ssh.getHost(), ssh.getPort(), config.getTimeout());
				else
					channel = new DbusUnixDomainSocketLocalForwardingChannel(ssh.getConnection(), path, config.getTimeout());
				ssh.getConnection().openChannel(channel);
				channel.waitForChannelOpenConfirmation();
				return channel.getSocketChannel();
			} catch (SshException sshe) {
				throw new IOException("Failed to connect using SSH transport.", sshe);
			}
		} catch (IOException ioe) {
			if (ssh != null) {
				ssh.disconnect();
			}
			/* TODO: This is wrong really... but dbus-java catches IOExceptions
			 * and retries. We do not want this
			 */
			throw new UncheckedIOException(ioe);
		}
	}

	private void createNewClient(String path) throws IOException, SshException {
		var ctx = new SshClientContext();
		ctx.setChannelFactory(new UnixDomainSocketClientChannelFactory());
		ctx.getForwardingManager().setForwardingFactory(new UnixDomainSocketClientForwardingFactory());
		ctx.getForwardingManager()
				.addRemoteForwardRequestHandler(new UnixDomainSocketRemoteForwardRequestHandler());
		var contextConfigurator = getContextConfigurator(config);
		if (contextConfigurator != null)
			ctx = contextConfigurator.apply(ctx);

		var port = 0;
		String host = null;
		if (path == null) {
			host = getAddress().getParameterValue("host", "localhost");
			port = Integer.parseInt(getAddress().getParameterValue("port", "-1"));
			if(port == -1)
				throw new IOException("You must supply a port parameter, which is the port number on which the DBus Broker is listening on the remote side.");
		}

		var username = getAddress().getParameterValue("username", System.getProperty("user.name"));
		var via = getAddress().getParameterValue("via", host);
		if(via == null || via.length() == 0)
			throw new IOException("You must supply a 'via' parameter, which is the address of the SSH server to which this transport should connect.");
		var viaPort = Integer.parseInt(getAddress().getParameterValue("viaPort", "22"));
		var password = getAddress().getParameterValue("password");
		if (password != null) {
			LOG.warn(
					"It is not recommended SSH passwords be part of an address string. Instead, use a private key, an agent, or provide a custom authenticator.");
		}
		var key = getAddress().getParameterValue("key");
		var passphrase = getAddress().getParameterValue("passphrase");
		if (passphrase != null) {
			LOG.warn(
					"It is not recommended SSH passphrase be part of an address string. Instead, use an agent or provide a custom authenticator.");
		}

		List<ClientAuthenticator> auth = new ArrayList<>();
		if (password != null) {
			auth.add(new PasswordAuthenticator(password));
		}
		if (key != null) {
			auth.add(new PrivateKeyFileAuthenticator(new File(key), passphrase));
		}
		var authenticationConfigurator = getAuthenticationConfigurator(config);
		if (authenticationConfigurator != null) {
			auth = authenticationConfigurator.apply(auth);
		}
		auth = new ArrayList<>(auth);

		ssh = SshClientBuilder.create().
		    withTarget(via, viaPort).
		    withUsername(username).
		    withSshContext(ctx).
		    withAuthenticators(auth).
		    onConfigure((cctx) -> {
		       cctx.getForwardingPolicy().allowForwarding();
		       cctx.getForwardingPolicy().add(ForwardingPolicy.UNIX_DOMAIN_SOCKET_FORWARDING);
		    }).
		    build();
	}

	/**
	 * Get the callback used to create clients. All other SSH connection related parameters will
	 * be ignored.
	 *
	 * @return  authenticator configurator.
	 */
	@SuppressWarnings("unchecked")
	public static Supplier<SshClient> getClient(TransportConfig config) {
		return (Supplier<SshClient>) config.getAdditionalConfig().get(CLIENT);
	}

	/**
	 * Set the a callback to create clients. All other SSH connection related parameters will
	 * be ignored.
	 *
	 * @param clientSupplier client supplier.
	 */
	public static void setAuthenticationConfigurator(
			Supplier<SshClient> clientSupplier, TransportConfigBuilder<?, ?> configBuilder) {
		configBuilder.withAdditionalConfig(CLIENT, clientSupplier);
	}

	/**
	 * Get the function that is called before authentication. You can modify the list of authenticators,
	 * or provide an entirely new list.
	 *
	 * @return  authenticator configurator.
	 */
	@SuppressWarnings("unchecked")
	public static Function<List<ClientAuthenticator>, List<ClientAuthenticator>> getAuthenticationConfigurator(TransportConfig config) {
		return (Function<List<ClientAuthenticator>, List<ClientAuthenticator>>) config.getAdditionalConfig().get(AUTHENTICATOR);
	}

	/**
	 * Set a function that is called before authentication. You can modify the list of authenticators,
	 * or provide an entirely new list.
	 *
	 * @param authenticationConfigurator authenticator configurator.
	 */
	public static void setAuthenticationConfigurator(
			Function<List<ClientAuthenticator>, List<ClientAuthenticator>> authenticationConfigurator, TransportConfigBuilder<?, ?> configBuilder) {
		configBuilder.withAdditionalConfig(AUTHENTICATOR, authenticationConfigurator);
	}

	/**
	 * Set the function that is called before connection. You can modify the configuration,
	 * or provide an entirely new object.
	 *
	 * @param contextConfigurator context configurator.
	 */
	public static void setContextConfigurator(
			Function<SshClientContext, SshClientContext> contextConfigurator, TransportConfigBuilder<?, ?> configBuilder) {
		configBuilder.withAdditionalConfig(CONTEXT, contextConfigurator);
	}

	/**
	 * Get the function that is called before connection. You can modify the configuration,
	 * or provide an entirely new object.
	 *
	 * @param contextConfigurator context configurator.
	 */
	@SuppressWarnings("unchecked")
	public static Function<SshClientContext, SshClientContext> getContextConfigurator(TransportConfig config) {
		return (Function<SshClientContext, SshClientContext>) config.getAdditionalConfig().get(CONTEXT);
	}

	@Override
	protected boolean hasFileDescriptorSupport() {
		return false; // file descriptor passing not possible on TCP connections
	}

	@Override
	protected SocketChannel acceptImpl() throws IOException {
		throw new UnsupportedOperationException("The SSH transport is for clients only.");
	}

	@Override
	protected void bindImpl() throws IOException {
		throw new UnsupportedOperationException("The SSH transport is for clients only.");
	}

	@Override
	protected boolean isBound() {
		// TODO Auto-generated method stub
		return false;
	}

}
