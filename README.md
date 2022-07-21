# dbus-java-transport-ssh

An extension to [DBus Java](https://github.com/hypfvieh/dbus-java) that allows connection to a remote [DBus](https://en.wikipedia.org/wiki/D-Bus) broker over [SSH](https://en.wikipedia.org/wiki/Secure_Shell). It supports both TCP and Unix domain sockets on the remote side. It uses [Maverick Synergy](https://jadaptive.com/en/products/open-source-java-ssh) for unix domain socket support directly. In this case, a real local domain socket file will not need to be created, eliminating another layer and further decreasing latency.

A DBus Java transport works with `SocketChannel`, so we must be able to access a `SocketChannel` from Maverick Synergy that is on the other end of the SSH session connected to a unix domain socket (or TCP socket) served by a DBus broker. This is achieved by extending Synergy's built in unix domain socket support to provide us with such a channel.

At time of writing, this requires at least `dbus-java-4.1.1-SNAPSHOT` and `maverick-synergy-client-3.1.0-SNAPSHOT`. *Neither of these libraries are available yet, this source is being published for development and review. Watch this space*.


#### Usage

Simply add the `dbus-java-transport-ssh` module to your POM (or other build descriptor).

```xml
<dependency>
    <groupId>com.sshtools</groupId>
    <artifactId>dbus-java-transport-ssh</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

Now choose the appropriate Bus path. 

```java
var address = "ssh:path=/path/to/dbus.socket,username=joeb,via=ssh.acme.com,viaPort=22,password=changeit";
var builder = DBusConnectionBuilder.forAddress(address);

// Add further configuration here, see below

var connection = builder.build();
```

The transport supports both TCP and Unix Domain Socket tunnels. The above syntax (with a `path` parameter) initiates  a unix domain socket tunnel.

The supported parameters are :-

* `via`. The hostname or IP address of the SSH server to connect to.
* `viaPort`. The port on which the server is listening, if different from the default of 22.
* `path`. The path to the domain socket on the remote side. If this is provided, a unix domain socket tunnel will be used.
* `host`. The target host on the remote side where the DBus broker is running. This defaults to `localhost` (i.e. the remote host itself). If this is provided, a TCP socket tunnel will be used.
*  `port`. The target port of the DBus broker on the remote side. Only relevant if `host` is provided.
*  `username`. The username to authenticate as on the SSH server.
*  `password`. The password to use for authentication. **Note, this is not recommended. See the Authentication section below.**
*  `key`. The path to a private key file to use instead of a password.
*  `passphrase`. If file pointed to by `key` above is passphrase protected, this parameter should specify the password. **Note, this is not recommended. See the Authentication section below.**

##### SSH Configuration

You may have further SSH configuration requirements, such as setting preferred ciphers, keys, compression, host key authentication and more.

This is achieved by access the `SshClientContext` Synergy provides. 

```java
SshTransport.setContextConfigurator((ctx) -> {
	ctx.setHostKeyVerification((host, key) -> {
		// TODO Check 'key' here for validity for the host
		return true;
	});
	return ctx;
}, builder.transportConfig());
```
See the Maverick Synergy [documentation](https://jadaptive.com/app/manpage/agent/category/1564757) for more information on configuration.

##### SSH Authentication

Rather than provide sensitive information such as passwords or passphrases in the address string, you can again directly access the transport and configure a custom authenticator.

```java
SshTransport.setAuthenticationConfigurator(
		(auths) -> Arrays.asList(new PasswordAuthenticator(() -> "changeme")),
		builder.transportConfig());
```

See the Maverick Synergy [documentation](https://jadaptive.com/app/manpage/agent/category/1564757) for more information on authentication.

##### DBus Authentication

DBus itself has it's own authentication layer that uses [SASL](https://en.wikipedia.org/wiki/Simple_Authentication_and_Security_Layer).
The SSH transport uses the `EXTERNAL` mechanism. Part of the SASL handshake includes the **UID** of the calling user. The DBus broker checks if the UID matches that of the connection it accepted, and will reject the connection if they do not match.

In the case of an SSH connection, the UID of the local user may be totally different to the UID of the remote user. To overcome this, you must know up-front the UID of the remote user, and provide it when configuring the local DBus connection.

```java
builder.transportConfig().withSaslUid(1000);		
```

 
