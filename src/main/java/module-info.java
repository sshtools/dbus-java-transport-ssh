open module org.freedesktop.dbus.transport.ssh {
	exports com.logonbox.dbus.transport.ssh;
    requires transitive com.sshtools.synergy.jdk16.client;
    requires transitive org.freedesktop.dbus; 
    provides org.freedesktop.dbus.spi.transport.ITransportProvider
            with
            com.logonbox.dbus.transport.ssh.SshTransportProvider;
}