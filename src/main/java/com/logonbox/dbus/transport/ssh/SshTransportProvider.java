package com.logonbox.dbus.transport.ssh;

import org.freedesktop.dbus.connections.BusAddress;
import org.freedesktop.dbus.connections.config.TransportConfig;
import org.freedesktop.dbus.connections.transports.AbstractTransport;
import org.freedesktop.dbus.exceptions.TransportConfigurationException;
import org.freedesktop.dbus.spi.transport.ITransportProvider;

public class SshTransportProvider implements ITransportProvider {

	@Override
	public String getTransportName() {
		return "dbus-java-transport-ssh";
	}

	@Override
	public String getSupportedBusType() {
		return "SSH";
	}

	@Override
	public String createDynamicSessionAddress(boolean _listeningSocket) {
		throw new IllegalArgumentException("The SSH transport does not support dynamic addresses.");
	}

	@Override
	public AbstractTransport createTransport(BusAddress _address, TransportConfig _config)
			throws TransportConfigurationException {
		return new SshTransport(_address, _config);
	}

}
