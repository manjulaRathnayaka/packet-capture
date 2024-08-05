package com.example;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.TcpPort;

import java.io.EOFException;
import java.util.List;
import java.util.concurrent.TimeoutException;

public class App {

    private static final int SNAPLEN = 65536;
    private static final int READ_TIMEOUT = 10;
    private static final int MAX_PACKETS = 1000;

    public static void main(String[] args) {
        try {
            // Get a list of network interfaces
            List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
            if (allDevs.isEmpty()) {
                System.out.println("No NIF to capture.");
                return;
            }

            // Select the first network interface for simplicity
            PcapNetworkInterface nif = allDevs.get(0);
            System.out.println("Using Network Interface: " + nif.getName());

            // Open the network interface for packet capture
            PcapHandle handle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

            int packetCount = 0;
            while (packetCount < MAX_PACKETS) {
                try {
                    Packet packet = handle.getNextPacketEx();
                    if (packet.contains(TcpPacket.class)) {
                        TcpPacket tcpPacket = packet.get(TcpPacket.class);
                        if (tcpPacket.getHeader().getDstPort().equals(TcpPort.HTTP) ||
                            tcpPacket.getHeader().getSrcPort().equals(TcpPort.HTTP)) {
                            System.out.println(packet);
                            packetCount++;
                        }
                    }
                } catch (EOFException e) {
                    System.out.println("EOF: " + e.getMessage());
                    break;
                } catch (TimeoutException e) {
                    // Timeout exception can be ignored
                }
            }

            handle.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
