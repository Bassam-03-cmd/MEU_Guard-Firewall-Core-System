// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  packetInformation.h 
/// Abstract:  simple packet information struct definition
/// </summary>
// --------------------------------------------------------------------------------


#pragma once
#include <WS2tcpip.h>

#define ANY_STRING "*"
#define ANY_SHORT 0
#define ANY_IP ANY_STRING
#define ANY_MAC ANY_STRING
#define ANY_PORT -1
#define ANY_PROTO 0

#define IP_ADDRESS std::string
#define MAC_ADDRESS std::string
#define PORT int
#define TIMESTAMP std::chrono::steady_clock::time_point
#define PROTOCOL u_char
#define PACKET_ACTION ndisapi::queued_packet_filter::packet_action


namespace firewall_core {
    struct PacketInformation {
        IP_ADDRESS srcIP;                //source IP in string format
        IP_ADDRESS destIP;           //destination ip in string format
        MAC_ADDRESS srcMAC;               //source MAC in "255:255:255:255:255:255" format
        MAC_ADDRESS destMAC;          //destination MAC in "255:255:255:255:255:255" format
        PORT srcPort;
        PORT destPort;
        PROTOCOL proto;
        PACKET_ACTION action;        

        PacketInformation() {
            srcIP = ANY_IP;
            destIP = ANY_IP;
            srcPort = ANY_PORT;
            destPort = ANY_PORT;
            srcMAC = ANY_MAC;
            destMAC = ANY_MAC;
            proto = ANY_PROTO;
            action = ndisapi::queued_packet_filter::packet_action::pass;
        }


        static MAC_ADDRESS formatMacAddress(const uint8_t* mac) {
            std::ostringstream oss;
            for (int i = 0; i < 6; ++i) {
                if (i != 0) oss << ":";
                oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
            }
            return oss.str();
        }

        /// <summary>
        /// extract all info from the header of the packet
        /// (src/dst IPs, src/dst Ports, src/dst MACs, protocol)
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns> object of PacketInformation Structure </returns>
        static PacketInformation extractPacket(INTERMEDIATE_BUFFER& buffer) {
            //returned packet
            firewall_core::PacketInformation packet;

            auto* ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);

            //MAC src/des
            packet.srcMAC = formatMacAddress(ethernet_header->h_source);
            /*packet.srcMAC = std::to_string(ethernet_header->h_source[0]) + ":"
                + std::to_string(ethernet_header->h_source[1]) + ":"
                + std::to_string(ethernet_header->h_source[2]) + ":"
                + std::to_string(ethernet_header->h_source[3]) + ":"
                + std::to_string(ethernet_header->h_source[4]) + ":"
                + std::to_string(ethernet_header->h_source[5]);
            */

            packet.destMAC = formatMacAddress(ethernet_header->h_dest);
            /*packet.destMAC = std::to_string(ethernet_header->h_dest[0]) + ":"
                + std::to_string(ethernet_header->h_dest[1]) + ":"
                + std::to_string(ethernet_header->h_dest[2]) + ":"
                + std::to_string(ethernet_header->h_dest[3]) + ":"
                + std::to_string(ethernet_header->h_dest[4]) + ":"
                + std::to_string(ethernet_header->h_dest[5]);
            */


            if (ethernet_header->h_proto == ntohs(ETH_P_IP))
            {
                auto* ip_header = reinterpret_cast<iphdr_ptr>(buffer.m_IBuffer + sizeof(ether_header));


                //protocol
                packet.proto = ip_header->ip_p;


                //src/dest ports
                if (ip_header->ip_p == IPPROTO_TCP)
                {
                    auto* tcp_header = reinterpret_cast<tcphdr_ptr>(buffer.m_IBuffer + sizeof(ether_header) + ip_header->ip_hl * 4);
                    packet.srcPort = ntohs(tcp_header->th_sport);
                    packet.destPort = ntohs(tcp_header->th_dport);
                }
                else if (ip_header->ip_p == IPPROTO_UDP)
                {
                    auto* udp_header = reinterpret_cast<udphdr_ptr>(buffer.m_IBuffer + sizeof(ether_header) + ip_header->ip_hl * 4);
                    packet.srcPort = ntohs(udp_header->th_sport);
                    packet.destPort = ntohs(udp_header->th_dport);
                }

                //extract src/dst IPs
                char srcip_str[INET_ADDRSTRLEN]; // Buffer to hold the IP string
                char destip_str[INET_ADDRSTRLEN];
                InetNtopA(AF_INET, &ip_header->ip_src, srcip_str, INET_ADDRSTRLEN); // Converts the IP to a string (ANSI version)
                InetNtopA(AF_INET, &ip_header->ip_dst, destip_str, INET_ADDRSTRLEN);

                packet.srcIP = srcip_str;
                packet.destIP = destip_str;
            }

            return packet;
        }

        PacketInformation(INTERMEDIATE_BUFFER& buffer) {
            PacketInformation p = extractPacket(buffer);
            srcIP = p.srcIP;
            destIP = p.destIP;
            srcPort = p.srcPort;
            destPort = p.destPort;
            srcMAC = p.srcMAC;
            destMAC = p.destMAC;
            proto = p.proto;
            action = p.action;
        }

        static std::string getProtoAsString(u_char proto) {
            static const std::map<u_char, std::string> mp = {
                {IPPROTO_TCP, "TCP"},
                {IPPROTO_UDP, "UDP"},
                {IPPROTO_ICMP, "ICMP"},
                {IPPROTO_GGP, "GGP"},
                {IPPROTO_PUP, "PUP"},
                {IPPROTO_IDP, "IDP"},
                {IPPROTO_ICMPV6, "ICMPV6"},
                {IPPROTO_ND, "UNDP"}
                //LATER... ADD MORE PROTOCOLS
            };

            auto it = mp.find(proto);
            return (it != mp.end()) ? it->second : "Unknown Proto";
        }

        void printPacket() {
            std:: cout << srcIP << ":" << srcPort << ":" << srcMAC << "-->";
            std::cout << destIP << ":" << destPort << ":" << destMAC << "  (" << getProtoAsString(proto) << ")\n";
        }
    };
}
