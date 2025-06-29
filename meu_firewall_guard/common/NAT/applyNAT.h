#pragma once
namespace NAT {
    inline bool ParseMACAddress(const std::string& macStr, uint8_t mac[6]) {
        try {
            return sscanf(macStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6;
        }
        catch (const std::exception& e) {
            std::cout << "COULDNT PARSE MAC Error: " << e.what() << std::endl;
            return false;
        }
    }

    inline uint16_t calculate_checksum(uint16_t* buffer, int size);
    inline uint16_t tcp_checksum(iphdr_ptr iphdr, tcphdr_ptr tcphdr, size_t total_length);
    inline uint16_t udp_checksum(iphdr_ptr iphdr, udphdr_ptr udphdr, size_t total_length);

    inline void modifyInternal(INTERMEDIATE_BUFFER& buffer, HANDLE& handle, const IP_ADDRESS &newIP, PORT newPort, const MAC_ADDRESS &newMac, const MAC_ADDRESS &routerMac)
    {
        auto* eth_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);

        if (eth_header->h_proto == ntohs(ETH_P_IP))
        {
            auto* ip_header = reinterpret_cast<iphdr_ptr>(buffer.m_IBuffer + sizeof(ether_header));

            // Change Source IP
            const PCSTR newIP_PCSTR = newIP.c_str();
            in_addr my_ip;
            inet_pton(AF_INET, newIP_PCSTR, &my_ip); // <<< your IP address
            ip_header->ip_src = my_ip;


            uint8_t new_src_mac[6];
            ParseMACAddress(newMac, new_src_mac);
            //change source MAC
            memcpy(eth_header->h_source, new_src_mac, 6);

            uint8_t new_dst_mac[6];
            ParseMACAddress(routerMac, new_dst_mac);
            //change destination MAC to router's (gateway)
            memcpy(eth_header->h_dest, new_dst_mac, 6);


            // Recalculate IP header checksum
            ip_header->ip_sum = 0;
            ip_header->ip_sum = calculate_checksum((uint16_t*)ip_header, ip_header->ip_hl * 4);

            // If it's TCP or UDP, recalculate their checksums too
            if (ip_header->ip_p == IPPROTO_TCP)
            {
                auto* tcp_header = reinterpret_cast<tcphdr_ptr>(
                    buffer.m_IBuffer + sizeof(ether_header) + ip_header->ip_hl * 4);

                //change the port
                tcp_header->th_sport = htons(newPort);

                tcp_header->th_sum = 0;
                tcp_header->th_sum = tcp_checksum(ip_header, tcp_header, buffer.m_Length - sizeof(ether_header));;
            }
            else if (ip_header->ip_p == IPPROTO_UDP)
            {
                auto* udp_header = reinterpret_cast<udphdr_ptr>(
                    buffer.m_IBuffer + sizeof(ether_header) + ip_header->ip_hl * 4);

                //change the port
                udp_header->th_sport = htons(newPort);

                udp_header->th_sum = 0;
                udp_header->th_sum = udp_checksum(ip_header, udp_header, buffer.m_Length - sizeof(ether_header));
            }
        }


       // buffer.m_dwDeviceFlags = PACKET_FLAG_ON_SEND;


        //ETH_REQUEST newPacket = { handle, &buffer };
        //ndis_api->SendPacketToAdapter(&newPacket);
    }

    inline void modifyExternal(INTERMEDIATE_BUFFER& buffer, HANDLE& handle,const MAC_ADDRESS &src_mac, const IP_ADDRESS &dst_ip, PORT dst_port, const MAC_ADDRESS &dst_mac)
    {
        auto* eth_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);

        if (eth_header->h_proto == ntohs(ETH_P_IP))
        {
            auto* ip_header = reinterpret_cast<iphdr_ptr>(buffer.m_IBuffer + sizeof(ether_header));


            PCSTR dst_ip_pcstr = dst_ip.c_str();

            // Change destination IP
            in_addr my_ip;
            inet_pton(AF_INET, dst_ip_pcstr, &my_ip); // <<< your IP address
            ip_header->ip_dst = my_ip;

            uint8_t new_dst_mac[6];
            ParseMACAddress(dst_mac, new_dst_mac);
            //change destination MAC
            memcpy(eth_header->h_dest, new_dst_mac, 6);


            //set the src mac to gateway's mac
            uint8_t new_src_mac[6];
            ParseMACAddress(src_mac, new_src_mac);
            //change destination MAC
            memcpy(eth_header->h_source, new_src_mac, 6);



            // Recalculate IP header checksum
            ip_header->ip_sum = 0;
            ip_header->ip_sum = calculate_checksum((uint16_t*)ip_header, ip_header->ip_hl * 4);

            // If it's TCP or UDP, recalculate their checksums too
            if (ip_header->ip_p == IPPROTO_TCP)
            {
                auto* tcp_header = reinterpret_cast<tcphdr_ptr>(
                    buffer.m_IBuffer + sizeof(ether_header) + ip_header->ip_hl * 4);

                //change the port
                tcp_header->th_dport = htons(dst_port);

                tcp_header->th_sum = 0;
                tcp_header->th_sum = tcp_checksum(ip_header, tcp_header, buffer.m_Length - sizeof(ether_header));;
            }
            else if (ip_header->ip_p == IPPROTO_UDP)
            {
                auto* udp_header = reinterpret_cast<udphdr_ptr>(
                    buffer.m_IBuffer + sizeof(ether_header) + ip_header->ip_hl * 4);

                //change the port
                udp_header->th_dport = htons(dst_port);

                udp_header->th_sum = 0;
                udp_header->th_sum = udp_checksum(ip_header, udp_header, buffer.m_Length - sizeof(ether_header));
            }
        }




        //buffer.m_dwDeviceFlags = PACKET_FLAG_ON_SEND;
        //ETH_REQUEST newPacket = { handle, &buffer };
        //ndis_api->SendPacketToAdapter(&newPacket);
    }





    inline uint16_t calculate_checksum(uint16_t* buffer, int size)
    {
        uint32_t checksum = 0;

        while (size > 1)
        {
            checksum += *buffer++;
            size -= 2;
        }

        if (size) // if odd number of bytes
        {
            checksum += *(uint8_t*)buffer;
        }

        // Fold 32-bit checksum to 16 bits
        while (checksum >> 16)
        {
            checksum = (checksum & 0xFFFF) + (checksum >> 16);
        }

        return static_cast<uint16_t>(~checksum);
    }

    inline uint16_t tcp_checksum(iphdr_ptr iphdr, tcphdr_ptr tcphdr, size_t total_length)
    {
        uint32_t checksum = 0;
        uint16_t tcp_length = ntohs(iphdr->ip_len) - (iphdr->ip_hl * 4);

        // Pseudo-header
        checksum += (iphdr->ip_src.s_addr >> 16) & 0xFFFF;
        checksum += (iphdr->ip_src.s_addr) & 0xFFFF;
        checksum += (iphdr->ip_dst.s_addr >> 16) & 0xFFFF;
        checksum += (iphdr->ip_dst.s_addr) & 0xFFFF;
        checksum += htons(IPPROTO_TCP);
        checksum += htons(tcp_length);

        // TCP header + data
        uint16_t* tcp_segment = (uint16_t*)tcphdr;
        size_t tcp_seg_length = tcp_length;

        while (tcp_seg_length > 1)
        {
            checksum += *tcp_segment++;
            tcp_seg_length -= 2;
        }

        if (tcp_seg_length > 0) // If odd length
        {
            checksum += *(uint8_t*)tcp_segment;
        }

        // Fold
        while (checksum >> 16)
        {
            checksum = (checksum & 0xFFFF) + (checksum >> 16);
        }

        return static_cast<uint16_t>(~checksum);
    }

    inline uint16_t udp_checksum(iphdr_ptr iphdr, udphdr_ptr udphdr, size_t total_length)
    {
        uint32_t checksum = 0;
        uint16_t udp_length = ntohs(udphdr->length);

        // Pseudo-header
        checksum += (iphdr->ip_src.s_addr >> 16) & 0xFFFF;
        checksum += (iphdr->ip_src.s_addr) & 0xFFFF;
        checksum += (iphdr->ip_dst.s_addr >> 16) & 0xFFFF;
        checksum += (iphdr->ip_dst.s_addr) & 0xFFFF;
        checksum += htons(IPPROTO_UDP);
        checksum += htons(udp_length);

        // UDP header + data
        uint16_t* udp_segment = (uint16_t*)udphdr;
        size_t udp_seg_length = udp_length;

        while (udp_seg_length > 1)
        {
            checksum += *udp_segment++;
            udp_seg_length -= 2;
        }

        if (udp_seg_length > 0) // If odd length
        {
            checksum += *(uint8_t*)udp_segment;
        }

        // Fold
        while (checksum >> 16)
        {
            checksum = (checksum & 0xFFFF) + (checksum >> 16);
        }

        uint16_t result = static_cast<uint16_t>(~checksum);
        return (result == 0x0000) ? 0xFFFF : result;
    }

}