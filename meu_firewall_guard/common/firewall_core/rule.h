// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  rule.h 
/// Abstract:  simple rule struct type definition
/// </summary>
// --------------------------------------------------------------------------------

#pragma once

#define ANY_STRING "*"
#define ANY_IP ANY_STRING
#define ANY_PORT -1
#define ANY_PROTO 0

namespace firewall_core {
    struct Rule {
        u_short id;
        IP_ADDRESS srcIP;            //source IP in string format
        IP_ADDRESS destIP;           //destination ip in string format
        PORT srcPort;
        PORT destPort;
        PROTOCOL proto;
        u_int priority;
        bool enabled;
        PACKET_ACTION action;

        //default contructor
        //set every feild to ANY
        //set action to 'pass'
        Rule() {
            id = 0;
            srcIP = ANY_IP, destIP = ANY_IP;
            srcPort = ANY_PORT, destPort = ANY_PORT, proto = ANY_PROTO;
            action = PACKET_ACTION::pass;
            priority = 100;
            enabled = true;
        }

        Rule(u_short id, PROTOCOL proto, IP_ADDRESS srcIP, IP_ADDRESS destIP, PORT srcPort, PORT destPort,
            PACKET_ACTION action = PACKET_ACTION::pass) {
            this->id = id;
            this->srcIP = srcIP, this->destIP = destIP;
            this->srcPort = srcPort, this->destPort = destPort, this->proto = proto;
            this->action = action;
            this->priority = 100;
            this->enabled = true;
        }

        bool match (const PacketInformation& packet) {
            return ((proto == ANY_PROTO || proto == packet.proto) &&
                (srcIP == ANY_IP || srcIP == packet.srcIP) &&
                (destIP == ANY_IP || destIP == packet.destIP) &&
                (srcPort == ANY_PORT || srcPort == packet.srcPort) &&
                (destPort == ANY_PORT || destPort == packet.destPort));
        }

        void print() {
            std::cout << id << ", " << (int)proto << ", " << srcIP << ", " << destIP << ", " << srcPort << ", ";
            std::cout << destPort << ", " << priority << ", " << enabled << ", ";
            std::cout << ((action == PACKET_ACTION::pass) ? "ALLOW" : "DENY");
        }
    };
}
