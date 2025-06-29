#include "pch.h"

const uint32_t FIREWALL_MASK = 0xFFFFFF00;
const uint32_t NAT_NETWORK = 0xC0A86400;


//hard coded for now
//TODO: dynamically allocate addresses
const IP_ADDRESS deviceIP = "192.168.100.200";
const IP_ADDRESS firewallIP = "192.168.100.22";
const MAC_ADDRESS firewallMac = "E0:94:67:E7:32:40";
const MAC_ADDRESS routerMac = "04:f3:52:d7:03:ed";


//Firewall Main Component
NAT::NATTable NatTable;
firewall_core::LinearRuleExecuter ruleExe;
logging::Logger logger;



//checks if both IPs are from the same network
bool isSameNetwork(const IP_ADDRESS& srcIP, const IP_ADDRESS& dstIP, uint32_t subnetMask) {
    in_addr addr1, addr2;

    if (inet_pton(AF_INET, srcIP.c_str(), &addr1) != 1 || inet_pton(AF_INET, dstIP.c_str(), &addr2) != 1)
        return false; // Invalid IP format

    uint32_t ip1_net = ntohl(addr1.s_addr) & subnetMask;
    uint32_t ip2_net = ntohl(addr2.s_addr) & subnetMask;

    return ip1_net == ip2_net;
}

//broadcast checker function
bool isBroadcast(const IP_ADDRESS& ip) {
    in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1)
        return false; //invalid IP

    uint32_t ip_int = ntohl(addr.s_addr);

    //255.255.255.255 (limited broadcast)
    if (ip_int == 0xFFFFFFFF)
        return true;

    uint32_t mask = 0xFFFFFF00; // 255.255.255.0
    uint32_t subnet = ip_int & mask;
    uint32_t broadcast = subnet | ~mask;

    return ip_int == broadcast;
}


//multicast checker function
bool isMulticast(const IP_ADDRESS& ip) {
    in_addr addr;
    inet_pton(AF_INET, ip.c_str(), &addr);
    uint32_t ip_int = ntohl(addr.s_addr);
    return ip_int >= 0xE0000000 && ip_int <= 0xEFFFFFFF; //224.0.0.0 to 239.255.255.255
}


//function that checks for loopbacks(127.0.0.0/8)
bool isLoopback(const IP_ADDRESS& ip) {
    in_addr addr;
    inet_pton(AF_INET, ip.c_str(), &addr);
    uint32_t ip_int = ntohl(addr.s_addr);
    return (ip_int & 0xFF000000) == 0x7F000000; // 127.0.0.0/8
}



void processIncoming();
void processOutgoing();

void passIncoming(INTERMEDIATE_BUFFER& buffer, HANDLE& handle, firewall_core::PacketInformation &p, u_short ruleID);
void passOutgoing(INTERMEDIATE_BUFFER& buffer, HANDLE& handle, firewall_core::PacketInformation &p, u_short ruleID);


struct queue_data {
    INTERMEDIATE_BUFFER buffer;
    HANDLE handle;
    firewall_core::PacketInformation packet;
    u_short ruleID;
};

std::queue<queue_data> incomingQueue;
std::queue<queue_data> outgoingQueue;

std::mutex incomingMutex;
std::mutex outgoingMutex;

std::thread sendIncomingThread;
std::thread sendOutgoingThread;

std::condition_variable incomingCV;
std::condition_variable outgoingCV;

//to keep sendIncoming/sendOutgoing threads alive;
std::atomic<bool> running = false;

bool sendAdapter(INTERMEDIATE_BUFFER& buffer, HANDLE& handle);
bool sendMstcp(INTERMEDIATE_BUFFER& buffer, HANDLE& handle);


auto ndis_api = std::make_unique<ndisapi::queued_packet_filter>(
    [](HANDLE handle, INTERMEDIATE_BUFFER& buffer) {
        auto* eth_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);

        //if its not IPv4 packet (pass it)
        if (eth_header->h_proto != ntohs(ETH_P_IP)) 
            return PACKET_ACTION::pass;

        firewall_core::PacketInformation p(buffer);
        //match rules and get answer
        std::pair<PACKET_ACTION, u_short> ruleExeRslt = ruleExe.matchRules(p);

        //log the packet before processing
        logger.insertLog(buffer, ruleExeRslt.second);
        
        //if passsed send the packet
        if (ruleExeRslt.first == PACKET_ACTION::pass) {
            passIncoming(buffer, handle, p, ruleExeRslt.second);
        }

        return PACKET_ACTION::drop;       
    },
    [](HANDLE handle, INTERMEDIATE_BUFFER& buffer) {
        auto* eth_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);

        //if its not IPv4 packet (pass it)
        if (eth_header->h_proto != ntohs(ETH_P_IP))
            return PACKET_ACTION::pass;

        firewall_core::PacketInformation p(buffer);
        //match rules and get answer
        std::pair<PACKET_ACTION, u_short> ruleExeRslt = ruleExe.matchRules(p);
        
        //log the packet before processing
        logger.insertLog(buffer, ruleExeRslt.second);

        //if passsed send the packet
        if (ruleExeRslt.first == PACKET_ACTION::pass) {
            passOutgoing(buffer, handle, p, ruleExeRslt.second);
        }

        return PACKET_ACTION::drop;
    });



void processIncoming() {
    while (running) {
        std::unique_lock<std::mutex> lock(incomingMutex);

        // Wait until queue is not empty or we are stopping
        incomingCV.wait(lock, [] {
            return !incomingQueue.empty() || !running;
        });

        // Exit loop if stopping
        if (!running && incomingQueue.empty())
            break;

        INTERMEDIATE_BUFFER buffer = incomingQueue.front().buffer;
        HANDLE handle = incomingQueue.front().handle;
        firewall_core::PacketInformation p = incomingQueue.front().packet;
        u_short ruleID = incomingQueue.front().ruleID;

		incomingQueue.pop();

		lock.unlock(); // unlock before heavy processing

		//handling edge cases
		//if its destination is the device's dest
		//if srcIP->dstIP are from the same network..
		//is broadcast or multicast
		//if its a loopback 127.0.0.x
		if (p.destIP == deviceIP || isSameNetwork(p.srcIP, p.destIP, FIREWALL_MASK) || isBroadcast(p.destIP) ||
			isMulticast(p.destIP) || isLoopback(p.srcIP) || isLoopback(p.destIP)) {
			sendMstcp(buffer, handle);
			continue;
		}


		//proccessing (allowed packets)
		auto* ip_header = reinterpret_cast<iphdr_ptr>(buffer.m_IBuffer + sizeof(ether_header));

		// Means the packet is coming from the internal network
		if ((ntohl(ip_header->ip_src.S_un.S_addr) & FIREWALL_MASK) == NAT_NETWORK)
		{
			IP_ADDRESS internalIP;
			PORT internalPort;
			MAC_ADDRESS internalMAC;



			//if there is NO nat entry for this packet (create one)
			if (!NatTable.getInternalMapping(p.destIP, p.destPort, p.proto, internalIP, internalPort, internalMAC)) {

				//circular packet srcIP -> srcIP (drop)
				if (p.srcIP == p.destIP) {
					logger.insertLog(buffer, ruleID);
					continue;
				}

				//TODO: Port Network Translation
				//PORT newPort = NatTable.generateUniquePort(firewallIP, p.proto);

				//add NAT entry
				NatTable.addEntry(p.srcIP, p.srcPort, p.srcMAC, firewallIP, p.srcPort, p.proto);

				//apply NATing from internal -> external
				NAT::modifyInternal(buffer, handle, firewallIP, p.srcPort, firewallMac, routerMac);
			}

			//apply NATing from internal -> external
			else {
				NAT::modifyInternal(buffer, handle, firewallIP, internalPort, firewallMac, routerMac);
			}

            //sending
			sendAdapter(buffer, handle);
		}
		else // Packet is coming from external network, probably a response
		{
			// Take destination IP and Port, and check the NAT table
			// If found, change the destination IP, Port, and MAC to the internal IP, Port, and MAC in the NAT entry.
			IP_ADDRESS internalIP;
			PORT internalPort;
			MAC_ADDRESS internalMAC;

			//from external -> internal find NAT entry (if exist)
			if (NatTable.getInternalMapping(p.destIP, p.destPort, p.proto, internalIP, internalPort, internalMAC)) {
				//if NAT entry exist apply NATing 
				NAT::modifyExternal(buffer, handle, firewallMac, internalIP, internalPort, internalMAC);


				//if its coming towards the device
				//we send to mstcp not ADAPTER
				if (internalIP == deviceIP) sendMstcp(buffer, handle);
				//else we send to adapter
				else sendAdapter(buffer, handle);
				//change the flag to send (instead of receive)
				//buffer.m_dwDeviceFlags = PACKET_FLAG_ON_SEND;

			}
			//else not NAT entry not found (external -> internal) (external tries to initialize) (drop)
			//TODO: initialize contact from external -> internal

		}

		//log after nating
		logger.insertLog(buffer, ruleID);
	}
}

/*
void processIncoming(INTERMEDIATE_BUFFER& buffer, HANDLE& handle) {
    firewall_core::PacketInformation p(buffer);

    //match rules and get answer
    std::pair<PACKET_ACTION, u_short> ruleExeRslt = ruleExe.matchRules(p);

    //log before nating
    logger.insertLog(buffer, ruleExeRslt.second);
    


    //handling edge cases
    //if its destination is the device's dest
    if (p.destIP == deviceIP) return;
    //if srcIP->dstIP are from the same network..
    if (isSameNetwork(p.srcIP, p.destIP, FIREWALL_MASK)) return;
    //is broadcast or multicast
    if (isBroadcast(p.destIP) || isMulticast(p.destIP)) return;
    //if its a loopback 127.0.0.x
    if (isLoopback(p.srcIP) || isLoopback(p.destIP)) return;





    //proccessing (allowed packets)
    auto* ip_header = reinterpret_cast<iphdr_ptr>(buffer.m_IBuffer + sizeof(ether_header));

    // Means the packet is coming from the internal network
    if ((ntohl(ip_header->ip_src.S_un.S_addr) & FIREWALL_MASK) == NAT_NETWORK)
    {
        IP_ADDRESS internalIP;
        PORT internalPort;
        MAC_ADDRESS internalMAC;

        

        //if there is NO nat entry for this packet (create one)
        if (!NatTable.getInternalMapping(p.destIP, p.destPort, p.proto, internalIP, internalPort, internalMAC)) {

            //circular packet srcIP -> srcIP
            if (p.srcIP == p.destIP) {
                logger.insertLog(buffer, ruleExeRslt.second);
                return PACKET_ACTION::drop;
            }

            //generate a unique port
            PORT newPort = NatTable.generateUniquePort(firewallIP, p.proto);

            //add NAT entry
            NatTable.addEntry(p.srcIP, p.srcPort, p.srcMAC, firewallIP, p.srcPort , p.proto);

            //apply NATing from internal -> external
            NAT::modifyInternal(buffer, handle, firewallIP, p.srcPort, firewallMac, routerMac);
        }

        //apply NATing from internal -> external
        else {
            NAT::modifyInternal(buffer, handle, firewallIP, internalPort, firewallMac, routerMac);
        }


        
        //sending
        //change the flag to send (instead of receive)
        //buffer.m_dwDeviceFlags = PACKET_FLAG_ON_SEND;

        ETH_REQUEST newPacket = { handle, &buffer };
        ndis_api->SendPacketToAdapter(&newPacket);
      
           
    }
    else // Packet is coming from external network, probably a response
    {
        // Take destination IP and Port, and check the NAT table
        // If found, change the destination IP, Port, and MAC to the internal IP, Port, and MAC in the NAT entry.
        IP_ADDRESS internalIP;
        PORT internalPort;
        MAC_ADDRESS internalMAC;

        //from external -> internal find NAT entry (if exist)
        if (NatTable.getInternalMapping(p.destIP, p.destPort, p.proto, internalIP, internalPort, internalMAC)) {
            //if NAT entry exist apply NATing 
            NAT::modifyExternal(buffer, handle, firewallMac, internalIP, internalPort, internalMAC);


            //sending
            ETH_REQUEST newPacket = { handle, &buffer };

            //if its coming towards the device
            //we send to mstcp not ADAPTER
            if (internalIP == deviceIP) {
                
                logger.insertLog(buffer, ruleExeRslt.second);
                //queue_packet_filter sends to mstcp
                return PACKET_ACTION::pass;
               
            }//else we send to adapter
            else {
                ndis_api->SendPacketToAdapter(&newPacket);
            }
            //change the flag to send (instead of receive)
            //buffer.m_dwDeviceFlags = PACKET_FLAG_ON_SEND;
            
            //sending to adapter
            
        }
        
    }

    //log after nating
    logger.insertLog(buffer, ruleExeRslt.second);

    //if we send to adapter (we drop the packet) to not send to mstcp
    return PACKET_ACTION::drop;
}
*/


//outgoing packet processor src_ip = deviceIP (always)
void processOutgoing() {
    while (running) {
        std::unique_lock<std::mutex> lock(outgoingMutex);

        // Wait until queue is not empty or we are stopping
        outgoingCV.wait(lock, [] {
            return !outgoingQueue.empty() || !running;
            });

        // Exit loop if stopping
        if (!running && outgoingQueue.empty())
            break;

        INTERMEDIATE_BUFFER buffer = outgoingQueue.front().buffer;
        HANDLE handle = outgoingQueue.front().handle;
        firewall_core::PacketInformation p = outgoingQueue.front().packet;
        u_short ruleID = outgoingQueue.front().ruleID;

        outgoingQueue.pop();

        lock.unlock(); // unlock before heavy processing

        //processing allowed packets
		//add NAT entry
		NatTable.addEntry(p.srcIP, p.srcPort, p.srcMAC, firewallIP, p.srcPort, p.proto);
		NAT::modifyInternal(buffer, handle, firewallIP, p.srcPort, firewallMac, routerMac);


		//log after NAT
		logger.insertLog(buffer, ruleID);

		sendAdapter(buffer, handle); 
    }
}

/*
//outgoing packet processor src_ip = deviceIP (always)
void processOutgoing() {
    firewall_core::PacketInformation p(buffer);

    //match rules and get answer
    std::pair<PACKET_ACTION, u_short> ruleExeRslt = ruleExe.matchRules(p);

    //log before nating
    logger.insertLog(buffer, ruleExeRslt.second);
    //if the rule action is to drop (dont proceed further)
    if (ruleExeRslt.first == PACKET_ACTION::drop) return PACKET_ACTION::drop;

    //add NAT entry
    NatTable.addEntry(p.srcIP, p.srcPort, p.srcMAC, firewallIP, p.srcPort, p.proto);
    NAT::modifyInternal(buffer, handle, firewallIP, p.srcPort, firewallMac, routerMac);

    //log after NAT
    logger.insertLog(buffer, ruleExeRslt.second);

    //let the queue_packet_filter send the packets..
    return PACKET_ACTION::pass;
}
*/

void passIncoming(INTERMEDIATE_BUFFER& buffer, HANDLE& handle, firewall_core::PacketInformation &p, u_short ruleID) {
    if (!running) return;
    {
        std::lock_guard<std::mutex> lock(incomingMutex);
        incomingQueue.push({ buffer, handle, p, ruleID });
    }
    incomingCV.notify_one();
}

void passOutgoing(INTERMEDIATE_BUFFER& buffer, HANDLE& handle, firewall_core::PacketInformation& p, u_short ruleID) {
    if (!running) return;
    {
        std::lock_guard<std::mutex> lock(outgoingMutex);
        outgoingQueue.push({ buffer, handle, p, ruleID });
    }
    outgoingCV.notify_one();
}



bool sendAdapter(INTERMEDIATE_BUFFER& buffer, HANDLE& handle) {
    ETH_REQUEST newPacket = { handle, &buffer };
    return ndis_api->SendPacketToAdapter(&newPacket);
}

bool sendMstcp(INTERMEDIATE_BUFFER& buffer, HANDLE& handle) {
    ETH_REQUEST newPacket = { handle, &buffer };
    return ndis_api->SendPacketToMstcp(&newPacket);
}

int main()
{

    //Firewall Main Component
    NAT::NATTable NatTable;
    firewall_core::LinearRuleExecuter ruleExe;
    logging::Logger logger;


    ruleExe.printExe();
    //Firewall Main Component

    //initialize sending threads
    running = true;
    sendIncomingThread = std::thread(processIncoming);
    sendOutgoingThread = std::thread(processOutgoing);


    try
    {
        if (ndis_api->IsDriverLoaded())
        {
            std::cout << "WinpkFilter is loaded" << std::endl << std::endl;
        }
        else
        {
            std::cout << "WinpkFilter is not loaded" << std::endl << std::endl;
            return 1;
        }


        std::cout << "Available network interfaces:" << std::endl << std::endl;
        size_t index = 0;
        for (auto& e : ndis_api->get_interface_names_list())
        {
            std::cout << ++index << ")\t" << e << std::endl;
        }

        std::cout << std::endl << "Select interface to filter:";
        std::cin >> index;

        if (index > ndis_api->get_interface_names_list().size())
        {
            std::cout << "Wrong parameter was selected. Out of range." << std::endl;
            return 0;
        }


        ndis_api->start_filter(index - 1);

        std::cout << "Press any key to stop filtering" << std::endl;

        std::ignore = _getch();

        std::cout << "Exiting..." << std::endl;

        ndis_api->stop_filter();
        std::cout << "filter stopped\n";

        //stop threads
        running = false;
        incomingCV.notify_all();
        sendIncomingThread.join();
        std::cout << "sendIncomingThread joined\n";

        outgoingCV.notify_all();
        sendOutgoingThread.join();
        std::cout << "sendOutgoingThread joined\n";

        logger.stopLogger();
        std::cout << "logger joined\n";

        NatTable.stopCleanUpThread();
        std::cout << "nat table joined\n";

        std::cin.ignore(); std::cin.get();
    }
    catch (const std::exception& ex)
    {
        std::cout << "Exception occurred: " << ex.what() << std::endl;
    }

    return 0;
}