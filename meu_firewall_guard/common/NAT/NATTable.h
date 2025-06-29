#pragma once

// Hash key for NAT table lookup (external)
namespace NAT {
    struct ExternalKey {
        IP_ADDRESS ip;
        PORT port;
        PROTOCOL protocol;

        bool operator==(const ExternalKey& other) const {
            return ip == other.ip && port == other.port && protocol == other.protocol;
        }

    };
}

//hashing functionality override
namespace std {
    template <>
    struct hash<NAT::ExternalKey> {
        inline std::size_t operator()(const NAT::ExternalKey& key) const {
            return hash<std::string>()(key.ip) ^ hash<u_short>()(key.port) ^ hash<int>()(static_cast<int>(key.protocol));
        }
    };
}

namespace NAT {
    // NAT Entry: one direction (internal external)
    struct NATEntry {
        IP_ADDRESS internalIP;
        PORT internalPort;
        MAC_ADDRESS internalMAC;
        IP_ADDRESS externalIP;
        PORT externalPort;
        PROTOCOL protocol;
        TIMESTAMP timestamp;
    };


    class NATTable {
    private:
        /// <summary> expiration time in seconds </summary>
        static constexpr std::chrono::seconds NAT_TIMEOUT = std::chrono::seconds(30);

        std::unordered_map<ExternalKey, NATEntry> externalToInternal;
        std::mutex tableMutex;

        /// <summary> working thread running status </summary>
        /// <summary> true = running, false = stopped </summary>
        std::atomic<bool> cleanupRunning = false;
        /// <summary> clean up thread object </summary>
        std::thread cleanUpThread;

    public:
        NATTable() { initCleanUpThread(); }
        ~NATTable() { stopCleanUpThread(); }


        // ********************************************************************************
        /// <summary>
        /// add a new NAT entry into the table (typically on outbound connection)
        /// </summary>
        // ********************************************************************************
        void addEntry(const IP_ADDRESS& internalIP, PORT internalPort, const MAC_ADDRESS& internalMAC, const IP_ADDRESS& externalIP, PORT externalPort, PROTOCOL protocol);
        

        // ********************************************************************************
        /// <summary>
        /// Lookup incoming packet destination (reverse NAT)
        /// </summary>
        /// <returns>true is success, false otherwise</returns>
        // ********************************************************************************
        bool getInternalMapping(const IP_ADDRESS& externalIP, PORT externalPort,PROTOCOL protocol, IP_ADDRESS& internalIPOut, PORT& internalPortOut, MAC_ADDRESS& internalMACOut);


        // ********************************************************************************
        /// <summary>
        /// generate a unqiue external port
        /// </summary>
        /// <returns> a unique port </returns>
        // ********************************************************************************
        PORT generateUniquePort(IP_ADDRESS ip, PROTOCOL protocol);


        // ********************************************************************************
        /// <summary>
        /// function that remove expired entries from table
        /// </summary>
        // ********************************************************************************
        void cleanUpExpiredEntries();


        // ********************************************************************************
        /// <summary>
        /// a thread routine that cleans up unused nat entries periodically
        /// </summary>
        // ********************************************************************************
        void cleanUpRoutine(std::chrono::seconds interval = std::chrono::seconds(30));


        // ********************************************************************************
        /// <summary>
        /// a thread routine that cleans up unused nat entries periodically
        /// </summary>
        /// <returns> true if succes, false otherwisw </returns>
        // ********************************************************************************
        bool initCleanUpThread();


        // ********************************************************************************
        /// <summary>
        /// a thread routine that cleans up unused nat entries periodically
        /// </summary>
        /// <returns> true if succes, false otherwisw </returns>
        // ********************************************************************************
        bool stopCleanUpThread();


        // ********************************************************************************
        /// <summary>
        /// Timeout cleaner or print method (using for testing purposes)
        /// </summary>
        // ********************************************************************************
        void printTable();
    };
}


inline void NAT::NATTable::addEntry(const IP_ADDRESS& internalIP, PORT internalPort, const MAC_ADDRESS &internalMAC,
    const IP_ADDRESS& externalIP, PORT externalPort, PROTOCOL protocol) 
{
    std::lock_guard<std::mutex> lock(tableMutex);
    
    ExternalKey key{ externalIP, externalPort, protocol };
    NATEntry entry{ internalIP, internalPort, internalMAC, externalIP, externalPort, protocol, std::chrono::steady_clock::now() };
   
    externalToInternal[key] = entry;
}


inline bool NAT::NATTable::getInternalMapping(const IP_ADDRESS& externalIP, PORT externalPort,
    PROTOCOL protocol, IP_ADDRESS& internalIPOut, PORT& internalPortOut, MAC_ADDRESS& internalMACOut) 
{
    std::lock_guard<std::mutex> lock(tableMutex);
    ExternalKey key{ externalIP, externalPort, protocol };

    auto it = externalToInternal.find(key);
    if (it != externalToInternal.end()) {
        internalIPOut = it->second.internalIP;
        internalPortOut = it->second.internalPort;
        internalMACOut = it->second.internalMAC;
        //update the timestamp
        it->second.timestamp = std::chrono::steady_clock::now();
        return true;
    }
    return false;
}

inline PORT NAT::NATTable::generateUniquePort(IP_ADDRESS ip, PROTOCOL protocol) {
    std::lock_guard<std::mutex> lock(tableMutex);

    for (int i = 49152; i <= 65535; ++i) {
        PORT port = static_cast<PORT>(i);
        ExternalKey testKey{ ip, port, protocol };

        if (externalToInternal.find(testKey) == externalToInternal.end())
            return port;
    }

    throw std::runtime_error("No available ports for NAT.");
}

inline void NAT::NATTable::cleanUpExpiredEntries() {
    std::lock_guard<std::mutex> lock(tableMutex);

    auto now = std::chrono::steady_clock::now();

    for (auto it = externalToInternal.begin(); it != externalToInternal.end(); ) {
        
        //if its past the expiration time (erase it)
        if (now - it->second.timestamp > NAT_TIMEOUT) 
            it = externalToInternal.erase(it);
        else  ++it;
    }
}

inline void NAT::NATTable::cleanUpRoutine(std::chrono::seconds interval) {
    while (cleanupRunning) {
        std::this_thread::sleep_for(interval);

        if (cleanupRunning) {
            cleanUpExpiredEntries();
        }
    }
}

inline bool NAT::NATTable::initCleanUpThread() {
    //if its already running
    if (cleanupRunning) return false;

    cleanupRunning = true;
    cleanUpThread = std::thread(&NATTable::cleanUpRoutine, this, std::chrono::seconds(30));

    return true;
}

inline bool NAT::NATTable::stopCleanUpThread() {
    //its not running
    if (!cleanupRunning) return false;

    cleanupRunning = false;
    if (cleanUpThread.joinable())
        cleanUpThread.join();
    
    return true;
}



inline void NAT::NATTable::printTable() {
    std::lock_guard<std::mutex> lock(tableMutex);
    std::cout << "NAT Table Entries:\n";
    for (const auto& [key, entry] : externalToInternal) {
        std::cout << key.ip << ":" << key.port
            << " -> " << entry.internalIP << ":" << entry.internalPort
            << " [" << (entry.protocol == IPPROTO_TCP ? "TCP" : "UDP") << "]\n";
    }
}