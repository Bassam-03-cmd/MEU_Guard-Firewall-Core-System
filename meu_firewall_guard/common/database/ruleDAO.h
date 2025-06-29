#pragma once

// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  ruleDAO.h 
/// Abstract:  a DAO (data access objcet) for a rule table in the database
/// </summary>
// --------------------------------------------------------------------------------
namespace database {
    class RuleDAO {

    private:
        std::map<std::string, u_char> protocolMap = {
            {"TCP", IPPROTO_TCP},
            {"UDP", IPPROTO_UDP},
            {"ICMP", IPPROTO_ICMP},
            {"GGP", IPPROTO_GGP},
            {"PUP", IPPROTO_PUP},
            {"IDP", IPPROTO_IDP},
            {"ICMPV6", IPPROTO_ICMPV6},
            {"UNDP", IPPROTO_ND},
            {"ANY", ANY_PROTO}
        };

        std::map<std::string, ndisapi::queued_packet_filter::packet_action> actionMap = {
            {"ALLOW", PACKET_ACTION::pass},
            {"DENY", PACKET_ACTION::drop},
            {"REJECT", PACKET_ACTION::revert}
        };

        // ********************************************************************************
        /// <summary>
        /// function that prints the SQL Error in the terminal
        /// </summary>
        /// // ********************************************************************************
        void printStmtError(SQLHANDLE hStmt);

    public:


        // ********************************************************************************
        /// <summary>
        /// fetchs all enabled firewall rules from the table
        /// </summary>
        /// <returns> vector of type firewall_core::Rule </returns>
        /// // ********************************************************************************
        std::vector<firewall_core::Rule> getAllRules();

        //TODO: add future methods: insertRule(Rule), deleteRule(id), updateRule(Rule)
    
    };




    inline std::vector<firewall_core::Rule> RuleDAO::getAllRules(){
        std::vector<firewall_core::Rule> rules;
        
        SQLHSTMT hStmt;
        SQLHDBC dbc = DatabaseConnection::getInstance().getConnection();

        if (SQLAllocHandle(SQL_HANDLE_STMT, dbc, &hStmt) != SQL_SUCCESS) {
            std::cerr << "Failed to allocate statement handle.\n";
            return rules;
        }

        SQLWCHAR* query = (SQLWCHAR*)L"SELECT * FROM rules WHERE enabled = 1 ORDER BY priority ASC";
        if (SQLExecDirect(hStmt, query, SQL_NTS) != SQL_SUCCESS) {
            std::cerr << "Failed to execute SQL query.\n";

            //print the error statement
            printStmtError(hStmt);

            SQLFreeHandle(SQL_HANDLE_STMT, hStmt);
            return rules;
        }

        while (SQLFetch(hStmt) == SQL_SUCCESS) {
            firewall_core::Rule rule;
            char protocol[11], src_ip[46], dst_ip[46], action[10];
            SQLINTEGER id, src_port, dst_port, priority;
            SQLCHAR enabled;

            SQLGetData(hStmt, 1, SQL_C_SLONG, &id, 0, NULL);
            SQLGetData(hStmt, 2, SQL_C_CHAR, protocol, sizeof(protocol), NULL);
            SQLGetData(hStmt, 3, SQL_C_CHAR, src_ip, sizeof(src_ip), NULL);
            SQLGetData(hStmt, 4, SQL_C_CHAR, dst_ip, sizeof(dst_ip), NULL);
            SQLGetData(hStmt, 5, SQL_C_SLONG, &src_port, 0, NULL);
            SQLGetData(hStmt, 6, SQL_C_SLONG, &dst_port, 0, NULL);
            SQLGetData(hStmt, 7, SQL_C_CHAR, action, sizeof(action), NULL);
            SQLGetData(hStmt, 8, SQL_C_SLONG, &priority, 0, NULL);
            SQLGetData(hStmt, 9, SQL_C_BIT, &enabled, 0, NULL);

            rule.id = id;
            rule.proto = protocolMap[protocol];
            rule.srcIP = (strcmp(src_ip, "ANY") == 0) ? ANY_IP : src_ip;
            rule.destIP = (strcmp(dst_ip, "ANY") == 0) ? ANY_IP : dst_ip;
            rule.srcPort = src_port;
            rule.destPort = dst_port;
            rule.action = actionMap[action];
            rule.priority = priority;
            rule.enabled = enabled;

            rules.push_back(rule);
        }

        SQLFreeHandle(SQL_HANDLE_STMT, hStmt);


        return rules;
    }

    inline void RuleDAO::printStmtError(SQLHANDLE hStmt) {
        SQLWCHAR sqlState[6];
        SQLWCHAR message[256];
        SQLINTEGER nativeError;
        SQLSMALLINT messageLen;

        SQLRETURN ret = SQLGetDiagRecW(
            SQL_HANDLE_STMT, hStmt, 1,sqlState,&nativeError,message,sizeof(message) / sizeof(SQLWCHAR),&messageLen
        );

        if (SQL_SUCCEEDED(ret)) {
            std::wcerr << L"[ODBC ERROR] SQLSTATE: " << sqlState
                << L" | Message: " << message
                << L" | NativeError: " << nativeError << std::endl;
        }
        else {
            std::cerr << "[ODBC ERROR] Could not retrieve detailed diagnostic information." << std::endl;
        }
    }
}

