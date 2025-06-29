#pragma once

// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  logDAO.h 
/// Abstract:  a DAO (data access objcet) for a log table in the database
/// </summary>
// --------------------------------------------------------------------------------
namespace database {
    class LogDAO {

    private:

        // ********************************************************************************
        /// <summary>
        /// function that prints the SQL Error in the terminal
        /// </summary>
        /// // ********************************************************************************
        void printStmtError(SQLHANDLE hStmt);



    public:
        // ********************************************************************************
        /// <summary>
        /// takes INTERMEDIATE_BUFFER and rule_id and logs the packet informations
        /// </summary>
        /// <param name="buffer"> the packet as INTERMEDIATE_BUFFER structure </param>
        /// <param name="rule_id"> the rule of the id that matched the packet </param>
        /// <returns> vector of type firewall_core::Rule </returns>
        /// // ********************************************************************************
        bool insertLog(INTERMEDIATE_BUFFER& packet, u_short rule_id);

    };


    inline bool LogDAO::insertLog(INTERMEDIATE_BUFFER& buffer, u_short rule_id) {
        SQLHDBC  dbc = DatabaseConnection::getInstance().getConnection();
        SQLRETURN ret;
        SQLHSTMT stmt;

        ret = SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
        if (!SQL_SUCCEEDED(ret)) {
            std::cout << "Error connecting to database from LogDAO\n";
            throw std::runtime_error("Error connecting to database from LogDAO\n");
            return false;
        }

   
        SQLWCHAR* sql = (SQLWCHAR*)L"INSERT INTO logs (protocol, src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac, packet, rule_id) "
            L"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

        firewall_core::PacketInformation packet = firewall_core::PacketInformation::extractPacket(buffer);

        // Bind parameters
        std::string protocol = firewall_core::PacketInformation::getProtoAsString(packet.proto);
        SQLBindParameter(stmt, 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 10, 0, (SQLPOINTER)protocol.c_str(), 0, NULL);
        SQLBindParameter(stmt, 2, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 45, 0, (SQLPOINTER)packet.srcIP.c_str(), 0, NULL);
        SQLBindParameter(stmt, 3, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 45, 0, (SQLPOINTER)packet.destIP.c_str(), 0, NULL);

        //int srcPortSql = static_cast<int>(packet.srcPort), destPortSql = static_cast<int>(packet.destPort);
        SQLBindParameter(stmt, 4, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, (SQLPOINTER)&packet.srcPort, 0, NULL);
        SQLBindParameter(stmt, 5, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, (SQLPOINTER)&packet.destPort, 0, NULL);

        SQLBindParameter(stmt, 6, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 23, 0, (SQLPOINTER)packet.srcMAC.c_str(), 0, NULL);
        SQLBindParameter(stmt, 7, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 23, 0, (SQLPOINTER)packet.destMAC.c_str(), 0, NULL);
        // Only insert the actual packet length (not full MAX_ETHER_FRAME)
        SQLBindParameter(stmt, 8, SQL_PARAM_INPUT, SQL_C_BINARY, SQL_VARBINARY, buffer.m_Length, 0, (SQLPOINTER)buffer.m_IBuffer, buffer.m_Length, NULL);

        SQLLEN rule_id_ind = (((int)rule_id) == 0) ? SQL_NULL_DATA : 0;
        int ruleIDSql = static_cast<int>(rule_id);
        SQLBindParameter(stmt, 9, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, (SQLPOINTER)&ruleIDSql, 0, &rule_id_ind);


        // Execute
        try {
            ret = SQLExecDirectW(stmt, sql, SQL_NTS);
        }
        catch (const std::exception& e) {
            std::cout << e.what() << '\n';
            abort();
        }
        if (!SQL_SUCCEEDED(ret)) {
            std::wcerr << "[LogDAO] Failed to insert log.SQLExecDirect error code : " + ret;
            printStmtError(stmt);
            throw std::runtime_error("[LogDAO] Failed to insert log. SQLExecDirect error code: " + ret);
            SQLFreeHandle(SQL_HANDLE_STMT, stmt);
            return false;
        }

        SQLFreeHandle(SQL_HANDLE_STMT, stmt);
        return true;
    }

    inline void LogDAO::printStmtError(SQLHANDLE hStmt) {
        SQLWCHAR sqlState[6];
        SQLWCHAR message[256];
        SQLINTEGER nativeError;
        SQLSMALLINT messageLen;

        SQLRETURN ret = SQLGetDiagRecW(
            SQL_HANDLE_STMT, hStmt, 1, sqlState, &nativeError, message, sizeof(message) / sizeof(SQLWCHAR), &messageLen
        );

        if (SQL_SUCCEEDED(ret)) {
            std::wcerr << L"[ODBC ERROR] LogDAO SQLSTATE: " << sqlState
                << L" | Message: " << message
                << L" | NativeError: " << nativeError << std::endl;
        }
        else {
            std::cerr << "[ODBC ERROR] Could not retrieve detailed diagnostic information." << std::endl;
        }
    }
}