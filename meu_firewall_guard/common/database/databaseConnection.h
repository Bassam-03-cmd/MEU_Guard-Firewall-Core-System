// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  databaseConnection.h 
/// Abstract:  simpleton database connection class that return an instance of database connection
/// </summary>
// --------------------------------------------------------------------------------

#pragma once
#include <sqlext.h>
#include <sqltypes.h>
#include <sql.h>

namespace database {
    class DatabaseConnection {
    private:
        SQLHENV hEnv;
        SQLHDBC hDbc;

        DatabaseConnection() {
            if (SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &hEnv) != SQL_SUCCESS ||
                SQLSetEnvAttr(hEnv, SQL_ATTR_ODBC_VERSION, (void*)SQL_OV_ODBC3, 0) != SQL_SUCCESS ||
                SQLAllocHandle(SQL_HANDLE_DBC, hEnv, &hDbc) != SQL_SUCCESS) {
                throw std::runtime_error("Failed to initialize ODBC environment or connection handle.");
            }

            SQLWCHAR connStr[] = L"Driver={SQL Server};Server=localhost;Database=Graduation_Project;Trusted_Connection=Yes;";
       
            SQLWCHAR outStr[1024];
            SQLSMALLINT outStrLen;
            SQLRETURN ret = SQLDriverConnect(hDbc, NULL, connStr, SQL_NTS, outStr, sizeof(outStr), &outStrLen, SQL_DRIVER_COMPLETE);
            if (!SQL_SUCCEEDED(ret)) {
                throw std::runtime_error("Failed to connect to SQL Server.");
            }
        }

    public:
        static DatabaseConnection& getInstance() {
            static DatabaseConnection instance;
            return instance;
        }

        SQLHDBC getConnection() const {
            return hDbc;
        }

        ~DatabaseConnection() {
            SQLDisconnect(hDbc);
            SQLFreeHandle(SQL_HANDLE_DBC, hDbc);
            SQLFreeHandle(SQL_HANDLE_ENV, hEnv);
        }

        DatabaseConnection(const DatabaseConnection&) = delete;
        DatabaseConnection& operator=(const DatabaseConnection&) = delete;
    };
}