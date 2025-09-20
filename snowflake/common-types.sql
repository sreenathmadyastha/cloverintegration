-- File: common_snowflake_queries.sql
-- Purpose: Collection of commonly used Snowflake queries for metadata, performance, storage, security, and data operations.
-- Usage: Replace placeholders (e.g., YOUR_DATABASE, YOUR_SCHEMA, YOUR_TABLE) with actual names.
-- Note: Ensure appropriate permissions (e.g., ACCOUNTADMIN for ACCOUNT_USAGE) and adjust time ranges as needed.

-- 1. METADATA QUERIES
-- Purpose: Retrieve metadata about database objects (tables, schemas, columns, etc.)

-- List all tables in a specific database and schema
-- Shows table name, type, creation, and last altered timestamps
SELECT TABLE_NAME, TABLE_TYPE, CREATED, LAST_ALTERED
FROM INFORMATION_SCHEMA.TABLES
WHERE TABLE_SCHEMA = 'YOUR_SCHEMA' AND TABLE_CATALOG = 'YOUR_DATABASE';

-- List all columns in a specific table
-- Provides column name, data type, nullability, and default values
SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_NAME = 'YOUR_TABLE' AND TABLE_SCHEMA = 'YOUR_SCHEMA';

-- List all schemas in a database
-- Displays schema names and creation timestamps
SELECT SCHEMA_NAME, CREATED
FROM INFORMATION_SCHEMA.SCHEMATA
WHERE CATALOG_NAME = 'YOUR_DATABASE';

-- List all databases in the account
-- Shows database names, creation times, and owners
SELECT DATABASE_NAME, CREATED, OWNER
FROM INFORMATION_SCHEMA.DATABASES;

-- 2. QUERY PERFORMANCE AND HISTORY
-- Purpose: Monitor query execution, performance, and warehouse usage

-- Recent query history (last 7 days)
-- Retrieves query ID, text, user, warehouse, status, and execution time
SELECT QUERY_ID, QUERY_TEXT, USER_NAME, WAREHOUSE_NAME, EXECUTION_STATUS, START_TIME, TOTAL_ELAPSED_TIME
FROM ACCOUNT_USAGE.QUERY_HISTORY
WHERE START_TIME >= DATEADD('day', -7, CURRENT_TIMESTAMP())
ORDER BY START_TIME DESC
LIMIT 100;

-- Long-running queries (execution time > 10 seconds)
-- Identifies slow queries for optimization
SELECT QUERY_ID, QUERY_TEXT, USER_NAME, WAREHOUSE_NAME, TOTAL_ELAPSED_TIME/1000 AS EXECUTION_TIME_SECONDS
FROM ACCOUNT_USAGE.QUERY_HISTORY
WHERE START_TIME >= DATEADD('day', -7, CURRENT_TIMESTAMP())
AND TOTAL_ELAPSED_TIME > 10000  -- 10 seconds in milliseconds
ORDER BY TOTAL_ELAPSED_TIME DESC
LIMIT 50;

-- Queries by warehouse usage
-- Summarizes query count and total execution time per warehouse
SELECT WAREHOUSE_NAME, COUNT(*) AS QUERY_COUNT, SUM(TOTAL_ELAPSED_TIME)/1000 AS TOTAL_EXECUTION_TIME_SECONDS
FROM ACCOUNT_USAGE.QUERY_HISTORY
WHERE START_TIME >= DATEADD('day', -7, CURRENT_TIMESTAMP())
GROUP BY WAREHOUSE_NAME
ORDER BY TOTAL_EXECUTION_TIME_SECONDS DESC;

-- 3. STORAGE AND USAGE MONITORING
-- Purpose: Track storage consumption and credit usage for billing

-- Storage usage by database
-- Shows storage in GB per database over the last 7 days
SELECT DATABASE_NAME, SUM(BYTES)/1024/1024/1024 AS STORAGE_GB
FROM ACCOUNT_USAGE.STORAGE_USAGE
WHERE USAGE_DATE >= DATEADD('day', -7, CURRENT_TIMESTAMP())
GROUP BY DATABASE_NAME
ORDER BY STORAGE_GB DESC;

-- Credit usage by warehouse
-- Tracks credit consumption for the last month
SELECT WAREHOUSE_NAME, SUM(CREDITS_USED) AS TOTAL_CREDITS
FROM ACCOUNT_USAGE.CREDIT_USAGE_HISTORY
WHERE USAGE_DATE >= DATEADD('month', -1, CURRENT_TIMESTAMP())
GROUP BY WAREHOUSE_NAME
ORDER BY TOTAL_CREDITS DESC;

-- Table storage details
-- Displays size (MB) and row count for tables in a database
SELECT TABLE_NAME, TABLE_SCHEMA, BYTES/1024/1024 AS SIZE_MB, ROW_COUNT
FROM INFORMATION_SCHEMA.TABLES
WHERE TABLE_TYPE = 'BASE TABLE' AND TABLE_CATALOG = 'YOUR_DATABASE'
ORDER BY SIZE_MB DESC;

-- 4. DATA LOADING AND COPY OPERATIONS
-- Purpose: Monitor data ingestion activities

-- Data load history
-- Shows recent data loads (last 14 days) for a schema
SELECT FILE_NAME, TABLE_NAME, STATUS, ROWS_LOADED, ERROR_COUNT, LAST_LOAD_TIME
FROM INFORMATION_SCHEMA.LOAD_HISTORY
WHERE SCHEMA_NAME = 'YOUR_SCHEMA'
AND LAST_LOAD_TIME >= DATEADD('day', -14, CURRENT_TIMESTAMP());

-- Copy command history
-- Tracks COPY command executions (last 7 days)
SELECT FILE_NAME, TABLE_NAME, STATUS, ROWS_LOADED, ERROR_COUNT, START_TIME
FROM ACCOUNT_USAGE.COPY_HISTORY
WHERE START_TIME >= DATEADD('day', -7, CURRENT_TIMESTAMP())
ORDER BY START_TIME DESC;

-- 5. SECURITY AND ACCESS CONTROL
-- Purpose: Manage roles, users, and privileges

-- List roles and their grants
-- Shows privileges assigned to roles
SELECT ROLE_NAME, GRANTED_TO, GRANTEE_NAME, OBJECT_TYPE, OBJECT_NAME, PRIVILEGE
FROM ACCOUNT_USAGE.GRANTS_TO_ROLES
WHERE DELETED_ON IS NULL
ORDER BY ROLE_NAME, OBJECT_TYPE;

-- List users and their roles
-- Displays which roles are assigned to users
SELECT NAME AS USER_NAME, ROLE_NAME
FROM ACCOUNT_USAGE.GRANTS_TO_USERS
WHERE DELETED_ON IS NULL
ORDER BY USER_NAME;

-- Login history
-- Audits user login activity (last 7 days)
SELECT USER_NAME, EVENT_TIMESTAMP, EVENT_TYPE, IS_SUCCESS
FROM ACCOUNT_USAGE.LOGIN_HISTORY
WHERE EVENT_TIMESTAMP >= DATEADD('day', -7, CURRENT_TIMESTAMP())
ORDER BY EVENT_TIMESTAMP DESC;

-- 6. WAREHOUSE MANAGEMENT
-- Purpose: Manage and monitor virtual warehouses

-- List all warehouses
-- Shows warehouse configurations and states
SELECT NAME, WAREHOUSE_SIZE, AUTO_SUSPEND, AUTO_RESUME, STATE
FROM SNOWFLAKE.WAREHOUSES;

-- Current warehouse usage
-- Identifies the active warehouse in the session
SELECT CURRENT_WAREHOUSE();

-- Warehouse performance
-- Analyzes average execution time and query count per warehouse
SELECT WAREHOUSE_NAME, AVG(EXECUTION_TIME)/1000 AS AVG_EXECUTION_SECONDS, COUNT(*) AS QUERY_COUNT
FROM ACCOUNT_USAGE.QUERY_HISTORY
WHERE START_TIME >= DATEADD('day', -7, CURRENT_TIMESTAMP())
GROUP BY WAREHOUSE_NAME
ORDER BY AVG_EXECUTION_SECONDS DESC;

-- 7. DATA SHARING AND REPLICATION
-- Purpose: Manage data shares and replication status

-- List data shares
-- Shows outbound and inbound data shares
SELECT SHARE_NAME, KIND, DATABASE_NAME, CREATED
FROM SNOWFLAKE.SHARES
WHERE KIND IN ('OUTBOUND', 'INBOUND');

-- Replication status
-- Monitors database replication status
SELECT DATABASE_NAME, REPLICATION_ENABLED, LAST_REPLICATED
FROM INFORMATION_SCHEMA.REPLICATION_DATABASES;

-- 8. COMMON DATA MANIPULATION QUERIES
-- Purpose: Work with user data

-- Select top rows from a table
-- Previews first 10 rows of a table
SELECT * FROM YOUR_DATABASE.YOUR_SCHEMA.YOUR_TABLE
LIMIT 10;

-- Aggregate data
-- Summarizes data (e.g., sales by region)
SELECT REGION, SUM(SALES_AMOUNT) AS TOTAL_SALES
FROM YOUR_DATABASE.YOUR_SCHEMA.SALES
GROUP BY REGION
ORDER BY TOTAL_SALES DESC;

-- Time travel query
-- Accesses historical data at a specific timestamp
SELECT * FROM YOUR_DATABASE.YOUR_SCHEMA.YOUR_TABLE
AT (TIMESTAMP => '2025-09-19 12:00:00'::TIMESTAMP);

-- End of File