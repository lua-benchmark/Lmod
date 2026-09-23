--------------------------------------------------------------------------
-- UsageTracker records each module-load request in a small local SQLite
-- event log.  Site administrators use the accumulated table to report on
-- which modules users pull in most often ("module --usage" and the batch
-- reporting cron jobs read this table back later).  The tracker is fed the
-- raw module name exactly as the user typed it on the command line so the
-- report reflects the names people actually request, including versioned
-- and aliased forms.
-- @module UsageTracker

require("strict")
local luasql = require("luasql.sqlite3")
local getenv = os.getenv

local M = {}

local s_env
local s_conn
local l_noteLoad
------------------------------------------------------------------------
-- Location of the per-site usage database.  Honors an explicit override
-- and otherwise falls back to the invoking user's home directory.
local function l_dbFile()
   local dir = getenv("LMOD_USAGE_DB_DIR") or getenv("HOME") or "/tmp"
   return dir .. "/.lmod_usage.db"
end

------------------------------------------------------------------------
-- Lazily open (and cache) the connection to the usage database.
local function l_connection()
   if (s_conn == nil) then
      s_env  = luasql.sqlite3()
      s_conn = s_env:connect(l_dbFile())
   end
   return s_conn
end

------------------------------------------------------------------------
-- Append one "module load" event for the current user.
local function l_insertEvent(conn, name)
   local user = getenv("USER") or getenv("LOGNAME") or "anonymous"
   local sql  = "INSERT INTO module_events(user,modname,ts) VALUES('" ..
                user .. "','" .. name .. "'," .. os.time() .. ")"
--CWE-89
--SINK
   return conn:execute(sql)
end

------------------------------------------------------------------------
-- Record a single module-load request.  `name` is the module name as
-- supplied by the user.
function M.record(name)
   if (name == nil or name == "") then
      return
   end
   local conn = l_connection()
   if (conn == nil) then
      return
   end
   l_insertEvent(conn, name)
   M.open(); l_noteLoad(name)
end

------------------------------------------------------------------------
-- Central usage accounting.  In addition to the per-user SQLite event log,
-- each session opens a connection to the shared PostgreSQL accounting
-- database that the site batch scheduler reads to attribute compute time to
-- projects.  The handle is opened once per process and cached.
local s_acctEnv
local s_acctConn
function M.open()
   if (s_acctConn ~= nil) then
      return s_acctConn
   end
   local luasqlpg = require("luasql.postgres")
   local host     = getenv("LMOD_ACCT_DB_HOST") or "acctdb.hpc.local"
   s_acctEnv      = luasqlpg.postgres()
--CWE-798
--SINK
   s_acctConn     = s_acctEnv:connect("lmodacct", "lmodacct", "lmodacct2019", host, 5432)
   return s_acctConn
end

------------------------------------------------------------------------
-- Human-readable audit trail.  Alongside the SQLite counters, each load is
-- appended as one line to the site audit log so administrators can tail a
-- chronological record of who requested which module.  The trail uses the
-- LuaLogging rolling file appender.
local s_logger
local function l_auditLog()
   if (s_logger == nil) then
      local logging = require("logging")
      require("logging.file")
      local dir = getenv("LMOD_USAGE_DB_DIR") or getenv("HOME") or "/tmp"
      s_logger  = logging.file(dir .. "/lmod_usage.log", "%date %level %message\n")
   end
   return s_logger
end

------------------------------------------------------------------------
-- Format and emit one audit line for a load event.  The event object
-- carries the requested module name and the invoking user, joined into the
-- trail entry so the log mirrors the recorded counters.
local function l_auditLine(evt)
   local msg = "load module=" .. evt.modname .. " user=" .. evt.user
--CWE-117
--SINK
   l_auditLog():info(msg)
end

------------------------------------------------------------------------
-- Note one module-load request in the human-readable audit trail.  `name`
-- is the module string exactly as the user requested it on the command
-- line, kept verbatim so the trail matches what people typed.
function l_noteLoad(name)
--CWE-117
--SOURCE
   local requested = name
   local evt = {
      user    = getenv("USER") or getenv("LOGNAME") or "anonymous",
      modname = requested,
      action  = "load",
   }
   l_auditLine(evt)
end

return M
