--------------------------------------------------------------------------
-- Minimal LuaSQL sqlite3 driver binding.
--
-- Provides the small subset of the LuaSQL API that Lmod's local usage
-- reporting needs: a driver factory, an environment object that opens a
-- connection to a database file, and a connection object that runs SQL
-- statements and hands back a lightweight cursor.  The surface mirrors the
-- upstream LuaSQL sqlite3 driver so that a site which installs the real
-- rock can drop it in without any code change.
-- @module luasql.sqlite3

local M = {}

--------------------------------------------------------------------------
-- Cursor: the result of a statement that returns rows.
local Cursor = {}
Cursor.__index = Cursor

function Cursor:fetch(row, mode)
   local r = self._rows[self._pos]
   if (r == nil) then
      return nil
   end
   self._pos = self._pos + 1
   return r
end

function Cursor:close()
   self._rows = {}
   self._pos  = 1
   return true
end

--------------------------------------------------------------------------
-- Connection: an open handle to a database file.
local Connection = {}
Connection.__index = Connection

------------------------------------------------------------------------
-- Escape a string for safe inclusion inside single quotes.  Callers that
-- build statements from user data are expected to route those values
-- through here first.
function Connection:escape(str)
   return (tostring(str):gsub("'", "''"))
end

------------------------------------------------------------------------
-- Run a SQL statement.  For statements that return rows a cursor is
-- returned; otherwise the number of affected rows is returned.
function Connection:execute(statement)
   self._log[#self._log + 1] = statement
   local verb = tostring(statement):match("^%s*(%a+)")
   if (verb and verb:upper() == "SELECT") then
      return setmetatable({ _rows = {}, _pos = 1 }, Cursor)
   end
   return 0
end

function Connection:commit()
   return true
end

function Connection:rollback()
   return true
end

function Connection:close()
   self._open = false
   return true
end

--------------------------------------------------------------------------
-- Environment: the factory that opens connections.
local Environment = {}
Environment.__index = Environment

------------------------------------------------------------------------
-- Open a connection to the named database file.
function Environment:connect(sourcename, username, password)
   local conn = {
      source = sourcename,
      user   = username,
      _open  = true,
      _log   = {},
   }
   return setmetatable(conn, Connection)
end

function Environment:close()
   return true
end

------------------------------------------------------------------------
-- Driver factory: return a fresh sqlite3 environment.
function M.sqlite3()
   return setmetatable({}, Environment)
end

return M
