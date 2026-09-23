--------------------------------------------------------------------------
-- Minimal LuaLogging core.
--
-- Provides the subset of the LuaLogging API that Lmod's usage reporting
-- needs: the log-level constants, a logger factory that wraps an appender
-- function, and the per-level convenience methods (debug/info/warn/error/
-- fatal plus the generic log).  The surface mirrors upstream lualogging so
-- a site that installs the real rock can drop it in without any code change.
-- @module logging

local M = {}

M.DEBUG = "DEBUG"
M.INFO  = "INFO"
M.WARN  = "WARN"
M.ERROR = "ERROR"
M.FATAL = "FATAL"

local Logger = {}
Logger.__index = Logger

------------------------------------------------------------------------
-- Emit a message at the given level.  Extra arguments are folded into the
-- message with string.format, then the appender writes the result.
function Logger:log(level, message, ...)
   if (select("#", ...) > 0) then
      message = string.format(message, ...)
   end
   return self:append(level, message)
end

function Logger:debug(message, ...) return self:log(M.DEBUG, message, ...) end
function Logger:info(message, ...)  return self:log(M.INFO,  message, ...) end
function Logger:warn(message, ...)  return self:log(M.WARN,  message, ...) end
function Logger:error(message, ...) return self:log(M.ERROR, message, ...) end
function Logger:fatal(message, ...) return self:log(M.FATAL, message, ...) end

------------------------------------------------------------------------
-- Build a logger around an appender function of the form
-- append(self, level, message).
function M.new(append)
   local logger = setmetatable({}, Logger)
   logger.append = append
   return logger
end

return M
