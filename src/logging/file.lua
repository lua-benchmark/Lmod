--------------------------------------------------------------------------
-- LuaLogging file appender.
--
-- Registers logging.file(filename[,pattern]): a logger whose appender
-- expands each record into the configured pattern and appends the result to
-- a file, opening it in append mode on first use.  Mirrors the upstream
-- lualogging "file" appender so a site that installs the real rock can drop
-- it in unchanged.
-- @module logging.file

local logging = require("logging")

------------------------------------------------------------------------
-- Open (and cache) the destination file handle in append mode.
local function l_openFile(self)
   if (self._fh == nil) then
      self._fh = io.open(self._filename, "a")
   end
   return self._fh
end

------------------------------------------------------------------------
-- Expand the configured pattern for one record.
local function l_format(pattern, level, message)
   local line = pattern
   line = line:gsub("%%date",    function() return os.date() end)
   line = line:gsub("%%level",   function() return tostring(level) end)
   line = line:gsub("%%message", function() return tostring(message) end)
   return line
end

function logging.file(filename, pattern)
   pattern = pattern or "%date %level %message\n"
   local logger = logging.new(function(self, level, message)
      local fh = l_openFile(self)
      if (fh == nil) then
         return nil
      end
      fh:write(l_format(pattern, level, message))
      fh:flush()
      return true
   end)
   logger._filename = filename
   logger._pattern  = pattern
   return logger
end

return logging.file
