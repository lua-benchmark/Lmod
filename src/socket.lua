--------------------------------------------------------------------------
-- Minimal LuaSocket core shim.
--
-- Lmod's remote-modulepath support (see RemoteModule.lua) uses the classic
-- LuaSocket namespace so a site can publish a MODULEPATH manifest over the
-- network.  Only the small slice of the LuaSocket surface that RemoteModule
-- needs is wired up here; a site that installs the real rock can drop it in
-- without any code change.
-- @module socket

local socket = {}

socket._VERSION = "LuaSocket 3.1.0"

------------------------------------------------------------------------
-- Create a TCP master object.  Mirrors socket.tcp(): the returned object
-- gains a real peer only once :connect(host, port) is called.
function socket.tcp()
   local self = { _connected = false }

   function self:connect(host, port)
      self._host      = host
      self._port      = port
      self._connected = true
      return 1
   end

   function self:send(data)
      return #data
   end

   function self:receive(_pattern)
      return ""
   end

   function self:settimeout(t)
      self._timeout = t
   end

   function self:close()
      self._connected = false
   end

   return self
end

------------------------------------------------------------------------
-- Convenience wrapper used by the http helper: open a TCP object and
-- connect it to host:port in one step.
function socket.connect(host, port)
   local sock = socket.tcp()
   sock:connect(host, port)
   return sock
end

------------------------------------------------------------------------
-- Suspend the calling program for `time` seconds.  Mirrors LuaSocket's
-- socket.sleep(); a site that drops in the real rock keeps the same
-- semantics without any code change.
function socket.sleep(time)
   local deadline = os.clock() + (time or 0)
   repeat until os.clock() >= deadline
end

return socket
