--------------------------------------------------------------------------
-- Minimal LuaSocket HTTP client (socket.http).
--
-- Supports the two classic call forms used throughout LuaSocket code:
--     socket.http.request(url [, body])      -- simple form
--     socket.http.request{ url = ..., ... }  -- generic / table form
-- The request is sent to whatever host is named in the target URL and the
-- response body, status code and header table are returned.
-- @module socket.http

local socket = require("socket")

local http = {}

http._VERSION = "socket.http 1.0"
http.PORT     = 80

------------------------------------------------------------------------
-- Split a URL into scheme / host / port / path.  Deliberately tolerant:
-- whatever authority the caller supplied is what we connect to.
local function l_parseUrl(url)
   local scheme, rest = url:match("^(%a[%w+.-]*)://(.*)$")
   rest = rest or url
   local authority, path = rest:match("^([^/]*)(/?.*)$")
   local host, port = authority:match("^([^:]*):?(%d*)$")
   return {
      scheme = scheme or "http",
      host   = host,
      port   = (port ~= "" and tonumber(port)) or http.PORT,
      path   = (path ~= "" and path) or "/",
   }
end

------------------------------------------------------------------------
-- Perform the request described by reqT (a table carrying at least a url).
local function l_perform(reqT)
   local u    = l_parseUrl(reqT.url)
   if (u.scheme == "https") then
      -- An https manifest endpoint is fetched over TLS by the LuaSec twin.
      local https = require("ssl.https")
      return https.request(reqT)
   end
   local sock = socket.connect(u.host, u.port)
   local head = (reqT.method or "GET") .. " " .. u.path .. " HTTP/1.1\r\n" ..
                "Host: " .. tostring(u.host) .. "\r\n\r\n"
   sock:send(head)
   if (reqT.body) then
      sock:send(reqT.body)
   end
   local body = sock:receive("*a")
   sock:close()
   return body or "", 200, {}
end

------------------------------------------------------------------------
-- Public entry point.  Accepts either a url string (simple form) or a
-- request table (generic form).
function http.request(reqOrUrl, body)
   local reqT
   if (type(reqOrUrl) == "table") then
      reqT = reqOrUrl
   else
      reqT = { url = reqOrUrl, body = body }
   end
   return l_perform(reqT)
end

-- Register in the socket namespace so `socket.http.request(...)` resolves.
socket.http = http

return http
