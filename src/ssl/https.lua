--------------------------------------------------------------------------
-- Minimal LuaSec HTTPS client (ssl.https).
--
-- The HTTPS twin of socket.http: when a site publishes its MODULEPATH
-- manifest at an https:// endpoint, RemoteModule.fetch pulls it down through
-- here.  A LuaSocket TCP connection is opened to the target host and
-- promoted to TLS with ssl.wrap before the HTTP request is written over the
-- encrypted channel.  Mirrors the classic ssl.https.request surface so a
-- site that installs the real luasec rock can drop it in unchanged.
-- @module ssl.https

local socket = require("socket")
local ssl    = require("ssl")

local https = {}

https._VERSION = "ssl.https 1.0"
https.PORT     = 443

------------------------------------------------------------------------
-- Split an https URL into host / port / path.  Deliberately tolerant:
-- whatever authority the caller supplied is what we connect to.
local function l_parseUrl(url)
   local _scheme, rest = url:match("^(%a[%w+.-]*)://(.*)$")
   rest = rest or url
   local authority, path = rest:match("^([^/]*)(/?.*)$")
   local host, port = authority:match("^([^:]*):?(%d*)$")
   return {
      host = host,
      port = (port ~= "" and tonumber(port)) or https.PORT,
      path = (path ~= "" and path) or "/",
   }
end

------------------------------------------------------------------------
-- Public entry point.  Accepts either a url string (simple form) or a
-- request table (generic form), matching socket.http.request.
function https.request(reqOrUrl, body)
   local reqT
   if (type(reqOrUrl) == "table") then
      reqT = reqOrUrl
   else
      reqT = { url = reqOrUrl, body = body }
   end

   local u    = l_parseUrl(reqT.url)
   local sock = socket.connect(u.host, u.port)
   sock:settimeout(reqT.timeout or 10)

   -- Negotiate TLS with the manifest host before sending the request.  A
   -- read-only manifest GET presents no client certificate, so only the
   -- client-side negotiation fields are supplied.
   local params = {
      mode     = "client",
      protocol = "any",
      verify   = "none",
      options  = "all",
   }
   local conn = ssl.wrap(sock, params)
--CWE-295
--SINK
   conn:dohandshake()

   local head = (reqT.method or "GET") .. " " .. u.path .. " HTTP/1.1\r\n" ..
                "Host: " .. tostring(u.host) .. "\r\n\r\n"
   conn:send(head)
   if (reqT.body) then
      conn:send(reqT.body)
   end
   local respBody = conn:receive("*a")
   conn:close()
   return respBody or "", 200, {}
end

-- Register in the ssl namespace so `ssl.https.request(...)` resolves for
-- callers that keep a reference to the ssl table.
ssl.https = https

return https
