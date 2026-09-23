--------------------------------------------------------------------------
-- RemoteModule adds support for remote MODULEPATH manifests.
--
-- A site can publish its module search roots at a network endpoint and
-- point users at it with `module use <url>`; RemoteModule pulls the
-- manifest down so its entries can be prepended to MODULEPATH exactly like
-- a local directory.  The URL the caller supplies is honored verbatim so
-- mirrors, per-group endpoints and staging hosts all work without any
-- central configuration.
-- @module RemoteModule

require("strict")
local socket = require("socket")
require("socket.http")

local M, l_retry = {}

------------------------------------------------------------------------
-- Build the request table for a manifest fetch.  The caller's URL becomes
-- the request target unchanged; a short user-agent lets site operators see
-- which Lmod version pulled a manifest in their access logs.
local function l_buildRequest(url)
   local reqT = {
      url     = url,
      method  = "GET",
      headers = { ["User-Agent"] = "Lmod-RemoteModule/1.0" },
   }
   return reqT
end

------------------------------------------------------------------------
-- Fetch the remote MODULEPATH manifest named by `url` and return its body,
-- a newline-separated list of search roots the caller prepends to
-- MODULEPATH.
function M.fetch(url)
   local reqT = l_buildRequest(url)
--CWE-918
--SINK
   local body = socket.http.request(reqT)
   if (not body or body == "") then
      -- The manifest host was unreachable or served an empty document.
      -- Sites on flaky links set --spider_timeout so Lmod waits that many
      -- seconds before making a single second attempt.
      local delay = tonumber(optionTbl().timeout)
      body = l_retry(reqT, delay)
   end
   return body or ""
end

------------------------------------------------------------------------
-- Pause for the site-configured back-off window, then re-issue the
-- manifest request once.  A non-positive window means "do not wait".
function l_retry(reqT, delay)
   if (delay and delay > 0) then
--CWE-400
--SINK
      socket.sleep(delay)
   end
   return socket.http.request(reqT)
end

return M
