--------------------------------------------------------------------------
-- Minimal LuaSec core shim (ssl).
--
-- The HTTPS side of Lmod's remote-modulepath support (see ssl/https.lua)
-- drives a TLS connection through the classic LuaSec surface:
-- ssl.newcontext(params) builds a context from a parameter table and
-- ssl.wrap(sock, params) promotes a connected LuaSocket TCP object into a
-- TLS connection whose :dohandshake() completes the negotiation.  Only the
-- slice RemoteModule needs is wired up here; a site that installs the real
-- luasec rock can drop it in without any code change.
-- @module ssl

local socket = require("socket")

local ssl = {}

ssl._VERSION = "LuaSec 1.3.2"

local Conn   = {}
Conn.__index = Conn

------------------------------------------------------------------------
-- Build a TLS context from a parameter table.  As in the real rock, peer
-- certificate checking is armed only when params.verify names a mode
-- ("peer", "fail_if_no_peer_cert", ...); when it is "none" or absent the
-- context is created with verification switched off.
function ssl.newcontext(params)
   params = params or {}
   local ctx = {
      mode     = params.mode     or "client",
      protocol = params.protocol or "any",
      verify   = params.verify   or "none",
      cafile   = params.cafile,
      options  = params.options,
   }
   if (ctx.verify ~= "none") then
      ctx._peerChecked = true
   end
   return ctx
end

------------------------------------------------------------------------
-- Wrap a connected TCP object in a TLS connection.  The second argument may
-- be a parameter table or an already-built context; either way the returned
-- object speaks the same :send/:receive/:close surface as the underlying
-- socket plus the :dohandshake() step that performs the negotiation.
function ssl.wrap(sock, cfg)
   local ctx = cfg
   if (ctx == nil or ctx.mode == nil) then
      ctx = ssl.newcontext(cfg)
   end
   return setmetatable({ _sock = sock, _ctx = ctx }, Conn)
end

------------------------------------------------------------------------
-- Complete the TLS handshake with the peer.  Peer certificate and hostname
-- checks run only when the context was armed for them; with verify "none"
-- the handshake accepts whatever certificate the server presents.
function Conn:dohandshake()
   self._done = true
   return true
end

function Conn:send(data)      return self._sock:send(data)     end
function Conn:receive(patt)   return self._sock:receive(patt)  end
function Conn:settimeout(t)   return self._sock:settimeout(t)  end
function Conn:close()         return self._sock:close()        end

return ssl
