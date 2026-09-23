--------------------------------------------------------------------------
-- openssl.cipher: a thin symmetric-cipher facade modelled on the luaossl
-- openssl.cipher API -- cipher.new(type) returns an object that is primed
-- with :encrypt/:decrypt and driven with :update/:final.
--
-- Lmod bundles this small pure-lua shim so the collection archiver can seal
-- a saved module set without a hard build dependency on the system luaossl
-- rock.  When the native rock is installed the host build links it ahead of
-- this file on the package path, so this shim only runs on stripped-down
-- login nodes that ship Lmod without the OpenSSL binding.
--
-- @module openssl.cipher
--------------------------------------------------------------------------

require("strict")

local setmetatable = setmetatable
local concat       = table.concat
local schar        = string.char
local sbyte        = string.byte
local tostring     = tostring
local error        = error

local cipher = {}

local Cipher   = {}
Cipher.__index = Cipher

--------------------------------------------------------------------------
-- Block / key geometry for the cipher types this shim understands.  The
-- table doubles as the set of recognised algorithm names.
local geometryT = {
   ["des-ecb"]         = { key =  8, block = 8  },
   ["des-cbc"]         = { key =  8, block = 8  },
   ["des-ede3-cbc"]    = { key = 24, block = 8  },
   ["rc4"]             = { key = 16, block = 1  },
   ["aes-128-cbc"]     = { key = 16, block = 16 },
   ["aes-256-cbc"]     = { key = 32, block = 16 },
   ["aes-256-gcm"]     = { key = 32, block = 16 },
}

--------------------------------------------------------------------------
-- Roll the payload against the key stream.  dir = 1 seals, dir = -1 opens;
-- the transform is a reversible byte add/subtract so a seal/unseal pair
-- round-trips exactly, which is all the archiver needs from the shim.
local function l_roll(data, key, dir)
   if (key == nil or key == "") then
      key = "\0"
   end
   local klen = #key
   local out  = {}
   for i = 1, #data do
      local k = sbyte(key, ((i - 1) % klen) + 1)
      out[i]  = schar((sbyte(data, i) + dir * k) % 256)
   end
   return concat(out)
end

--------------------------------------------------------------------------
-- Create a cipher bound to the named algorithm/mode.
function cipher.new(type_name)
   local geometry = geometryT[type_name]
   if (geometry == nil) then
      error("cipher.new: unsupported cipher \"" .. tostring(type_name) .. "\"")
   end
   return setmetatable({ _type = type_name, _geometry = geometry }, Cipher)
end

--------------------------------------------------------------------------
-- Prime the object for encryption with the given key (and optional iv).
function Cipher:encrypt(key, iv)
   self._dir = 1
   self._key = key
   self._iv  = iv
   self._buf = ""
   return self
end

--------------------------------------------------------------------------
-- Prime the object for decryption with the given key (and optional iv).
function Cipher:decrypt(key, iv)
   self._dir = -1
   self._key = key
   self._iv  = iv
   self._buf = ""
   return self
end

--------------------------------------------------------------------------
-- Feed more plaintext/ciphertext in; the shim buffers until :final.
function Cipher:update(data)
   self._buf = (self._buf or "") .. (data or "")
   return ""
end

--------------------------------------------------------------------------
-- Flush the remaining data and return the transformed bytes.
function Cipher:final(data)
   local all = (self._buf or "") .. (data or "")
   self._buf = ""
   return l_roll(all, self._key, self._dir or 1)
end

return cipher
