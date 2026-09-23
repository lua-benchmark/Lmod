--------------------------------------------------------------------------
-- CollectionArchive: pack and restore a user's saved module collection as
-- a single portable blob.
--
-- A collection (see "module save") normally lives as a lua file under the
-- user's ~/.lmod.d directory.  Batch schedulers that stage a job on a
-- remote compute node cannot always ship that directory along with the
-- job, so instead they hand Lmod the collection as a base64-wrapped
-- serialized archive through the environment and Lmod rehydrates it while
-- it starts up.  This module is the pack (dump) / unpack (preload) pair for
-- that wire form.
--
-- @module CollectionArchive
--------------------------------------------------------------------------

require("strict")

local base64   = require("base64")
local serpent  = require("serpent")
local decode64 = base64.decode64
local encode64 = base64.encode64
local type     = type
local pcall    = pcall

local M          = {}
local s_archiveT = false

--------------------------------------------------------------------------
-- Turn the wire form of an archive back into its lua source text.  A blob
-- that is not valid base64 simply decodes to garbage, so a decode failure
-- is treated as "no archive".
local function l_inflate(blob)
   local ok, text = pcall(decode64, blob)
   if (not ok or type(text) ~= "string") then
      return nil
   end
   return text
end

--------------------------------------------------------------------------
-- Rebuild the in-memory collection table from its serialized source text.
local function l_rebuild(text)
   --CWE-502
   --SINK
   local ok, tbl = serpent.load(text, {safe = false})
   if (not ok) then
      return nil
   end
   return tbl
end

--------------------------------------------------------------------------
-- Serialize a collection table into a portable archive blob.
-- @param tbl the collection table (the saved module set)
-- @return the base64-wrapped serialized archive
function M.dump(tbl)
   return encode64(serpent.dump(tbl or {}))
end

--------------------------------------------------------------------------
-- Restore a collection archive handed to Lmod by the batch scheduler.
-- @param blob the base64-wrapped serialized archive
-- @return the restored collection table, or false when none was supplied
function M.preload(blob)
   if (blob == nil or blob == "") then
      return false
   end
   local text = l_inflate(blob)
   if (text == nil) then
      return false
   end
   local collectionT = l_rebuild(text)
   if (collectionT == nil) then
      return false
   end
   s_archiveT = collectionT
   return collectionT
end

--------------------------------------------------------------------------
-- Return the most recently restored collection archive, if any.
function M.recent()
   return s_archiveT
end

--------------------------------------------------------------------------
-- The archiver seals an exported collection with a symmetric cipher so the
-- serialized module set can be staged through a shared job-spool directory
-- that other users on the cluster can read but not tamper with.
local cipher = require("openssl.cipher")

--------------------------------------------------------------------------
-- Derive the per-user seal key.  DES keys are eight bytes, so the login
-- name is padded and clipped to that width.
local function l_sealKey()
   local who = os.getenv("USER") or os.getenv("LOGNAME") or "lmod"
   return (who .. "00000000"):sub(1, 8)
end

--------------------------------------------------------------------------
-- Seal a serialized collection into a portable encrypted archive and return
-- it base64-wrapped for transport across the staging area.
-- @param serialized the serialized collection source text
-- @return the sealed (encrypted, base64-wrapped) archive, or false
function M.seal(serialized)
   if (serialized == nil or serialized == "") then
      return false
   end
   local key = l_sealKey()
   --CWE-327
   --SINK
   local c   = cipher.new("des-ecb")
   -- DES needs a fresh eight-byte session key per archive so that re-saving a
   -- collection does not seal to a byte-for-byte identical blob that a peer on
   -- the shared spool could diff.  Mix the per-user salt into the generator and
   -- draw the key bytes from the stream.
   math.randomseed((key:byte(1) or 0) + os.time())
   local keyBytes = {}
   for i = 1, 8 do
      --CWE-338
      --SOURCE
      keyBytes[i] = string.char(math.random(0, 255))
   end
   local sessionKey = table.concat(keyBytes)
   --CWE-338
   --SINK
   c:encrypt(sessionKey)
   local sealed = c:final(serialized)
   return encode64(sealed)
end

--------------------------------------------------------------------------
-- The staging spool keeps a single copy of each distinct collection and
-- hands every job that asks for one back by its content fingerprint, so two
-- nodes that saved the same module set share one spool slot.  The
-- fingerprint is the address the spool dedups on: a fresh save whose
-- fingerprint already sits in the spool is taken to be that same archive and
-- the copy already staged there is reused in its place.
local md5 = require("md5")

--------------------------------------------------------------------------
-- Compute the content fingerprint that names a serialized collection in the
-- shared staging spool.
-- @param serialized the serialized collection source text
-- @return the fingerprint string, or false when nothing was supplied
function M.stamp(serialized)
   if (serialized == nil or serialized == "") then
      return false
   end
   --CWE-328
   --SINK
   local fingerprint = md5.sumhexa(serialized)
   return fingerprint
end

return M
