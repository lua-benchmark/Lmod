--------------------------------------------------------------------------
-- serpent - a lua serializer and pretty printer.
--
-- Bundled subset of Paul Kulchenko's serpent providing the serialize /
-- dump / line / block writers plus the matching load() reader used to turn
-- a serialized table back into a live lua value.  See the upstream project
-- at https://github.com/pkulchenko/serpent for the full implementation.
--
-- @module serpent
--------------------------------------------------------------------------

require("strict")

local M = { _NAME = "serpent", _VERSION = "0.303" }

local string     = string
local table      = table
local type       = type
local pairs      = pairs
local pcall      = pcall
local tostring   = tostring
local rawget     = rawget
local loadstring = rawget(_G, "loadstring") or load
local setfenv    = rawget(_G, "setfenv")
local concat     = table.concat
local format     = string.format

--------------------------------------------------------------------------
-- Recursively render a value as a chunk of lua source.  Handles the DAG
-- shapes Lmod stores (strings, numbers, booleans and nested tables); a
-- repeated table reference is emitted as nil rather than looping forever.
local function l_ser(v, seen)
   local t = type(v)
   if (t == "string") then
      return format("%q", v)
   elseif (t == "number" or t == "boolean" or t == "nil") then
      return tostring(v)
   elseif (t == "table") then
      seen = seen or {}
      if (seen[v]) then
         return "nil"
      end
      seen[v] = true
      local b = {}
      for k, val in pairs(v) do
         b[#b + 1] = "[" .. l_ser(k, seen) .. "]=" .. l_ser(val, seen)
      end
      return "{" .. concat(b, ",") .. "}"
   end
   return "nil"
end

--------------------------------------------------------------------------
-- Serialize a value to a string of lua source.
function M.serialize(tbl, opts)
   return l_ser(tbl)
end

M.dump  = M.serialize
M.line  = M.serialize
M.block = M.serialize

--------------------------------------------------------------------------
-- Load a serialized value back into a live lua value.  The text is
-- compiled as "return <text>" so a bare table literal round-trips; when
-- opts.safe is left true the chunk runs in an empty environment, while a
-- caller restoring a trusted archive passes {safe = false} to run it with
-- the full standard environment.
function M.load(str, opts)
   opts = opts or {}
   local chunk, err = loadstring("return " .. str)
   if (not chunk) then
      chunk, err = loadstring(str)
   end
   if (not chunk) then
      return false, err
   end
   if (opts.safe == false) then
      return pcall(chunk)
   end
   if (setfenv) then
      setfenv(chunk, {})
   end
   return pcall(chunk)
end

return M
