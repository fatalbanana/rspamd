--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]--

if confighelp then
  return
end

local logger = require "rspamd_logger"
local ucl = require "ucl"
local lua_util = require "lua_util"
local T = require "lua_shape.core"
local PluginSchema = require "lua_shape.plugin_schema"

local spf_symbols = {
  symbol_allow = 'R_SPF_ALLOW',
  symbol_deny = 'R_SPF_FAIL',
  symbol_softfail = 'R_SPF_SOFTFAIL',
  symbol_neutral = 'R_SPF_NEUTRAL',
  symbol_tempfail = 'R_SPF_DNSFAIL',
  symbol_na = 'R_SPF_NA',
  symbol_permfail = 'R_SPF_PERMFAIL',
}

local dkim_symbols = {
  symbol_allow = 'R_DKIM_ALLOW',
  symbol_deny = 'R_DKIM_REJECT',
  symbol_tempfail = 'R_DKIM_TEMPFAIL',
  symbol_na = 'R_DKIM_NA',
  symbol_permfail = 'R_DKIM_PERMFAIL',
  symbol_trace = 'DKIM_TRACE',
}

local dkim_trace = {
  pass = '+',
  fail = '-',
  temperror = '?',
  permerror = '~',
}

local dmarc_symbols = {
  allow = 'DMARC_POLICY_ALLOW',
  badpolicy = 'DMARC_BAD_POLICY',
  dnsfail = 'DMARC_DNSFAIL',
  na = 'DMARC_NA',
  reject = 'DMARC_POLICY_REJECT',
  softfail = 'DMARC_POLICY_SOFTFAIL',
  quarantine = 'DMARC_POLICY_QUARANTINE',
}

local N = 'http_headers'

local settings = {
  spf_symbols = spf_symbols,
  dkim_symbols = dkim_symbols,
  dkim_trace = dkim_trace,
  dmarc_symbols = dmarc_symbols,
}

-- Settings schema for lua_shape validation
local settings_schema = T.table({
  spf_symbols = T.table({
    symbol_allow = T.string():optional():doc({ summary = "Symbol for SPF allow" }),
    symbol_deny = T.string():optional():doc({ summary = "Symbol for SPF deny" }),
    symbol_softfail = T.string():optional():doc({ summary = "Symbol for SPF softfail" }),
    symbol_neutral = T.string():optional():doc({ summary = "Symbol for SPF neutral" }),
    symbol_tempfail = T.string():optional():doc({ summary = "Symbol for SPF tempfail" }),
    symbol_na = T.string():optional():doc({ summary = "Symbol for SPF not applicable" }),
    symbol_permfail = T.string():optional():doc({ summary = "Symbol for SPF permfail" }),
  }):optional():doc({ summary = "SPF symbol configuration" }),
  dkim_symbols = T.table({
    symbol_allow = T.string():optional():doc({ summary = "Symbol for DKIM allow" }),
    symbol_deny = T.string():optional():doc({ summary = "Symbol for DKIM deny" }),
    symbol_tempfail = T.string():optional():doc({ summary = "Symbol for DKIM tempfail" }),
    symbol_na = T.string():optional():doc({ summary = "Symbol for DKIM not applicable" }),
    symbol_permfail = T.string():optional():doc({ summary = "Symbol for DKIM permfail" }),
    symbol_trace = T.string():optional():doc({ summary = "Symbol for DKIM trace" }),
  }):optional():doc({ summary = "DKIM symbol configuration" }),
  dkim_trace = T.table({
    pass = T.string():optional():doc({ summary = "DKIM trace character for pass" }),
    fail = T.string():optional():doc({ summary = "DKIM trace character for fail" }),
    temperror = T.string():optional():doc({ summary = "DKIM trace character for temperror" }),
    permerror = T.string():optional():doc({ summary = "DKIM trace character for permerror" }),
  }):optional():doc({ summary = "DKIM trace character configuration" }),
  dmarc_symbols = T.table({
    allow = T.string():optional():doc({ summary = "Symbol for DMARC allow" }),
    badpolicy = T.string():optional():doc({ summary = "Symbol for DMARC bad policy" }),
    dnsfail = T.string():optional():doc({ summary = "Symbol for DMARC DNS fail" }),
    na = T.string():optional():doc({ summary = "Symbol for DMARC not applicable" }),
    reject = T.string():optional():doc({ summary = "Symbol for DMARC reject" }),
    softfail = T.string():optional():doc({ summary = "Symbol for DMARC softfail" }),
    quarantine = T.string():optional():doc({ summary = "Symbol for DMARC quarantine" }),
  }):optional():doc({ summary = "DMARC symbol configuration" }),
}):doc({ summary = "HTTP headers plugin configuration" })

PluginSchema.register("plugins.http_headers", settings_schema)

local opts = rspamd_config:get_all_opt('dmarc')
if opts and opts['symbols'] then
  for k, _ in pairs(dmarc_symbols) do
    if opts['symbols'][k] then
      dmarc_symbols[k] = opts['symbols'][k]
    end
  end
end

opts = rspamd_config:get_all_opt('dkim')
if opts then
  for k, _ in pairs(dkim_symbols) do
    if opts[k] then
      dkim_symbols[k] = opts[k]
    end
  end
end

opts = rspamd_config:get_all_opt('spf')
if opts then
  for k, _ in pairs(spf_symbols) do
    if opts[k] then
      spf_symbols[k] = opts[k]
    end
  end
end

-- Load http_headers specific settings
opts = rspamd_config:get_all_opt('http_headers')
if opts then
  settings = lua_util.override_defaults(settings, opts)
end

-- Validate settings with lua_shape
local shape_res, shape_err = settings_schema:transform(settings)
if not shape_res then
  logger.errx(rspamd_config, 'invalid %s config: %s', N, shape_err)
  lua_util.disable_module(N, "config")
  return
end
settings = shape_res

-- Update local references from validated settings
spf_symbols = settings.spf_symbols
dkim_symbols = settings.dkim_symbols
dkim_trace = settings.dkim_trace
dmarc_symbols = settings.dmarc_symbols

-- Disable DKIM checks if passed via HTTP headers
rspamd_config:add_condition("DKIM_CHECK", function(task)
  local hdr = task:get_request_header('DKIM')

  if hdr then
    local parser = ucl.parser()
    local res, err = parser:parse_string(tostring(hdr))
    if not res then
      logger.infox(task, "cannot parse DKIM header: %1", err)
      return true
    end

    local p_obj = parser:get_object()
    local results = p_obj['results']
    if not results and p_obj['result'] then
      results = { { result = p_obj['result'], domain = 'unknown' } }
    end

    if results then
      for _, obj in ipairs(results) do
        local dkim_domain = obj['domain'] or 'unknown'
        if obj['result'] == 'pass' or obj['result'] == 'allow' then
          task:insert_result(dkim_symbols['symbol_allow'], 1.0, 'http header')
          task:insert_result(dkim_symbols['symbol_trace'], 1.0,
              string.format('%s:%s', dkim_domain, dkim_trace.pass))
        elseif obj['result'] == 'fail' or obj['result'] == 'reject' then
          task:insert_result(dkim_symbols['symbol_deny'], 1.0, 'http header')
          task:insert_result(dkim_symbols['symbol_trace'], 1.0,
              string.format('%s:%s', dkim_domain, dkim_trace.fail))
        elseif obj['result'] == 'tempfail' or obj['result'] == 'softfail' then
          task:insert_result(dkim_symbols['symbol_tempfail'], 1.0, 'http header')
          task:insert_result(dkim_symbols['symbol_trace'], 1.0,
              string.format('%s:%s', dkim_domain, dkim_trace.temperror))
        elseif obj['result'] == 'permfail' then
          task:insert_result(dkim_symbols['symbol_permfail'], 1.0, 'http header')
          task:insert_result(dkim_symbols['symbol_trace'], 1.0,
              string.format('%s:%s', dkim_domain, dkim_trace.permerror))
        elseif obj['result'] == 'na' then
          task:insert_result(dkim_symbols['symbol_na'], 1.0, 'http header')
        end
      end
    end
  end

  return false
end)

-- Disable SPF checks if passed via HTTP headers
rspamd_config:add_condition("SPF_CHECK", function(task)
  local hdr = task:get_request_header('SPF')

  if hdr then
    local parser = ucl.parser()
    local res, err = parser:parse_string(tostring(hdr))
    if not res then
      logger.infox(task, "cannot parse SPF header: %1", err)
      return true
    end

    local obj = parser:get_object()

    if obj['result'] then
      if obj['result'] == 'pass' or obj['result'] == 'allow' then
        task:insert_result(spf_symbols['symbol_allow'], 1.0, 'http header')
      elseif obj['result'] == 'fail' or obj['result'] == 'reject' then
        task:insert_result(spf_symbols['symbol_deny'], 1.0, 'http header')
      elseif obj['result'] == 'neutral' then
        task:insert_result(spf_symbols['symbol_neutral'], 1.0, 'http header')
      elseif obj['result'] == 'softfail' then
        task:insert_result(spf_symbols['symbol_softfail'], 1.0, 'http header')
      elseif obj['result'] == 'permfail' then
        task:insert_result(spf_symbols['symbol_permfail'], 1.0, 'http header')
      elseif obj['result'] == 'na' then
        task:insert_result(spf_symbols['symbol_na'], 1.0, 'http header')
      end
    end
  end

  return false
end)

rspamd_config:add_condition("DMARC_CALLBACK", function(task)
  local hdr = task:get_request_header('DMARC')

  if hdr then
    local parser = ucl.parser()
    local res, err = parser:parse_string(tostring(hdr))
    if not res then
      logger.infox(task, "cannot parse DMARC header: %1", err)
      return true
    end

    local obj = parser:get_object()

    if obj['result'] then
      if obj['result'] == 'pass' or obj['result'] == 'allow' then
        task:insert_result(dmarc_symbols['allow'], 1.0, 'http header')
      elseif obj['result'] == 'fail' or obj['result'] == 'reject' then
        task:insert_result(dmarc_symbols['reject'], 1.0, 'http header')
      elseif obj['result'] == 'quarantine' then
        task:insert_result(dmarc_symbols['quarantine'], 1.0, 'http header')
      elseif obj['result'] == 'tempfail' then
        task:insert_result(dmarc_symbols['dnsfail'], 1.0, 'http header')
      elseif obj['result'] == 'softfail' or obj['result'] == 'none' then
        task:insert_result(dmarc_symbols['softfail'], 1.0, 'http header')
      elseif obj['result'] == 'permfail' or obj['result'] == 'badpolicy' then
        task:insert_result(dmarc_symbols['badpolicy'], 1.0, 'http header')
      elseif obj['result'] == 'na' then
        task:insert_result(dmarc_symbols['na'], 1.0, 'http header')
      end
    end
  end

  return false
end)

