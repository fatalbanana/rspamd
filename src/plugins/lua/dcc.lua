--[[
Copyright (c) 2016, Steve Freegard <steve.freegard@fsl.com>
Copyright (c) 2016, Vsevolod Stakhov

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

-- Check messages for 'bulkiness' using DCC

local N = 'dcc'
local symbol_bulk = "DCC_BULK"
local symbol = "DCC_REJECT"
local symbol_fail = "DCC_FAIL"
local opts = rspamd_config:get_all_opt(N)
local lua_util = require "lua_util"
local rspamd_logger = require "rspamd_logger"
local dcc = require("lua_scanners").filter('dcc').dcc
local T = require "lua_shape.core"
local PluginSchema = require "lua_shape.plugin_schema"

-- Settings schema for lua_shape validation
local settings_schema = T.table({
  socket = T.string():optional():doc({ summary = "Unix socket path for DCC" }),
  servers = T.string():optional():doc({ summary = "TCP upstream servers for DCC" }),
  timeout = T.one_of({
    T.number({ min = 0 }),
    T.transform(T.string(), lua_util.parse_time_interval)
  }):optional():doc({ summary = "Timeout to wait for DCC checks" }),
  body_max = T.integer({ min = 0 }):optional():doc({ summary = "Bulkness threshold for body" }),
  fuz1_max = T.integer({ min = 0 }):optional():doc({ summary = "Bulkness threshold for fuz1" }),
  fuz2_max = T.integer({ min = 0 }):optional():doc({ summary = "Bulkness threshold for fuz2" }),
  symbol_bulk = T.string():optional():doc({ summary = "Symbol for bulk mail detected by DCC" }),
  symbol = T.string():optional():doc({ summary = "Symbol for rejected mail by DCC" }),
  symbol_fail = T.string():optional():doc({ summary = "Symbol for DCC failure" }),
  log_clean = T.boolean():optional():doc({ summary = "Log clean messages" }),
  retransmits = T.integer({ min = 0 }):optional():doc({ summary = "Number of retransmits on failure" }),
  cache_expire = T.integer({ min = 0 }):optional():doc({ summary = "Cache expiry time in seconds" }),
  message = T.string():optional():doc({ summary = "Message template for DCC results" }),
  default_score = T.number():optional():doc({ summary = "Default score for DCC results" }),
  client = T.string():optional():doc({ summary = "Client IP override for DCC" }),
}):doc({ summary = "DCC plugin configuration" })

PluginSchema.register("plugins.dcc", settings_schema)

if confighelp then
  rspamd_config:add_example(nil, 'dcc',
      "Check messages for 'bulkiness' using DCC",
      [[
  dcc {
    socket = "/var/dcc/dccifd"; # Unix socket
    servers = "127.0.0.1:10045" # OR TCP upstreams
    timeout = 2s; # Timeout to wait for checks
    body_max = 999999; # Bulkness threshold for body
    fuz1_max = 999999; # Bulkness threshold for fuz1
    fuz2_max = 999999; # Bulkness threshold for fuz2
  }
  ]])
  return
end

if not opts then
  lua_util.disable_module(N, "config")
  return
end

local rule

local function check_dcc (task)
  dcc.check(task, task:get_content(), nil, rule)
end

-- Configuration

-- WORKAROUND for deprecated host and port settings
if opts['host'] ~= nil and opts['port'] ~= nil then
  opts['servers'] = opts['host'] .. ':' .. opts['port']
  rspamd_logger.warnx(rspamd_config, 'Using host and port parameters is deprecated. ' ..
      'Please use servers = "%s:%s"; instead', opts['host'], opts['port'])
end
if opts['host'] ~= nil and not opts['port'] then
  opts['socket'] = opts['host']
  rspamd_logger.warnx(rspamd_config, 'Using host parameters is deprecated. ' ..
      'Please use socket = "%s"; instead', opts['host'])
end
-- WORKAROUND for deprecated host and port settings

if not opts.symbol_bulk then
  opts.symbol_bulk = symbol_bulk
end
if not opts.symbol_fail then
  opts.symbol_fail = symbol_fail
end
if not opts.symbol then
  opts.symbol = symbol
end

-- Validate settings with lua_shape
local res, err = settings_schema:transform(opts)
if not res then
  rspamd_logger.warnx(rspamd_config, 'plugin %s is misconfigured: %s', N, err)
  lua_util.disable_module(N, "config")
  return
end
opts = res

rule = dcc.configure(opts)

if rule then
  local id = rspamd_config:register_symbol({
    name = 'DCC_CHECK',
    callback = check_dcc,
    type = 'callback',
  })
  rspamd_config:register_symbol {
    type = 'virtual',
    parent = id,
    name = opts.symbol
  }
  rspamd_config:register_symbol {
    type = 'virtual',
    parent = id,
    name = opts.symbol_bulk
  }
  rspamd_config:register_symbol {
    type = 'virtual',
    parent = id,
    name = opts.symbol_fail
  }
  rspamd_config:set_metric_symbol({
    group = N,
    score = 1.0,
    description = 'Detected as bulk mail by DCC',
    one_shot = true,
    name = opts.symbol_bulk,
  })
  rspamd_config:set_metric_symbol({
    group = N,
    score = 2.0,
    description = 'Rejected by DCC',
    one_shot = true,
    name = opts.symbol,
  })
  rspamd_config:set_metric_symbol({
    group = N,
    score = 0.0,
    description = 'DCC failure',
    one_shot = true,
    name = opts.symbol_fail,
  })
else
  lua_util.disable_module(N, "config")
  rspamd_logger.infox(rspamd_config, 'DCC module not configured');
end
