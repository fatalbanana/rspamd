--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>
Copyright (c) 2019, Denis Paavilainen <denpa@denpa.pro>

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

-- Detect remote OS via passive fingerprinting

local lua_util = require "lua_util"
local lua_redis = require "lua_redis"
local rspamd_logger = require "rspamd_logger"
local p0f = require("lua_scanners").filter('p0f').p0f
local T = require "lua_shape.core"
local PluginSchema = require "lua_shape.plugin_schema"

local N = 'p0f'

if confighelp then
  rspamd_config:add_example(nil, N,
      'Detect remote OS via passive fingerprinting',
      [[
  p0f {
    # Enable module
    enabled = true

    # Path to the unix socket that p0f listens on
    socket = '/var/run/p0f.sock';

    # Connection timeout
    timeout = 5s;

    # If defined, insert symbol with lookup results
    symbol = 'P0F';

    # Patterns to match against results returned by p0f
    # Symbol will be yielded on OS string, link type or distance matches
    patterns = {
      WINDOWS = '^Windows.*';
      DSL = '^DSL$';
      DISTANCE10 = '^distance:10$';
    }

    # Cache lifetime in seconds (default - 2 hours)
    expire = 7200;

    # Cache key prefix
    prefix = 'p0f';
  }
  ]])
  return
end

-- Settings schema for lua_shape validation
local settings_schema = T.table({
  enabled = T.boolean():optional():doc({ summary = "Enable the plugin" }),
  socket = T.string():optional():doc({ summary = "Path to the unix socket that p0f listens on" }),
  timeout = T.one_of({
    T.number({ min = 0 }),
    T.transform(T.string(), lua_util.parse_time_interval)
  }):optional():doc({ summary = "Connection timeout" }),
  symbol = T.string():optional():doc({ summary = "Symbol to insert with lookup results" }),
  symbol_fail = T.string():optional():doc({ summary = "Symbol for p0f failure" }),
  patterns = T.table({}, { open = true }):optional()
    :doc({ summary = "Patterns to match against p0f results (symbol name -> regex)" }),
  expire = T.integer({ min = 0 }):optional():doc({ summary = "Cache lifetime in seconds" }),
  prefix = T.string():optional():doc({ summary = "Cache key prefix" }),
  name = T.string():optional():doc({ summary = "Scanner name for logging" }),
  detection_category = T.string():optional():doc({ summary = "Detection category" }),
  message = T.string():optional():doc({ summary = "Message template for results" }),
  log_prefix = T.string():optional():doc({ summary = "Log prefix" }),
}):doc({ summary = "P0f plugin configuration" })

PluginSchema.register("plugins.p0f", settings_schema)

local rule

local function check_p0f(task)
  local ip = task:get_from_ip()

  if not (ip and ip:is_valid()) or ip:is_local() then
    return
  end

  p0f.check(task, ip, rule)
end

local opts = rspamd_config:get_all_opt(N)

if not opts then
  lua_util.disable_module(N, "config")
  return
end

-- Validate settings with lua_shape
local res, err = settings_schema:transform(opts)
if not res then
  rspamd_logger.warnx(rspamd_config, 'plugin %s is misconfigured: %s', N, err)
  lua_util.disable_module(N, "config")
  return
end
opts = res

rule = p0f.configure(opts)

if rule then
  rule.redis_params = lua_redis.parse_redis_server(N)

  lua_redis.register_prefix(rule.prefix .. '*', N,
      'P0f check cache', {
        type = 'string',
      })

  local id = rspamd_config:register_symbol({
    name = 'P0F_CHECK',
    type = 'prefilter',
    callback = check_p0f,
    priority = lua_util.symbols_priorities.medium,
    flags = 'empty,nostat',
    group = N,
    augmentations = { string.format("timeout=%f", rule.timeout or 0.0) },

  })

  if rule.symbol then
    rspamd_config:register_symbol({
      name = rule.symbol,
      parent = id,
      type = 'virtual',
      flags = 'empty',
      group = N
    })
  end

  for sym in pairs(rule.patterns) do
    lua_util.debugm(N, rspamd_config, 'registering: %1', {
      type = 'virtual',
      name = sym,
      parent = id,
      group = N
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = sym,
      parent = id,
      group = N
    })
  end
else
  lua_util.disable_module(N, 'config')
  rspamd_logger.infox(rspamd_config, 'p0f module not configured');
end
