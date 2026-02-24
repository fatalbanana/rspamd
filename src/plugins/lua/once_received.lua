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

-- 0 or 1 received: = spam
local rspamd_logger = require "rspamd_logger"
local lua_util = require "lua_util"
local fun = require "fun"
local T = require "lua_shape.core"
local PluginSchema = require "lua_shape.plugin_schema"
local N = 'once_received'

-- Default settings
local settings = {
  symbol = 'ONCE_RECEIVED',
  symbol_mx = 'DIRECT_TO_MX',
  symbol_strict = nil,
  bad_hosts = {},
  good_hosts = {},
  whitelist = nil,
  check_local = false,
  check_authed = false,
}

-- Settings schema for lua_shape validation
local settings_schema = T.table({
  symbol = T.string():optional():doc({ summary = "Main symbol for single received header" }),
  symbol_mx = T.string():optional():doc({ summary = "Symbol for direct-to-MX messages" }),
  symbol_strict = T.string():optional():doc({ summary = "Symbol for strict checks" }),
  bad_host = T.one_of({
    T.string(),
    T.array(T.string())
  }):optional():doc({ summary = "Hostname pattern(s) that trigger strict symbol" }),
  good_host = T.one_of({
    T.string(),
    T.array(T.string())
  }):optional():doc({ summary = "Hostname pattern(s) to exclude from checks" }),
  whitelist = T.string():optional():doc({ summary = "Path to IP whitelist map" }),
  check_local = T.boolean():optional():doc({ summary = "Check messages from local networks" }),
  check_authed = T.boolean():optional():doc({ summary = "Check messages from authenticated users" }),
}):doc({ summary = "Once received plugin configuration" })

PluginSchema.register("plugins.once_received", settings_schema)

local whitelist

local function check_quantity_received (task)
  local recvh = task:get_received_headers()

  local nreceived = fun.reduce(function(acc, _)
    return acc + 1
  end, 0, fun.filter(function(h)
    return not h['flags']['artificial']
  end, recvh))

  local task_ip = task:get_ip()

  if ((not settings.check_authed and task:get_user()) or
      (not settings.check_local and task_ip and task_ip:is_local())) then
    rspamd_logger.infox(task, 'Skipping once_received for authenticated user or local network')
    return
  end
  if whitelist and task_ip and whitelist:get_key(task_ip) then
    rspamd_logger.infox(task, 'whitelisted mail from %s',
        task_ip:to_string())
    return
  end

  local hn = task:get_hostname()
  -- Here we don't care about received
  if not hn then
    if nreceived <= 1 then
      task:insert_result(settings.symbol, 1)
      -- Avoid strict symbol inserting as the remaining symbols have already
      -- quote a significant weight, so a message could be rejected by just
      -- this property.
      --task:insert_result(settings.symbol_strict, 1)
      -- Check for MUAs
      local ua = task:get_header('User-Agent')
      local xm = task:get_header('X-Mailer')
      if (ua or xm) then
        task:insert_result(settings.symbol_mx, 1, (ua or xm))
      end
    end
    return
  else
    if settings.good_hosts then
      for _, gh in ipairs(settings.good_hosts) do
        if string.find(hn, gh) then
          return
        end
      end
    end

    if nreceived <= 1 then
      task:insert_result(settings.symbol, 1)
      for _, h in ipairs(settings.bad_hosts) do
        if string.find(hn, h) then
          task:insert_result(settings.symbol_strict, 1, h)
          return
        end
      end
    end
  end

  if nreceived <= 1 then
    local ret = true
    local r = recvh[1]

    if not r then
      return
    end

    if r['real_hostname'] then
      local rhn = string.lower(r['real_hostname'])
      -- Check for good hostname
      if rhn and settings.good_hosts then
        for _, gh in ipairs(settings.good_hosts) do
          if string.find(rhn, gh) then
            ret = false
            break
          end
        end
      end
    end

    if ret then
      -- Strict checks
      if settings.symbol_strict then
        -- Unresolved host
        task:insert_result(settings.symbol, 1)

        if not hn then
          return
        end
        for _, h in ipairs(settings.bad_hosts) do
          if string.find(hn, h) then
            task:insert_result(settings.symbol_strict, 1, h)
            return
          end
        end
      else
        task:insert_result(settings.symbol, 1)
      end
    end
  end
end

-- Configuration
local opts = rspamd_config:get_all_opt(N)
if opts then
  -- Normalize bad_host and good_host from single string to array
  if opts['bad_host'] then
    if type(opts['bad_host']) == 'string' then
      opts['bad_host'] = { opts['bad_host'] }
    end
  end
  if opts['good_host'] then
    if type(opts['good_host']) == 'string' then
      opts['good_host'] = { opts['good_host'] }
    end
  end

  settings = lua_util.override_defaults(settings, opts)

  -- Validate settings with lua_shape
  local res, err = settings_schema:transform(settings)
  if not res then
    rspamd_logger.warnx(rspamd_config, 'plugin %s is misconfigured: %s', N, err)
    lua_util.disable_module(N, "config")
    return
  end
  settings = res

  -- Convert bad_host/good_host array fields to settings.bad_hosts/good_hosts
  if settings.bad_host then
    settings.bad_hosts = settings.bad_host
    settings.bad_host = nil
  end
  if settings.good_host then
    settings.good_hosts = settings.good_host
    settings.good_host = nil
  end

  local auth_and_local_conf = lua_util.config_check_local_or_authed(rspamd_config, N,
      settings.check_local, settings.check_authed)
  settings.check_local = auth_and_local_conf[1]
  settings.check_authed = auth_and_local_conf[2]

  if settings['whitelist'] then
    local lua_maps = require "lua_maps"
    whitelist = lua_maps.map_add('once_received', 'whitelist', 'radix',
        'once received whitelist')
  end

  local id = rspamd_config:register_symbol({
    name = settings.symbol,
    callback = check_quantity_received,
  })

  if settings.symbol_strict then
    rspamd_config:register_symbol({
      name = settings.symbol_strict,
      type = 'virtual',
      parent = id
    })
  end

  rspamd_config:register_symbol({
    name = settings.symbol_mx,
    type = 'virtual',
    parent = id
  })
end
