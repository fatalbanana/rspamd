--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>
Copyright (c) 2016, Andrew Lewis <nerf@judo.za.org>

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

local rspamd_logger = require "rspamd_logger"
local rspamd_regexp = require "rspamd_regexp"
local lua_util = require "lua_util"
local T = require "lua_shape.core"
local PluginSchema = require "lua_shape.plugin_schema"
local N = "asn"

if confighelp then
  return
end

local settings = {
  provider_type = 'rspamd',
  provider_info = {
    ip4 = 'asn.rspamd.com',
    ip6 = 'asn6.rspamd.com',
  },
  symbol = 'ASN',
  check_local = false,
}

-- Settings schema for lua_shape validation
local settings_schema = T.table({
  provider_type = T.enum({ "rspamd", "external" }):optional():doc({ summary = "ASN provider type" }),
  provider_info = T.table({}, { open = true }):optional():doc({ summary = "Provider-specific configuration" }),
  symbol = T.string():optional():doc({ summary = "Symbol to insert for ASN info" }),
  check_local = T.boolean():optional():doc({ summary = "Check local IP addresses" }),
}):doc({ summary = "ASN plugin configuration" })

PluginSchema.register("plugins.asn", settings_schema)

local rspamd_re = rspamd_regexp.create_cached("[\\|\\s]")

local function asn_check(task)

  local function asn_set(asn, ipnet, country)
    local descr_t = {}
    local mempool = task:get_mempool()
    if asn then
      if tonumber(asn) ~= nil then
        mempool:set_variable("asn", asn)
        table.insert(descr_t, "asn:" .. asn)
      else
        rspamd_logger.errx(task, 'malformed ASN "%s" for ip %s', asn, task:get_from_ip())
      end
    end
    if ipnet then
      mempool:set_variable("ipnet", ipnet)
      table.insert(descr_t, "ipnet:" .. ipnet)
    end
    if country then
      mempool:set_variable("country", country)
      table.insert(descr_t, "country:" .. country)
    end
    if settings['symbol'] then
      task:insert_result(settings['symbol'], 0.0, table.concat(descr_t, ', '))
    end
  end

  local asn_check_func = {}
  asn_check_func.rspamd = function(ip)
    local dnsbl = settings['provider_info']['ip' .. ip:get_version()]
    local req_name = string.format("%s.%s",
        table.concat(ip:inversed_str_octets(), '.'), dnsbl)
    local function rspamd_dns_cb(_, _, results, dns_err, _, _, serv)
      if dns_err and (dns_err ~= 'requested record is not found' and dns_err ~= 'no records with this name') then
        rspamd_logger.errx(task, 'error querying dns "%s" on %s: %s',
            req_name, serv, dns_err)
        task:insert_result(settings['symbol_fail'], 0, string.format('%s:%s', req_name, dns_err))
        return
      end
      if not results or not results[1] then
        rspamd_logger.infox(task, 'no ASN information is available for the IP address "%s" on %s',
            req_name, serv)
        return
      end

      lua_util.debugm(N, task, 'got reply from %s when requesting %s: %s',
          serv, req_name, results[1])

      local parts = rspamd_re:split(results[1])
      -- "15169 | 8.8.8.0/24 | US | arin |" for 8.8.8.8
      asn_set(parts[1], parts[2], parts[3])
    end

    task:get_resolver():resolve_txt({
      task = task,
      name = req_name,
      callback = rspamd_dns_cb
    })
  end

  local ip = task:get_from_ip()
  if not (ip and ip:is_valid()) or
      (not settings.check_local and ip:is_local()) then
    return
  end

  asn_check_func[settings['provider_type']](ip)
end

-- Configuration options
local configure_asn_module = function()
  local opts = rspamd_config:get_all_opt('asn')
  if opts then
    settings = lua_util.override_defaults(settings, opts)

    -- Validate settings with lua_shape
    local res, err = settings_schema:transform(settings)
    if not res then
      rspamd_logger.warnx(rspamd_config, 'plugin %s is misconfigured: %s', N, err)
      return false
    end
    settings = res
  end

  local auth_and_local_conf = lua_util.config_check_local_or_authed(rspamd_config, N,
      false, true)
  settings.check_local = auth_and_local_conf[1]
  settings.check_authed = auth_and_local_conf[2]

  if settings['provider_type'] == 'rspamd' then
    if not settings['provider_info'] or not settings['provider_info']['ip4'] or
        not settings['provider_info']['ip6'] then
      rspamd_logger.errx(rspamd_config, "Missing required provider_info for rspamd")
      return false
    end
  else
    rspamd_logger.errx(rspamd_config, "Unknown provider_type: %s", settings['provider_type'])
    return false
  end

  if settings['symbol'] then
    settings['symbol_fail'] = settings['symbol'] .. '_FAIL'
  else
    settings['symbol_fail'] = 'ASN_FAIL'
  end

  return true
end

if configure_asn_module() then
  local id = rspamd_config:register_symbol({
    name = 'ASN_CHECK',
    type = 'prefilter',
    callback = asn_check,
    priority = lua_util.symbols_priorities.high,
    flags = 'empty,nostat',
    augmentations = { lua_util.dns_timeout_augmentation(rspamd_config) },
  })
  if settings['symbol'] then
    rspamd_config:register_symbol({
      name = settings['symbol'],
      parent = id,
      type = 'virtual',
      flags = 'empty,nostat',
      score = 0,
    })
  end
  rspamd_config:register_symbol {
    name = settings['symbol_fail'],
    parent = id,
    type = 'virtual',
    flags = 'empty,nostat',
    score = 0,
  }
else
  lua_util.disable_module(N, 'config')
end
