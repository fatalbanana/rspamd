--[[
Copyright (c) 2016, Andrew Lewis <nerf@judo.za.org>
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

local lua_util = require "lua_util"
local rspamd_logger = require "rspamd_logger"
local dkim_sign_tools = require "lua_dkim_tools"
local lua_redis = require "lua_redis"
local lua_mime = require "lua_mime"
local T = require "lua_shape.core"
local PluginSchema = require "lua_shape.plugin_schema"

if confighelp then
  return
end

local settings = {
  allow_envfrom_empty = true,
  allow_hdrfrom_mismatch = false,
  allow_hdrfrom_mismatch_local = false,
  allow_hdrfrom_mismatch_sign_networks = false,
  allow_hdrfrom_multiple = false,
  allow_username_mismatch = false,
  allow_pubkey_mismatch = true,
  sign_authenticated = true,
  allowed_ids = nil,
  forbidden_ids = nil,
  check_pubkey = false,
  domain = {},
  path = string.format('%s/%s/%s', rspamd_paths['DBDIR'], 'dkim', '$domain.$selector.key'),
  sign_local = true,
  selector = 'dkim',
  symbol = 'DKIM_SIGNED',
  try_fallback = true,
  use_domain = 'header',
  use_esld = true,
  use_redis = false,
  key_prefix = 'dkim_keys', -- default hash name
  use_milter_headers = false, -- use milter headers instead of `dkim_signature`
}

-- Settings schema for lua_shape validation
local settings_schema = T.table({
  allow_envfrom_empty = T.boolean():optional():doc({ summary = "Allow empty envelope from" }),
  allow_hdrfrom_mismatch = T.boolean():optional():doc({ summary = "Allow header from mismatch" }),
  allow_hdrfrom_mismatch_local = T.boolean():optional():doc({ summary = "Allow header from mismatch for local networks" }),
  allow_hdrfrom_mismatch_sign_networks = T.boolean():optional():doc({ summary = "Allow header from mismatch for signing networks" }),
  allow_hdrfrom_multiple = T.boolean():optional():doc({ summary = "Allow multiple From headers" }),
  allow_username_mismatch = T.boolean():optional():doc({ summary = "Allow username mismatch" }),
  allow_pubkey_mismatch = T.boolean():optional():doc({ summary = "Allow public key mismatch" }),
  sign_authenticated = T.boolean():optional():doc({ summary = "Sign authenticated messages" }),
  allowed_ids = T.array(T.string()):optional():doc({ summary = "Allowed settings IDs" }),
  forbidden_ids = T.array(T.string()):optional():doc({ summary = "Forbidden settings IDs" }),
  check_pubkey = T.boolean():optional():doc({ summary = "Check public key before signing" }),
  domain = T.table({}, { open = true }):optional():doc({ summary = "Domain-specific signing configuration" }),
  path = T.string():optional():doc({ summary = "Path template for signing keys" }),
  sign_local = T.boolean():optional():doc({ summary = "Sign local messages" }),
  selector = T.string():optional():doc({ summary = "DKIM selector for signing" }),
  symbol = T.string():optional():doc({ summary = "Symbol for signed messages" }),
  try_fallback = T.boolean():optional():doc({ summary = "Try fallback domain for signing" }),
  use_domain = T.enum({ "header", "envelope" }):optional():doc({ summary = "Domain source for signing" }),
  use_esld = T.boolean():optional():doc({ summary = "Use effective sender domain (ESLD)" }),
  use_redis = T.boolean():optional():doc({ summary = "Load keys from Redis" }),
  key_prefix = T.string():optional():doc({ summary = "Redis key prefix for DKIM keys" }),
  use_milter_headers = T.boolean():optional():doc({ summary = "Use milter headers instead of dkim_signature" }),
}):doc({ summary = "DKIM signing plugin configuration" })

PluginSchema.register("plugins.dkim_signing", settings_schema)

local N = 'dkim_signing'
local redis_params
local sign_func = rspamd_plugins.dkim.sign

local function insert_sign_results(task, ret, hdr, dkim_params)
  if settings.use_milter_headers then
    lua_mime.modify_headers(task, {
      add = {
        ['DKIM-Signature'] = { order = 1, value = hdr },
      }
    })
  end
  if ret then
    task:insert_result(settings.symbol, 1.0, string.format('%s:s=%s',
        dkim_params.domain, dkim_params.selector))
  end
end

local function do_sign(task, p)
  if settings.use_milter_headers then
    p.no_cache = true -- Disable caching in rspamd_mempool
  end
  if settings.check_pubkey then
    local resolve_name = p.selector .. "._domainkey." .. p.domain
    task:get_resolver():resolve_txt({
      task = task,
      name = resolve_name,
      callback = function(_, _, results, err)
        if not err and results and results[1] then
          p.pubkey = results[1]
          p.strict_pubkey_check = not settings.allow_pubkey_mismatch
        elseif not settings.allow_pubkey_mismatch then
          rspamd_logger.infox(task, 'public key for domain %s/%s is not found: %s, skip signing',
              p.domain, p.selector, err)
          return
        else
          rspamd_logger.infox(task, 'public key for domain %s/%s is not found: %s',
              p.domain, p.selector, err)
        end

        local sret, hdr = sign_func(task, p)
        insert_sign_results(task, sret, hdr, p)
      end,
      forced = true
    })
  else
    local sret, hdr = sign_func(task, p)
    insert_sign_results(task, sret, hdr, p)
  end
end

local function sign_error(task, msg)
  rspamd_logger.errx(task, 'signing failure: %s', msg)
end

local function dkim_signing_cb(task)
  local ret, selectors = dkim_sign_tools.prepare_dkim_signing(N, task, settings)

  if not ret or #selectors == 0 then
    return
  end
  if settings.use_redis then
    -- Use only redis stuff here
    dkim_sign_tools.sign_using_redis(N, task, settings, selectors, do_sign, sign_error)
    return
  end

  for _, k in ipairs(selectors) do
    if k.vault then
      dkim_sign_tools.sign_using_vault(N, task, settings, k, do_sign, sign_error)
    else
      -- templates
      if k.key then
        k.key = lua_util.template(k.key, {
          domain = k.domain,
          selector = k.selector
        })
        lua_util.debugm(N, task, 'using key "%s", use selector "%s" for domain "%s"',
            k.key, k.selector, k.domain)
      end

      do_sign(task, k)

    end
  end
end

local opts = rspamd_config:get_all_opt('dkim_signing')
if not opts then
  return
end

dkim_sign_tools.process_signing_settings(N, settings, opts)

-- Validate settings with lua_shape
local res, err = settings_schema:transform(settings)
if not res then
  rspamd_logger.errx(rspamd_config, 'invalid %s config: %s', N, err)
  lua_util.disable_module(N, "config")
  return
end
settings = res

if not dkim_sign_tools.validate_signing_settings(settings) then
  rspamd_logger.infox(rspamd_config, 'mandatory parameters missing, disable dkim signing')
  lua_util.disable_module(N, "config")
  return
end

if settings.use_redis then
  redis_params = lua_redis.parse_redis_server('dkim_signing')

  if not redis_params then
    rspamd_logger.errx(rspamd_config,
        'no servers are specified, but module is configured to load keys from redis, disable dkim signing')
    lua_util.disable_module(N, "redis")
    return
  end

  settings.redis_params = redis_params
end

local sym_reg_tbl = {
  name = settings['symbol'],
  callback = dkim_signing_cb,
  groups = { "policies", "dkim" },
  flags = 'ignore_passthrough',
  score = 0.0,
}

if type(settings.allowed_ids) == 'table' then
  sym_reg_tbl.allowed_ids = settings.allowed_ids
end
if type(settings.forbidden_ids) == 'table' then
  sym_reg_tbl.forbidden_ids = settings.forbidden_ids
end

rspamd_config:register_symbol(sym_reg_tbl)
-- Add dependency on DKIM checks
rspamd_config:register_dependency(settings['symbol'], 'DKIM_CHECK')
