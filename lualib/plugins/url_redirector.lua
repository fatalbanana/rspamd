--[[
Copyright (c) 2021, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local hash = require "rspamd_cryptobox_hash"
local lua_util = require "lua_util"
local lua_redis = require "lua_redis"
local rspamd_http = require "rspamd_http"
local rspamd_logger = require "rspamd_logger"
local rspamd_url = require "rspamd_url"

local M = {}
local N = 'url_redirector'

-- Some popular UA
local default_ua = {
  'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
  'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
  'Wget/1.9.1',
  'Mozilla/5.0 (Android; Linux armv7l; rv:9.0) Gecko/20111216 Firefox/9.0 Fennec/9.0',
  'Mozilla/5.0 (Windows NT 5.2; RW; rv:7.0a1) Gecko/20091211 SeaMonkey/9.23a1pre',
  'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko',
  'W3C-checklink/4.5 [4.160] libwww-perl/5.823',
  'Lynx/2.8.8dev.3 libwww-FM/2.14 SSL-MM/1.4.1',
}

local redis_params

local settings = {
  expire = 86400, -- 1 day by default
  timeout = 10, -- 10 seconds by default
  nested_limit = 5, -- How many redirects to follow
  --proxy = "http://example.com:3128", -- Send request through proxy
  key_prefix = 'rdr:', -- default hash name
  check_ssl = false, -- check ssl certificates
  max_urls = 5, -- how many urls to check
  max_size = 10 * 1024, -- maximum body to process
  user_agent = default_ua,
  redirector_symbol = nil, -- insert symbol if redirected url has been found
  redirectors_only = true, -- follow merely redirectors
  top_urls_key = 'rdr:top_urls', -- key for top urls
  top_urls_count = 200, -- how many top urls to save
  redirector_hosts_map = nil -- check only those redirectors
}

M.adjust_url = function(task, orig_url, redir_url)
  if type(redir_url) == 'string' then
    redir_url = rspamd_url.create(task:get_mempool(), redir_url)
  end

  if redir_url then
    orig_url:set_redirected(redir_url)
    task:inject_url(redir_url)
    if settings.redirector_symbol then
      task:insert_result(settings.redirector_symbol, 1.0,
          string.format('%s->%s', orig_url:get_host(), redir_url:get_host()))
    end
  else
    rspamd_logger.infox(task, 'bad url %s as redirection for %s', redir_url, orig_url)
  end
end

M.cache_url = function(task, orig_url, url, key, param)
  -- String representation
  local str_orig_url = tostring(orig_url)
  local str_url = tostring(url)

  if str_url ~= str_orig_url then
    -- Set redirected url
    M.adjust_url(task, orig_url, url)
  end

  local function redis_trim_cb(err, _)
    if err then
      rspamd_logger.errx(task, 'got error while getting top urls count: %s', err)
    else
      rspamd_logger.infox(task, 'trimmed url set to %s elements',
        settings.top_urls_count)
    end
  end

  -- Cleanup logic
  local function redis_card_cb(err, data)
    if err then
      rspamd_logger.errx(task, 'got error while getting top urls count: %s', err)
    else
      if data then
        if tonumber(data) > settings.top_urls_count * 2 then
          local ret = lua_redis.redis_make_request(task,
            redis_params, -- connect params
            key, -- hash key
            true, -- is write
            redis_trim_cb, --callback
            'ZREMRANGEBYRANK', -- command
            {settings.top_urls_key, '0',
              tostring(settings.top_urls_count + 1)} -- arguments
          )
          if not ret then
            rspamd_logger.errx(task, 'cannot trim top urls set')
          else
            rspamd_logger.infox(task, 'need to trim urls set from %s to %s elements',
              data,
              settings.top_urls_count)
            return
          end
        end
      end
    end
  end

  local function redis_set_cb(err, _)
    if err then
      rspamd_logger.errx(task, 'got error while setting redirect keys: %s', err)
    else
      local ret = lua_redis.redis_make_request(task,
        redis_params, -- connect params
        key, -- hash key
        false, -- is write
        redis_card_cb, --callback
        'ZCARD', -- command
        {settings.top_urls_key} -- arguments
      )
      if not ret then
        rspamd_logger.errx(task, 'cannot make redis request to cache results')
      end
    end
  end

  local ret,conn,_ = lua_redis.redis_make_request(task,
    redis_params, -- connect params
    key, -- hash key
    true, -- is write
    redis_set_cb, --callback
    'SETEX', -- command
    {key, tostring(settings.expire), str_url} -- arguments
  )

  if not ret then
    rspamd_logger.errx(task, 'cannot make redis request to cache results')
  else
    conn:add_cmd('ZINCRBY', {settings.top_urls_key, '1', str_url})
  end
end

local function resolve_url(task, orig_url, url, key, ntries)
  if ntries > settings.nested_limit then
    -- We cannot resolve more, stop
    rspamd_logger.debugm(N, task, 'cannot get more requests to resolve %s, stop on %s after %s attempts',
      orig_url, url, ntries)
    M.cache_url(task, orig_url, url, key)

    return
  end

  local function http_callback(err, code, _, headers)
    if err then
      rspamd_logger.infox(task, 'found redirect error from %s to %s, err message: %s',
        orig_url, url, err)
      M.cache_url(task, orig_url, url, key)
    else
      if code == 200 then
        if orig_url == url then
          rspamd_logger.infox(task, 'direct url %s, err code 200',
            url)
        else
          rspamd_logger.infox(task, 'found redirect from %s to %s, err code 200',
            orig_url, url)
        end

        M.cache_url(task, orig_url, url, key)

      elseif code == 301 or code == 302 then
        local loc = headers['location']
        local redir_url
        if loc then
          redir_url = rspamd_url.create(task:get_mempool(), loc)
        end
        rspamd_logger.debugm(N, task, 'found redirect from %s to %s, err code %s',
          orig_url, loc, code)

        if redir_url then
          if settings.redirectors_only then
            if settings.redirector_hosts_map:get_key(redir_url:get_host()) then
              M.resolve_cached(task, orig_url, redir_url, key, ntries + 1)
            else
              lua_util.debugm(N, task,
                "stop resolving redirects as %s is not a redirector", loc)
              M.cache_url(task, orig_url, redir_url, key)
            end
          else
            M.resolve_cached(task, orig_url, redir_url, key, ntries + 1)
          end
        else
          rspamd_logger.debugm(N, task, "no location, headers: %s", headers)
          M.cache_url(task, orig_url, url, key)
        end
      else
        rspamd_logger.debugm(N, task, 'found redirect error from %s to %s, err code: %s',
          orig_url, url, code)
        M.cache_url(task, orig_url, url, key)
      end
    end
  end

  local ua
  if type(settings.user_agent) == 'string' then
    ua = settings.user_agent
  else
    ua = settings.user_agent[math.random(#settings.user_agent)]
  end

  lua_util.debugm(N, task, 'select user agent %s', ua)

  rspamd_http.request{
    headers = {
      ['User-Agent'] = ua,
    },
    url = tostring(url),
    task = task,
    method = 'head',
    max_size = settings.max_size,
    timeout = settings.timeout,
    opaque_body = true,
    no_ssl_verify = not settings.check_ssl,
    callback = http_callback
  }
end

-- Resolve maybe cached url
-- Orig url is the original url object
-- url should be a new url object...
M.resolve_cached = function(task, orig_url, url, key, ntries, url_resolver)
  local function redis_get_cb(err, data)
    if not err then
      if type(data) == 'string' then
        if data ~= 'processing' then
          -- Got cached result
          rspamd_logger.debugm(N, task, 'found cached redirect from %s to %s',
            url, data)
          if data ~= tostring(orig_url) then
            M.adjust_url(task, orig_url, data)
          end
          return
        end
      end
    end
    local function redis_reserve_cb(nerr, ndata)
      if nerr then
        rspamd_logger.errx(task, 'got error while setting redirect keys: %s', nerr)
      elseif ndata == 'OK' then
        url_resolver(task, orig_url, url, key, ntries)
      end
    end

    if ntries == 1 then
      -- Reserve key in Redis that we are processing this redirection
      local ret = lua_redis.redis_make_request(task,
        redis_params, -- connect params
        key, -- hash key
        true, -- is write
        redis_reserve_cb, --callback
        'SET', -- command
        {key, 'processing', 'EX', tostring(settings.timeout * 2), 'NX'} -- arguments
      )
      if not ret then
        rspamd_logger.errx(task, 'Couldn\'t schedule SET')
      end
    else
      -- Just continue resolving
      url_resolver(task, orig_url, url, key, ntries)
    end

  end
  local ret = lua_redis.redis_make_request(task,
    redis_params, -- connect params
    key, -- hash key
    false, -- is write
    redis_get_cb, --callback
    'GET', -- command
    {key} -- arguments
  )
  if not ret then
    rspamd_logger.errx(task, 'cannot make redis request to check results')
  end
end

M.make_key = function(url)
  local url_str = url:get_raw()
  -- 32 base32 characters are roughly 20 bytes of data or 160 bits
  local key = settings.key_prefix .. hash.create(url_str):base32():sub(1, 32)
  return key
end

local function url_redirector_process_urls(task, sp_urls)
  for _,u in ipairs(sp_urls) do
    M.resolve_cached(task, u, u, M.make_key(u), 1, resolve_url)
  end
end

local function url_redirector_handler(task)
  local sp_urls = lua_util.extract_specific_urls({
    task = task,
    limit = settings.max_urls,
    filter = function(url)
      local host = url:get_host()
      if settings.redirector_hosts_map:get_key(host) then
        lua_util.debugm(N, task, 'check url %s', tostring(url))
        return true
      end
    end,
    no_cache = true,
  })

  if sp_urls then
    url_redirector_process_urls(task, sp_urls)
  end
end

M.configure_module = function()

  local opts = rspamd_config:get_all_opt('url_redirector')
  if not opts then
    return
  end
  settings = lua_util.override_defaults(settings, opts)
  redis_params = lua_redis.parse_redis_server('url_redirector', settings)

  if not redis_params then
    rspamd_logger.infox(rspamd_config, 'no servers are specified, disabling module')
    lua_util.disable_module(N, "redis")
    return
  end

  if settings.external_redirector then
    local ok, f = pcall(dofile, settings.external_redirector)
    if not ok then
      rspamd_logger.errx(rspamd_config,
          "couldn't load external redirector function: %s, disabling module", f)
      lua_util.disable_module(N, "config")
      return
    end
    if type(f) ~= 'function' then
      rspamd_logger.errx(rspamd_config,
          "external redirector script returned %s (wanted function), disabling module", type(f))
      lua_util.disable_module(N, "config")
      return
    end
    rspamd_logger.infox(rspamd_config, "using external redirector function from %1", settings.external_redirector)
    url_redirector_process_urls = f
  end

  if not settings.redirector_hosts_map then
    rspamd_logger.infox(rspamd_config, 'no redirector_hosts_map option is specified, disabling module')
    lua_util.disable_module(N, "config")
    return
  end

  local lua_maps = require "lua_maps"
  settings.redirector_hosts_map = lua_maps.map_add_from_ucl(settings.redirector_hosts_map,
      'set', 'Redirectors definitions')

  lua_redis.register_prefix(settings.key_prefix .. '[a-z0-9]{32}', N,
      'URL redirector hashes', {
          type = 'string',
      })

  if settings.top_urls_key then
    lua_redis.register_prefix(settings.top_urls_key, N,
        'URL redirector top urls', {
            type = 'zlist',
        })
  end

  local id = rspamd_config:register_symbol{
    name = 'URL_REDIRECTOR_CHECK',
    type = 'callback,prefilter',
    callback = url_redirector_handler,
  }

  if settings.redirector_symbol then
    rspamd_config:register_symbol{
      name = settings.redirector_symbol,
      type = 'virtual',
      parent = id,
      score = 0,
    }
  end
end

return M
