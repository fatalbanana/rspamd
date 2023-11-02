--[[
Copyright (c) 2023, Vsevolod Stakhov <vsevolod@rspamd.com>

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
local rspamd_hash = require "rspamd_cryptobox_hash"
local rspamd_ip = require "rspamd_ip"
local rspamd_regexp = require "rspamd_regexp"
local ts = (require "tableshape").types

local re_disk_urls = rspamd_regexp.create_cached([[/^(?:drive\.google\.com$|yadi\.sk$|disk\.yandex\.)/]])
local re_short_path = rspamd_regexp.create_cached([[/^(?!(?:[a-z]+|[A-Z]+|[0-9]+)$)[a-zA-Z0-9]{3,11}$/]])

local fmt_urls = function(urls)
  for i = 1, #urls do
    local url = urls[i]
    urls[i] = rspamd_hash.create_specific('sha1', url:get_host():lower() .. '/' .. url:get_path())
  end
  return urls
end

local configure_ami_extractors = function(ex)

  ex.ami_shorturls = {
    get_value = function(task, args)
      local shorturls = lua_util.extract_specific_urls({
        task = task,
        limit = args[1] or 5,
        filter = function(url)
          return re_short_path:match(url:get_path())
        end,
      })
      if shorturls[1] then
        return fmt_urls(shorturls), 'string_list'
      end
    end,
    description = [[Hashes related to URLs with short paths]],
    args_schema = { ts.number:is_optional() },
  }

  ex.ami_diskurls = {
    get_value = function(task, args)
      local diskurls = lua_util.extract_specific_urls({
        task = task,
        limit = args[1] or 5,
        filter = function(url)
          return re_disk_urls:match(url:get_host())
        end,
      })
      if diskurls[1] then
        return fmt_urls(diskurls), 'string_list'
      end
    end,
    description = [[Hashes related to cloud storage URLs]],
    args_schema = { ts.number:is_optional() },
  }

  ex.ami_websubmission = {
    get_value = function(task, args)
      local ips = {}
      local count, limit = 0, args[1] or 3
      local from_ip = task:get_from_ip()

      local h = task:get_header('http-posting-client')
      if h then
        local ip = rspamd_ip.from_string(h)
        if ip and ip:is_valid() and ip ~= from_ip then
          ips[ip:to_string():inversed_str_octets()] = true
          count = count + 1
        end
      end

      h = task:get_header('x-php-script')
      if h then
        local for_s = h:match(' for (.+)')
        if for_s then
          local split_for = rspamd_str_split(for_s:gsub('%s', ''), ',')
          split_for[limit - count + 1] = nil
          for _, e in ipairs(split_for) do
            local ip = rspamd_ip.fromstring(e)
            if ip and ip:is_valid() and ip ~= from_ip then
              local ip_r = ip:inversed_str_octets()
              if not ips[ip_r] then
                ips[ip_r] = true
                count = count + 1
              end
            end
          end
        end
      end

      local ip_l = {}
      for k in pairs(ips) do
        table.insert(ip_l, k)
      end

      if ip_l[1] then
        return ip_l, 'string_list'
      end
    end,
    description = [[Reversed IPs related to web submissions]],
    args_schema = { ts.number:is_optional() },
  }

end

return configure_ami_extractors
