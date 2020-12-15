local lua_settings = require "lua_settings"
local neural_common = require "plugins/neural"
local ucl = require "ucl"

rspamd_config:register_symbol({
  name = 'SPAM_SYMBOL',
  score = 5.0,
  callback = function()
    return true, 'Fires always'
  end
})

rspamd_config:register_symbol({
  name = 'HAM_SYMBOL',
  score = -3.0,
  callback = function()
    return true, 'Fires always'
  end
})

rspamd_config:register_symbol({
  name = 'NEUTRAL_SYMBOL',
  score = 1.0,
  flags = 'explicit_disable',
  callback = function()
    return true, 'Fires always'
  end
})

rspamd_config.NN_VECTOR = {
  callback = function(task)
    local function tohex(str)
      return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
      end))
    end
    --[[
    local res = neural_common.result_to_vector(task, {symbols = lua_settings.all_symbols()})
    return true, 1.0, tohex(ucl.to_format(res, 'msgpack'))
    --]]
    local logger = require 'rspamd_logger'
    logger.infox(task, 'CACHE ACTUAL GET neural_vec_mpack: <<%1>>', task:cache_get('neural_vec_mpack'))
    return true, 1.0, tohex(task:cache_get('neural_vec_mpack') or '')
  end,
  type = 'postfilter',
  flags = 'no_stat,explicit_disable',
  priority = 10,
}

rspamd_config.NN_VECTOR_ALT = {
  callback = function(task)
    local function tohex(str)
      return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
      end))
    end
    --[[
    local res = neural_common.result_to_vector(task, {symbols = lua_settings.all_symbols()})
    return true, 1.0, tohex(ucl.to_format(res, 'msgpack'))
    --]]
    local logger = require 'rspamd_logger'
    logger.infox(task, 'CACHE ACTUAL ALT GET neural_vec_mpack: <<%1>>', task:cache_get('neural_vec_mpack'))
    return true, 1.0, tohex(task:cache_get('neural_vec_mpack') or '')
  end,
  type = 'postfilter',
  flags = 'no_stat,explicit_disable',
  priority = 1,
}

rspamd_config.NN_WTF = {
  callback = function(task)
    local function tohex(str)
      return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
      end))
    end
    local logger = require 'rspamd_logger'
    logger.infox(task, 'CACHE WTF GET neural_vec_mpack: <<%1>>', task:cache_get('neural_vec_mpack'))
  end,
  type = 'idempotent',
  flags = 'no_stat,explicit_disable',
}


dofile(rspamd_env.INSTALLROOT .. "/share/rspamd/rules/controller/init.lua")
