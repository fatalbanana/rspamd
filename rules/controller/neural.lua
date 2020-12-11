--[[
Copyright (c) 2020, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local neural_common = require "plugins/neural"
local rspamd_logger = require "rspamd_logger"
local ts = require("tableshape").types
local ucl = require "ucl"

-- Controller neural plugin

local learn_request_schema = ts.shape{
  ham_vec = ts.array_of(ts.array_of(ts.number)),
  rule = ts.string:is_optional(),
  spam_vec = ts.array_of(ts.array_of(ts.number)),
}

local function handle_learn(task, conn)
  task:process_message()
  -- Payload is JSON disguised as e-Mail body
  local parser = ucl.parser()
  local req_params, err = parser:parse_string(task:get_rawbody())
  if err then
    conn:send_error(400, err)
    return
  end

  local _
  _, err = learn_request_schema:transform(req_params)
  if err then
    conn:send_error(400, err)
    return
  end

  local rule_name = req_params.rule or 'default'
  local rule = neural_common.settings[rule_name]
  local set = neural_common.get_rule_settings(task, rule_name)
  local version = (set.ann.version or 0) + 1

  neural_common.spawn_train{
    ev_base = task:get_ev_base(),
    ann_key = neural_common.new_ann_key(rule, set, version),
    set = set,
    rule = rule,
    ham_vec = req_params.ham_vec,
    spam_vec = req_params.spam_vec,
    settings = neural_common.settings,
    plugin_ver = neural_common.plugin_ver,
  }

  conn:send_string('{"success" : true}')
end

return {
  learn = {
    handler = handle_learn,
    enable = true,
    need_task = true,
  },
}
