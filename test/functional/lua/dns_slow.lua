local rspamd_logger = require "rspamd_logger"

-- DNS over TCP test with slow custom server that triggers partial writes
local function dns_tcp_slow_symbol(task)
  local function dns_tcp_slow_cb(_, to_resolve, results, err)
    rspamd_logger.errx(task, "DNS TCP SLOW: _=%1, to_resolve=%2, results=%3, err=%4",
                _, to_resolve, results, err)
    
    if err then
      task:insert_result('DNS_TCP_SLOW_ERROR', 1.0, err)
    else
      if results and #results > 0 then
        task:insert_result('DNS_TCP_SLOW', 1.0, string.format('%d records', #results))
      else
        task:insert_result('DNS_TCP_SLOW_EMPTY', 1.0)
      end
    end
  end
  
  local to_resolve = tostring(task:get_request_header('to-resolve'))
  
  task:get_resolver():resolve_txt({
    task = task,
    name = to_resolve,
    callback = dns_tcp_slow_cb,
  })
end

rspamd_config:register_symbol({
  name = 'SIMPLE_DNS_TCP_SLOW',
  score = 1.0,
  callback = dns_tcp_slow_symbol,
})
