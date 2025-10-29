local rspamd_dns = require "rspamd_dns"
local logger = require "rspamd_logger"

local function dns_sync_symbol(task)
  local to_resolve = tostring(task:get_request_header('to-resolve'))
  local is_ok, results = rspamd_dns.request({
    task = task,
    type = 'a',
    name = to_resolve ,
  })

  logger.errx(task, "is_ok=%1, results=%2, results[1]=%3", is_ok, results, results[1])

  if not is_ok then
    task:insert_result('DNS_SYNC_ERROR', 1.0, results)
  else
    task:insert_result('DNS_SYNC', 1.0, tostring(results[1]))
  end
end

rspamd_config:register_symbol({
  name = 'SIMPLE_DNS_SYNC',
  score = 1.0,
  callback = dns_sync_symbol,
  no_squeeze = true,
  flags = 'coro',
})


-- Async request
local function dns_symbol(task)
  local function dns_cb(_, to_resolve, results, err)
    logger.errx(task, "_=%1, to_resolve=%2, results=%3, err%4", _, to_resolve, results, err)
    if err then
      task:insert_result('DNS_ERROR', 1.0, err)
    else
      task:insert_result('DNS', 1.0, tostring(results[1]))
    end
  end
  local to_resolve = tostring(task:get_request_header('to-resolve'))

  task:get_resolver():resolve_a({
    task = task,
    name = to_resolve,
    callback = dns_cb
  })
end

rspamd_config:register_symbol({
  name = 'SIMPLE_DNS',
  score = 1.0,
  callback = dns_symbol,
})


-- DNS over TCP test with large TXT record
-- This test exercises DNS over TCP which may trigger for large responses
-- The fix in contrib/librdns/resolver.c addressed a bug in partial write handling
-- where the code incorrectly calculated if a packet was fully written:
--   Old: ntohs(oc->next_write_size) < oc->cur_write
--   Fixed: ntohs(oc->next_write_size) + sizeof(oc->next_write_size) <= oc->cur_write
-- The bug could cause premature freeing of output buffers during partial writes.
-- While hard to reproduce reliably (requires kernel to partially write), this test
-- uses large TXT records which are more likely to trigger TCP and stress the code path.
local function dns_tcp_symbol(task)
  local completed = 0
  local total = 0
  local errors = {}
  local success_count = 0

  local function dns_tcp_cb(_, to_resolve, results, err)
    completed = completed + 1
    logger.errx(task, "DNS TCP: _=%1, to_resolve=%2, results=%3, err=%4, completed=%5/%6",
                _, to_resolve, results, err, completed, total)

    if err then
      table.insert(errors, string.format('%s: %s', to_resolve, err))
    else
      if results and #results > 0 then
        success_count = success_count + 1
      end
    end

    -- Only insert result when all queries complete
    if completed == total then
      if #errors > 0 then
        task:insert_result('DNS_TCP_ERROR', 1.0, errors)
      elseif success_count > 0 then
        task:insert_result('DNS_TCP', 1.0, string.format('%d/%d records', success_count, total))
      else
        task:insert_result('DNS_TCP_EMPTY', 1.0)
      end
    end
  end

  local to_resolve = tostring(task:get_request_header('to-resolve'))

  -- Send multiple concurrent requests to increase chance of partial writes
  -- and stress test the TCP write path
  local domains = {to_resolve}

  -- If resolving github.com, also try other domains with large TXT records
  if to_resolve == 'github.com' then
    -- Add more queries to stress the TCP connection
    table.insert(domains, 'google.com')
    table.insert(domains, 'microsoft.com')
  end

  total = #domains

  for _, domain in ipairs(domains) do
    task:get_resolver():resolve_txt({
      task = task,
      name = domain,
      callback = dns_tcp_cb
    })
  end
end

rspamd_config:register_symbol({
  name = 'SIMPLE_DNS_TCP',
  score = 1.0,
  callback = dns_tcp_symbol,
})


-- DNS over TCP test with slow custom server that triggers partial writes
local function dns_tcp_slow_symbol(task)
  local function dns_tcp_slow_cb(_, to_resolve, results, err)
    logger.errx(task, "DNS TCP SLOW: _=%1, to_resolve=%2, results=%3, err=%4",
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

  -- Force TCP by using custom nameserver on port 15353 (TCP only, no UDP)
  -- The resolver will need to use TCP since our server only listens on TCP
  task:get_resolver():resolve_txt({
    task = task,
    name = to_resolve,
    callback = dns_tcp_slow_cb,
    server = '127.0.0.1:15353',  -- Custom DNS server
  })
end

rspamd_config:register_symbol({
  name = 'SIMPLE_DNS_TCP_SLOW',
  score = 1.0,
  callback = dns_tcp_slow_symbol,
})
