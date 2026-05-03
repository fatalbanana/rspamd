*** Settings ***
Suite Setup     Urlredirector Cache Setup
Suite Teardown  Urlredirector Cache Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/url_redirector_chain.conf
${CHAIN_MESSAGE}   ${RSPAMD_TESTDIR}/messages/chain_redirect.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS}        {symbols_enabled=[URL_REDIRECTOR_CHECK]}

*** Test Cases ***
CACHE HOP MARKERS
  [Documentation]  Test that cache entries have correct hop markers
  ...              - ^hop: for intermediate hops that should be continued
  ...              - ^nested: for hops where limit was exceeded
  ...              - no marker for terminal URLs
  Scan File  ${CHAIN_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

PER-ADJACENT-PAIR CACHE LAYOUT
  [Documentation]  Test PR 6014 cache layout: one Redis entry per adjacent URL pair
  ...              hash(prev_url) -> next_url (with optional marker prefix)
  Scan File  ${CHAIN_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

CACHE WALK WITH MARKERS
  [Documentation]  Test cache walk behavior: reader follows ^hop: markers until terminal
  ...              When hitting ^nested:, starts fresh HTTP walk with full budget
  Scan File  ${CHAIN_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

SELF-HEALING CACHE
  [Documentation]  Test self-healing: when ^nested: gets extended, marker is overwritten with ^hop:
  Scan File  ${CHAIN_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello
  # Second scan should see healed cache
  Scan File  ${CHAIN_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

CYCLE DETECTION IN CACHE WALK
  [Documentation]  Test cycle protection: per-walk seen-set keyed by URL string
  Scan File  ${CHAIN_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

REDIS TIMEOUT APPLIED
  [Documentation]  Test that redis_timeout setting is applied to Redis calls
  Scan File  ${CHAIN_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

TOP_URLS ZINCRBY CANONICAL
  [Documentation]  Test that ZINCRBY on top_urls uses canonical URL string (no markers)
  Scan File  ${CHAIN_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

RESERVATION LOCK TTL
  [Documentation]  Test that reservation lock on hash(orig) has correct TTL = settings.timeout
  Scan File  ${CHAIN_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

*** Keywords ***
Urlredirector Cache Setup
  Run Dummy Http
  Rspamd Redis Setup

Urlredirector Cache Teardown
  Rspamd Redis Teardown
  Dummy Http Teardown
  Terminate All Processes    kill=True
