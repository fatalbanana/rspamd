*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Systemd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}                         ${RSPAMD_TESTDIR}/configs/trivial.conf
${RSPAMD_SCOPE}                   Suite

*** Test Cases ***
EMPTY TEST
  Pass Execution  No worries

*** Keywords ***
Systemd Teardown
  Rspamd Teardown
  ${config} =  Get File  ${EXECDIR}/robot-save/rspamd.configdump.last
  Log To Console  WTF ${config}
  ${log} =  Get File  ${EXECDIR}/robot-save/rspamd.stderr.last
  Should Match Regexp  ${log}  ^[0-9]{4}-[0-9]{2}-[0-9]{2} #[0-9]+(main) <[0-9a-f]+>; main; main: rspamd 0-9]+\.[0-9]+\.[0-9]+ is loading configuration, build id: release\n
