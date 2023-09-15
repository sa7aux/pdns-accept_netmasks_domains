local cjson = require "cjson"
local cjson2 = cjson.new()
local cjson_safe = require "cjson.safe"
local ccjson = require("cjson.safe").new()
local cjsonutil = require "cjson.util"

pdnslog("pdns-recursor Lua script starting!", pdns.loglevels.all)

local nMask = newNMG()
local domainsSuffixs = newDS()

local PATH_ETC = '/etc/powerdns'
local CONFIG = cjsonutil.file_load('/etc/powerdns/config.json')

local function log_dq(dq, message)
    pdnslog(cjson.encode({
        message=message,
        qname=dq.qname:toString(),
        qtype=dq.qtype,
        rcode=dq.rcode,
        isTcp=dq.isTcp,
        remoteaddr=dq.remoteaddr:toString(),
        localaddr=dq.localaddr:toString(),
        variable=dq.variable,
        followupFunction=dq.followupFunction,
        followCNAMERecords=dq.followCNAMERecords,
        getFakeAAAARecords=dq.getFakeAAAARecords,
        getFakePTRRecords=dq.getFakePTRRecords,
        udpQueryResponse=dq.udpQueryResponse,
    }))
end

t = cjson.decode(CONFIG)

for _, dict in ipairs(t['netmasks']) do
  nMask:addMask(dict)
--  print(dict)
end

for _, dict in ipairs(t['domainsSuffixs']) do
  domainsSuffixs:add(dict)
--  print(dict)
end

function preresolve(dq)
--  log_dq(dq, 'dns host zone')
  if domainsSuffixs:check(dq.qname) then
    pdnslog("Accept query")
    dq.appliedPolicy.policyKind = pdns.policykinds.NoAction
    dq.variable = true
    return false
  else
--    pdnslog("dopping query")
    if not nMask:match(dq.remoteaddr) then
      pdnslog("dopping query")
      dq.appliedPolicy.policyKind = pdns.policykinds.Drop
      return true 
    else 
	pdnslog("Accept query")
        dq.appliedPolicy.policyKind = pdns.policykinds.NoAction
      dq.variable = true
      return false      
    end
  end
end
