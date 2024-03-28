#!/usr/bin/env lua
-- Tells Suricata to only execute this script if the
-- packet triggered an alert
function init (args)
    local needs = {}
    needs["type"] = "packet"
    needs["filter"] = "alerts"
    return needs
  end
  
  -- Setting up the log files to use
  function setup (args)
    -- The first log will be used to determine if the report
    -- was a success or a failure.
    filename = SCLogPath() .. "/" .. "abuseipdb_alert_reports.log"
    file = assert(io.open(filename, "a"))
    -- The second log is a custom log set up for debugging your alerts
    filename2 = SCLogPath() .. "/" .. "abuseipdb_custom_debug.log"
    file2 = assert(io.open(filename2, "a"))
    SCLogInfo("Report to AbuseIPDB " .. filename)
    count = 0
  end
  
  -- Function that reports to AbuseIPDB and logs
  -- the reports to the specified file
  function log(args)
  
    local https = require("ssl.https");
    local ltn12 = require("ltn12")
    local url = require("socket.url")
  
    -- Grab data from packet to use in post request
    local ipver, srcip, dstip, proto, sp, dp = SCPacketTuple()
    -- Grab timestamp
    local timestring = SCPacketTimeString()
    local class, prio = SCRuleClass()
    local surCategory = "15"
    -- Assigning AbuseIPDB category based on Suricata Rule classification
    if string.match(class, "web application") then
      file2:write("Message: " .. SCRuleMsg() .. " Class: " .. class .. " matched to category 21\n")
      surCategory = "21"
    elseif string.match(class, "user") or string.match(class, "administrator") then
      file2:write("Message: " .. SCRuleMsg() .. " Class: " .. class .. " matched to category 18\n")
      surCategory = "18"
    elseif string.match(class, "suspicious username") or string.match(class, "default username") then
      file2:write("Message: " .. SCRuleMsg() .. " Class: " .. class .. " matched to categories 18, 22\n")
      surCategory = "18,22"
    elseif (string.match(class, "rpc") or string.match(class, "Network scan") or string.match(class, "Information Leak")) then
      file2:write("Message: " .. SCRuleMsg() .. " Class: " .. class .. " matched to category 14\n")
      surCategory = "14"
    elseif string.match(class, "Denial of Service") then
      file2:write("Message: " .. SCRuleMsg() .. " Class: " .. class .. " matched to category 4\n")
      surCategory = "4"
    else
      file2:write("Message: " .. SCRuleMsg() .. " Class: " .. class .. " matched to category 15\n")
      surCategory = "15"
    end
  
    if string.match(SCRuleMsg(), "SQL INJECTION") then
      file2:write("Message: " .. SCRuleMsg() .. " Class: " .. class .. " category 16 added\n")
      surCategory = surCategory .. ",16"
    end
  
    -- Setting up the post request.
    comment = timestring .. " " .. srcip .. " Protocol: " .. proto .. " " .. SCRuleMsg()
    commentE = url.escape(comment)
    local path = "https://api.abuseipdb.com/api/v2/report?ip=" .. srcip .. "&comment=" .. commentE .. "&categories="
  
    local body  = {
      categories = "18,22",
      ["ip"] = srcip
    }
  
    local response_body = {}
    -- Set up the response request.
    local res, code, response_headers = https.request({
        url = path .. surCategory,
        method = "POST",
        headers =
        {
          ["Accept"] = "Application/json",
          ["Key"] = "c27d0ae45b8a4da7fec4d3aa1c730ce0ee8abd95be2fc4a7f2a018fe6500cc89f2a81f57ce19e4dc",
          ["Content-Length"] = #body,
        },
        protocol = "tlsv1",
        source = ltn12.source.string(tostring(body)),
        sink  = ltn12.sink.table(response_body)
      })
      if code == 200 then
        file:write ("\nReport " .. count .. " Success! " .. comment .. " " .. table.concat(response_body))
      else
        file:write ("\nReport " .. count .. " FAILED!" .. timestring .. " Error Code: " .. code .. " Category: " .. surCategory)
      end
      file:flush()
      file2:flush()
      count = count + 1
  end
  
  -- Cleans up, and closes the log files
  function deinit (args)
    SCLogInfo ("Reports Logged: " .. count);
    io.close(file)
    io.close(file2)
  end