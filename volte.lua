-- volte.lua
-- By jeff.chen.xun@ericsson.com
-- Will check every SIP message, see if it's contain the desire calling or called party. Then dump all message for this stream to a file.
do

	-- put the passed-in args into a table
	local args = {...}
	-- print them out
	local subscriberNumber = args[1]
	--print("Subscriber Number:"..subscriberNumber)
	-- create a table to hold the dumper objects/file handles
	local dumpers = nil

	print("Starting volte.lua script.")

	-- sub-function: creat sub folder for it.
	function createDir (dirname)
		-- this will print out an error if the directory already exists, but that's fine
		os.execute("md " .. dirname)
	end
	
	local dir = "by_subscriber"
	createDir(dir)
	
	function table.val_to_str ( v )
	  if "string" == type( v ) then
		v = string.gsub( v, "\n", "\\n" )
		if string.match( string.gsub(v,"[^'\"]",""), '^"+$' ) then
		  return "'" .. v .. "'"
		end
		return '"' .. string.gsub(v,'"', '\\"' ) .. '"'
	  else
		return "table" == type( v ) and table.tostring( v ) or
		  tostring( v )
	  end
	end

	function table.key_to_str ( k )
	  if "string" == type( k ) and string.match( k, "^[_%a][_%a%d]*$" ) then
		return k
	  else
		return "[" .. table.val_to_str( k ) .. "]"
	  end
	end

	function table.tostring( tbl )
	  local result, done = {}, {}
	  for k, v in ipairs( tbl ) do
		table.insert( result, table.val_to_str( v ) )
		done[ k ] = true
	  end
	  for k, v in pairs( tbl ) do
		if not done[ k ] then
		  table.insert( result,
			table.key_to_str( k ) .. "=" .. table.val_to_str( v ) )
		end
	  end
	  return "{" .. table.concat( result, "," ) .. "}"
	end
	
	-- sub-function: search string.
	function searchStr(content, str)
		local i = nil
		local result = nil
		local hexstr = ""
		
		for i=1,string.len(str) do
			hexstr = hexstr..string.format("%02X",string.byte(str,i))
		end
		--print("String: "..hexstr)
		result = string.find(content,hexstr)
		return result
	end
	
	--sub-function: conver hexstr to str
	function hexstr2str(content)
		local number
		local dstStr=""
		--print("Content 1: "..content.." Len:"..string.len(content))
		for i=1,string.len(content),2 do
			--print("Content: "..string.sub(content,i,i)..string.sub(content,i+1,i+1))
			dstStr = dstStr..string.char(tonumber(string.sub(content,i,i),16)*16+tonumber(string.sub(content,i+1,i+1),16))
			--print("content after:"..dstStr)
		end
		return dstStr
	end
	
	-- sub-function: search SIP/SDP IP
	function searchRtpIpInfo(content)
		local rtpIp = nil
		local rtpPort = nil
		local offset = 0
		
		--print("Search rtp ip")
		offset = searchStr(content, "c=IN IP6")
		if offset~=nil then
			local substr = string.sub(content, offset, string.len(content))
			--print("Search ending flag")
			local endFlag = searchStr(substr, "\r\n")
			local cinStr = string.sub(substr,1, endFlag-1)
			--print("RTP IP:"..cinStr)
			local ipstartFlag = searchStr(cinStr," ")
			local tempStr = string.sub(cinStr,ipstartFlag+2,string.len(cinStr))
			--print("tempStr:"..tempStr)
			ipstartFlag = searchStr(tempStr," ")
			local ipStr = string.sub(tempStr, ipstartFlag+2, string.len(tempStr))
			--print("ipStr:"..ipStr)
			rtpIp = hexstr2str(ipStr)
		end
		return rtpIp
	end

	-- sub-function: search SIP/SDP IP Port
	function searchRtpPortInfo(content)

		local rtpPort = nil
		local offset = 0
		
		--print("Search rtp port")
		--print(content)
		offset = searchStr(content, "m=audio ")
		if offset~=nil then
			local substr = string.sub(content, offset+16, string.len(content))
			--print("Search ending flag from"..substr)
			local endFlag = searchStr(substr, " ")
			local cinStr = string.sub(substr,1, endFlag-1)
			--print("RTP Port1:"..cinStr)
			rtpPort = hexstr2str(cinStr)
			--print("RTP Port2:"..cinStr)
		end
		return rtpPort
	end
	
	-- Remove duplicates from a table array (doesn't currently work
	-- Count the number of times a value occurs in a table 
	function table_count(tt, item)
	  local count
	  count = 0
	  for ii,xx in pairs(tt) do
		--print("Searching Item:"..table.tostring(item).." "..table.tostring(xx))
		if table.tostring(item) == table.tostring(xx) then count = count + 1 end
	  end
	  return count
	end
	
	-- on key-value tables)
	function table_unique(tt)
	  local newtable
	  newtable = {}
	  for ii,xx in ipairs(tt) do
		--print("Now Searching :"..table.tostring(xx))
		if(table_count(newtable, xx) == 0) then
		  newtable[#newtable+1] = xx
		end
		--print("New table current:"..table.tostring(newtable))
	  end
	  return newtable
	end

	-- create a table to hold the 5 key parameters
	local udpstreamIdentifier = {}
	
	-- create a table to hold the call ID
	local callId = {}
	
	-- create a listener tap for ipv6.
	local tap = Listener.new("ipv6")

	-- we will be called once for every IPV6 Header.
	function tap.packet(pinfo,tvb)
		--print("packet called")
		local srcadd = pinfo.src
		local dstadd = pinfo.dst
		local srcport = pinfo.src_port
		local dstport = pinfo.dst_port
		local frame = pinfo.number
		local udpflag = false
		local udpoffsest = 0
		local udpcontent = nil
		
		-- Get a table of fields
		local fields = { all_field_infos() }
		
		-- Print the name of every field
		for i, finfo in pairs(fields) do
			--print("name: ", finfo.name)
			--print("length: ", finfo.len)
			if finfo.name == "ipv6.fraghdr" then
				--print("ipv6.fraghdr")
				--print(tostring(finfo.value)..", "..tostring(finfo.offset))
				--udpportstr = tvb:range(finfo.offset+8,4)
				--print(tostring(udpportstr))
				srcport = tvb:range(finfo.offset+8,2):uint()
				dstport = tvb:range(finfo.offset+8+2,2):uint()
				udpflag = true
				udpoffsest = finfo.offset+8
				udpcontent = tostring(finfo.value)
			elseif finfo.name == "udp" then
				srcport = finfo.value:get_index(0)*256+finfo.value:get_index(1)
				dstport = finfo.value:get_index(2)*256+finfo.value:get_index(3)
				udpflag = true
				udpoffsest = finfo.offset
				udpcontent = tostring(finfo.value)
			end
		end
		
		if udpflag == true then
			--It's a udp message
			--Check if need dump
			--if table_count(udpstreamIdentifier, )
			local udpRecord = {}
			if srcadd > dstadd then
				udpRecord={packetType="sip", srcIpAddr = srcadd, srcIpPort = srcport, dstIpAddr = dstadd, dstIpPort = dstport}
			else
				udpRecord={packetType="sip", srcIpAddr = dstadd, srcIpPort = dstport, dstIpAddr = srcadd, dstIpPort = srcport}
			end
			
			if table_count(udpstreamIdentifier, udpRecord) > 0 then
				--Need dump this packet
				--print("Frame: "..frame.." ".."This packet should be dump *1")
				if dumpers == nil then
					dumpers = Dumper.new_for_current(dir.."/".."result.pcap")
				else
					dumpers:dump_current()
				end
			else				
				if searchStr(udpcontent,"sip")~=nil then
					if searchStr(udpcontent,"INVITE sip:")~=nil then
						--print(tostring(frame).."Invite message found")
						if searchStr(udpcontent,"SIP/2.0")~=nil then
							if searchStr(udpcontent,subscriberNumber)~=nil then
								local rtpIpAddr=""
								local rtpPortNum=0
								local rtpLink={}
								local sipLink={}
								--1. Add to call ID table
								--print("Subscriber found")
								--print(tostring(frame).." Source IP:"..tostring(srcadd).." Source PORT:"..tostring(srcport).." Dest IP:"..tostring(dstadd).." Dest PORT:"..tostring(dstport))
								if srcadd > dstadd then
									sipLink={packetType="sip", srcIpAddr = srcadd, srcIpPort = srcport, dstIpAddr = dstadd, dstIpPort = dstport}
								else
									sipLink={packetType="sip", srcIpAddr = dstadd, srcIpPort = dstport, dstIpAddr = srcadd, dstIpPort = srcport}
								end
								table.insert(udpstreamIdentifier, sipLink)
								if searchRtpIpInfo(udpcontent) ~= nil then
									--print("RTP IP: "..searchRtpIpInfo(udpcontent))
									rtpIpAddr = searchRtpIpInfo(udpcontent)
									if searchRtpPortInfo(udpcontent) ~= nil then
										--print("RTP Port: "..searchRtpPortInfo(udpcontent))
										rtpPortNum = searchRtpPortInfo(udpcontent)
										rtpLink={packetType="rtp", srcIpAddr = rtpIpAddr, srcIpPort = rtpPortNum}
										table.insert(udpstreamIdentifier, rtpLink)
									end
								end
								--Remove Duplicate Record
								--print("Frame: "..frame.." ".."Before: "..table.tostring(udpstreamIdentifier))
								udpstreamIdentifier = table_unique(udpstreamIdentifier)
								--print("Frame: "..frame.." ".."After: "..table.tostring(table_unique(udpstreamIdentifier)))
								
								--Need dump this packet
								--print("Frame: "..frame.." ".."This packet should be dump *2")
								if dumpers == nil then
									dumpers = Dumper.new_for_current(dir.."/".."result.pcap")
								else
									dumpers:dump_current()
								end
								--Push all ip and port information into table
								--print("SIP Link:".." "..tostring(sipLink.srcIpAddr).." "..tostring(sipLink.srcIpPort).." "..tostring(sipLink.dstIpAddr).." "..tostring(sipLink.dstIpPort))
								--print("RTP Link:".." "..tostring(rtpLink.srcIpAddr).." "..tostring(rtpLink.srcIpPort))
							end
						end
					end
				end
			end
		end
	end

	-- a listener tap's draw function is called every few seconds in the GUI
	-- and at end of file (once) in tshark
	function tap.draw()
		print("draw called")
		dumpers:flush()
	end

	-- a listener tap's reset function is called at the end of a live capture run,
	-- when a file is opened, or closed.  Tshark never appears to call it.
	function tap.reset()
		print("reset called")
		dumpers:flush()
		dumpers = nil
	end
	
end