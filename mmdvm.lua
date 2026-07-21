-- Wireshark dissector for MMDVM / Homebrew (HBP) protocol.
-- Based on marrold/MMDVM-Dissector with Talker Alias support (ADN / MMDVMHost HBP):
--   * DMRA UDP packets
--   * Embedded LC in DMRD voice bursts B–E (FLCO 4–7; same path radios use)
--
-- Install: copy to Wireshark plugins dir and restart Wireshark.
--   Linux: ~/.local/lib/wireshark/plugins/
--   Windows: %APPDATA%\Wireshark\plugins\
-- Decode As: UDP port 62030 / 62031 → MMDVM

-- state handling
local stream_map = {}
local state_map = {}
local socket_map = {}
local ta_map = {}
-- Per-call accumulator for embedded LC fragments (vseq 1–4 → one 9-byte LC)
local ta_voice_acc = {}
local f_udp_stream = Field.new("udp.stream")
local FLCO_TA_HEADER = 4
local FLCO_TA_BLOCK3 = 7

-- create myproto protocol and its fields
p_mmdvm = Proto("MMDVM", "MMDVM Protocol")
p_mmdvm_conf = Proto("MMDVM_Conf", "MMDVM Configuration")

local f_signature = ProtoField.string("mmdvm.sig", "Signature", base.ASCII)
local f_seq = ProtoField.uint8("mmdvm.seq", "Sequence", base.DEC)
local f_len = ProtoField.uint8("mmdvm.len", "Length", base.DEC)
local f_src_id = ProtoField.uint24("mmdvm.src_id", "Source ID", base.DEC)
local f_dst_id = ProtoField.uint24("mmdvm.dst_id", "Destination ID", base.DEC)
local f_rptr_id = ProtoField.uint32("mmdvm.rptr_id", "Repeater ID", base.DEC)
local f_rptr_id_ascii = ProtoField.string("mmdvm.rptr_id_ascii", "Repeater ID", base.ASCII)
local f_slot = ProtoField.string("mmdvm.slot", "Slot", base.ASCII)
local f_call_type = ProtoField.string("mmdvm.call_type", "Call type", base.ASCII)
local f_frame_type = ProtoField.string("mmdvm.frame_type", "Frame type", base.ASCII)
local f_data_type = ProtoField.string("mmdvm.data_type", "Data type", base.ASCII)
local f_voice_seq = ProtoField.string("mmdvm.voice_seq", "Voice Sequence", base.ASCII)
local f_stream_id = ProtoField.uint32("mmdvm.stream_id", "Stream ID", base.DEC)
local f_dmr_pkt = ProtoField.bytes("mmdvm.data", "DMR Data", base.NONE)
local f_dmr_sig = ProtoField.bytes("mmdvm.sig", "OpenBridge Signature", base.NONE)
local f_ber = ProtoField.string("mmdvm.ber", "BER", base.ASCII)
local f_rssi = ProtoField.string("mmdvm.rssi", "RSSI", base.ASCII)

local f_ta_block = ProtoField.uint8("mmdvm.ta.block", "TA Block", base.DEC)
local f_ta_payload = ProtoField.bytes("mmdvm.ta.payload", "TA Payload", base.NONE)
local f_ta_format = ProtoField.string("mmdvm.ta.format", "TA Format", base.ASCII)
local f_ta_size = ProtoField.uint8("mmdvm.ta.size", "TA Size", base.DEC)
local f_ta_text = ProtoField.string("mmdvm.ta.text", "Talker Alias", base.UTF_8)
local f_ta_via = ProtoField.string("mmdvm.ta.via", "TA Source", base.ASCII)
local f_ta_flco = ProtoField.uint8("mmdvm.ta.flco", "TA FLCO", base.DEC)
local f_ta_embed_lc = ProtoField.bytes("mmdvm.ta.embed_lc", "Embedded TA LC", base.NONE)

local f_salt = ProtoField.bytes("mmdvm.salt", "Salt", base.NONE)
local f_hash = ProtoField.bytes("mmdvm.hash", "Hash", base.NONE)

local f_call_sign = ProtoField.string("mmdvm.call", "Call Sign", base.ASCII)
local f_rx_freq = ProtoField.string("mmdvm.rx", "Rx Frequency", base.ASCII)
local f_tx_freq = ProtoField.string("mmdvm.tx", "Tx Frequency", base.ASCII)
local f_pwr = ProtoField.string("mmdvm.pwr", "Tx Power", base.ASCII)
local f_color_code = ProtoField.string("mmdvm.cc", "Color Code", base.ASCII)
local f_latitude = ProtoField.string("mmdvm.lat", "Latitude", base.ASCII)
local f_longitude = ProtoField.string("mmdvm.long", "Longitude", base.ASCII)
local f_height = ProtoField.string("mmdvm.height", "Height", base.ASCII)
local f_location = ProtoField.string("mmdvm.loc", "Location", base.ASCII)
local f_description = ProtoField.string("mmdvm.desc", "Description", base.ASCII)
local f_mode = ProtoField.string("mmdvm.mode", "Mode", base.ASCII)
local f_slots = ProtoField.string("mmdvm.slots", "Slots", base.ASCII)
local f_url = ProtoField.string("mmdvm.url", "URL", base.ASCII)
local f_software_id = ProtoField.string("mmdvm.sw", "Software ID", base.ASCII)
local f_package_id = ProtoField.string("mmdvm.pkg", "Package ID", base.ASCII)
local f_options = ProtoField.string("mmdvm.opts", "Options", base.ASCII)

p_mmdvm.fields = {
    f_signature, f_len, f_seq, f_src_id, f_dst_id, f_rptr_id, f_slot, f_call_type,
    f_frame_type, f_data_type, f_voice_seq, f_stream_id, f_dmr_pkt, f_dmr_sig, f_ber, f_rssi,
    f_ta_block, f_ta_payload, f_ta_format, f_ta_size, f_ta_text, f_ta_via, f_ta_flco, f_ta_embed_lc,
    f_salt, f_hash, f_call_sign, f_rx_freq, f_tx_freq, f_pwr, f_color_code, f_latitude,
    f_longitude, f_height, f_location, f_description, f_mode, f_slots, f_url, f_software_id,
    f_package_id, f_options,
}

function string.fromhex(str)
    return (str:gsub("..", function(cc)
        return string.char(tonumber(cc, 16))
    end))
end

function round(num, precision)
    local scale = 10 ^ precision
    return math.floor(num * scale + 0.5) / scale
end

function rem_zero(x)
    x = x:string()
    return x:match("0*(%d+)")
end

function call_slot(bits)
    bits = bits:bytes()
    bits = bits:get_index(0)
    if bit.band(bits, 0x80) ~= 0 then
        return "2"
    end
    return "1"
end

function bm_slot(bits)
    bits = bits(1, 1)
    local result = tonumber(bits)
    if result == 0 then
        return "DMO"
    elseif result == 1 then
        return "1"
    elseif result == 2 then
        return "2"
    end
end

function call_type(bits)
    bits = bits:bytes()
    bits = bits:get_index(0)
    if bit.band(bits, 0x40) ~= 0 then
        return "unit"
    end
    return "group"
end

function frame_type(bits)
    bits = bits:bytes()
    bits = bits:get_index(0)
    bits = bit.band(bits, 0x30)
    local result = bit.rshift(bits, 4)
    if result == 0 then
        return "voice"
    elseif result == 1 then
        return "voice_sync"
    elseif result == 2 then
        return "data_sync"
    end
    return "unknown"
end

function data_type(bits)
    bits = bits:bytes()
    bits = bits:get_index(0)
    local result = bit.band(bits, 0x0F)
    if result == 1 then
        return "voice_head"
    elseif result == 2 then
        return "voice_term"
    end
    return "unknown (" .. result .. ")"
end

function voice_seq_num(bits)
    bits = bits:bytes()
    bits = bits:get_index(0)
    return bit.band(bits, 0x0F)
end

function voice_seq(bits)
    local result = voice_seq_num(bits)
    if result == 0 then
        return "A"
    elseif result == 1 then
        return "B"
    elseif result == 2 then
        return "C"
    elseif result == 3 then
        return "D"
    elseif result == 4 then
        return "E"
    elseif result == 5 then
        return "F"
    end
    return ""
end

-- DMR voice burst → bit table (264 bits from 33 bytes), big-endian MSB first.
function dmr_bytes_to_bits(s)
    local bits = {}
    for i = 1, #s do
        local b = s:byte(i)
        for j = 7, 0, -1 do
            bits[#bits + 1] = bit.band(bit.rshift(b, j), 1)
        end
    end
    return bits
end

-- EMBED LC fragment: bits [116,148) of the 33-byte DMR payload (32 bits).
function dmr_embed_fragment(dmrpkt33)
    if not dmrpkt33 or #dmrpkt33 < 33 then
        return nil
    end
    local bits = dmr_bytes_to_bits(dmrpkt33)
    local emb = {}
    for i = 116, 147 do
        emb[#emb + 1] = bits[i + 1]
    end
    return emb
end

-- BPTC(128,72) data-bit deinterleave → 9-byte LC (matches adn_server.domain.dmr.bptc.decode_emblc).
function decode_emblc(elc128)
    if not elc128 or #elc128 < 128 then
        return nil
    end
    local function e(i)
        return elc128[i + 1] or 0
    end
    local rows = {
        { 0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80 },
        { 1, 9, 17, 25, 33, 41, 49, 57, 65, 73, 81 },
        { 2, 10, 18, 26, 34, 42, 50, 58, 66, 74 },
        { 3, 11, 19, 27, 35, 43, 51, 59, 67, 75 },
        { 4, 12, 20, 28, 36, 44, 52, 60, 68, 76 },
        { 5, 13, 21, 29, 37, 45, 53, 61, 69, 77 },
        { 6, 14, 22, 30, 38, 46, 54, 62, 70, 78 },
    }
    local outbits = {}
    for _, row in ipairs(rows) do
        for _, idx in ipairs(row) do
            outbits[#outbits + 1] = e(idx)
        end
    end
    local chars = {}
    for bi = 0, 8 do
        local v = 0
        for j = 0, 7 do
            v = bit.lshift(v, 1) + (outbits[bi * 8 + j + 1] or 0)
        end
        chars[#chars + 1] = string.char(v)
    end
    return table.concat(chars)
end

-- Reassemble B–E, decode LC; if FLCO 4–7 store TA block. Returns block_id or nil.
function try_buffer_ta_from_voice(stream_key, vseq, dmrpkt33)
    if vseq < 1 or vseq > 4 then
        return nil
    end
    local frag = dmr_embed_fragment(dmrpkt33)
    if not frag then
        return nil
    end
    if not ta_voice_acc[stream_key] then
        ta_voice_acc[stream_key] = {}
    end
    local acc = ta_voice_acc[stream_key]
    if vseq == 1 then
        for k in pairs(acc) do
            acc[k] = nil
        end
    end
    acc[vseq] = frag
    if not (acc[1] and acc[2] and acc[3] and acc[4]) then
        return nil
    end
    local elc = {}
    for v = 1, 4 do
        for i = 1, 32 do
            elc[#elc + 1] = acc[v][i]
        end
    end
    for k in pairs(acc) do
        acc[k] = nil
    end
    local lc = decode_emblc(elc)
    if not lc or #lc < 9 then
        return nil
    end
    local flco = lc:byte(1)
    if flco < FLCO_TA_HEADER or flco > FLCO_TA_BLOCK3 then
        return nil
    end
    local block_id = flco - FLCO_TA_HEADER
    local payload = lc:sub(3, 9)
    local text, fmt, ta_size, just_completed = ta_store_block(stream_key, block_id, payload)
    return {
        block_id = block_id,
        payload = payload,
        flco = flco,
        lc = lc,
        text = text,
        fmt = fmt,
        ta_size = ta_size,
        just_completed = just_completed,
    }
end

function bytes_to_hex(s)
    if not s then
        return ""
    end
    return (s:gsub(".", function(c)
        return string.format("%02x", string.byte(c))
    end))
end

-- Shared Info/tree annotation after a TA block is stored (DMRA or embedded).
-- Returns (display_text_or_nil, info_suffix).
function ta_annotate(subtree, stream_key, block_id, payload, text, fmt, ta_size, just_completed, via)
    local entry = ta_map[stream_key]
    subtree:add(f_ta_via, via)

    local needed = entry and ta_expected_blocks(entry.blocks) or 1
    local all_received = entry ~= nil
    if all_received then
        for i = 0, needed - 1 do
            if entry.blocks[i] == nil then
                all_received = false
                break
            end
        end
    end

    local assembled = nil
    if entry and entry.decoded and entry.decoded ~= "" then
        assembled = entry.decoded
    elseif entry and entry.partial and entry.partial ~= "" then
        assembled = entry.partial
    elseif just_completed and text and text ~= "" then
        assembled = text
    end

    local display_text = nil
    if assembled and all_received and block_id == needed - 1 then
        display_text = assembled
    end

    local suffix = ""
    if display_text then
        if entry and entry.fmt then
            subtree:add(f_ta_format, entry.fmt)
        elseif fmt then
            subtree:add(f_ta_format, fmt)
        end
        local shown_size = (entry and entry.ta_size) or ta_size
        if shown_size then
            subtree:add(f_ta_size, shown_size)
        end
        subtree:add(f_ta_text, display_text)
        suffix = ' "' .. display_text .. '"'
    else
        local preview = ta_payload_preview(block_id, payload)
        if preview ~= "" then
            suffix = ' fragment="' .. preview .. '"'
        elseif block_id == 0 and payload and #payload >= 1 and ta_is_header_byte(payload:byte(1)) then
            suffix = " (header)"
        end
    end
    return display_text, suffix
end

function mode(bits)
    bits = bits:string()
    bits = tonumber(bits)
    if bits == 4 then
        return "simplex", ""
    elseif bits == 3 then
        return "duplex", "1,2"
    elseif bits == 2 then
        return "duplex", "2"
    elseif bits == 1 then
        return "duplex", "1"
    end
    return "unknown", ""
end

function ber(bits)
    bits = bits:bytes()
    bits = bits:get_index(0)
    bits = bits / 1.41
    return tostring(round(bits, 2))
end

function rssi(bits)
    bits = bits:bytes()
    bits = bits:get_index(0)
    return tostring(bits * -1)
end

function tg(bits)
    return bits:uint()
end

function ta_format_name(fmt)
    if fmt == 0 then
        return "7bit"
    elseif fmt == 1 then
        return "iso8"
    elseif fmt == 2 then
        return "utf8"
    elseif fmt == 3 then
        return "utf16"
    end
    return "unknown"
end

function tvb_bytes(tvb_range)
    local len = tvb_range:len()
    if len == 0 then
        return ""
    end
    local ok, s = pcall(function()
        return tvb_range:string()
    end)
    if ok and s and #s == len then
        return s
    end
    ok, s = pcall(function()
        return tvb_range:raw()
    end)
    if ok and s and #s == len then
        return s
    end
    local chars = {}
    for i = 0, len - 1 do
        chars[#chars + 1] = string.char(tvb_range(i, 1):uint())
    end
    return table.concat(chars)
end

function ta_normalize_payload(payload)
    if not payload or #payload == 0 then
        return string.rep("\0", 7)
    end
    if #payload >= 7 then
        return payload:sub(1, 7)
    end
    return payload .. string.rep("\0", 7 - #payload)
end

function ta_block_nonempty(payload)
    if payload == nil then
        return false
    end
    for i = 1, #payload do
        if payload:byte(i) ~= 0 then
            return true
        end
    end
    return false
end

function ta_merge_blocks(blocks)
    local out = {}
    for i = 0, 3 do
        out[#out + 1] = ta_normalize_payload(blocks[i])
    end
    return table.concat(out)
end

function ta_is_header_byte(byte0)
    if bit.band(byte0, 1) ~= 0 then
        return false
    end
    local fmt = bit.rshift(bit.band(byte0, 0xC0), 6)
    local size = bit.band(bit.rshift(byte0, 1), 0x1F)
    return (fmt == 1 or fmt == 2) and size >= 1 and size <= 29
end

-- Match ADN/MMDVMHost: last block index with any non-zero byte + 1.
function ta_required_block_count(blocks)
    local last = -1
    for i = 0, 3 do
        if ta_block_nonempty(blocks[i]) then
            last = i
        end
    end
    return math.max(1, last + 1)
end

-- When block 0 carries a TA header, derive expected block count from ta_size (ETSI).
function ta_expected_blocks(blocks)
    local merged = ta_merge_blocks(blocks)
    if ta_is_header_byte(merged:byte(1)) then
        local ta_size = bit.band(bit.rshift(merged:byte(1), 1), 0x1F)
        local n = math.floor((ta_size + 6) / 7)
        if n < 1 then
            n = 1
        elseif n > 4 then
            n = 4
        end
        return n
    end
    return ta_required_block_count(blocks)
end

function ta_sanitize(text)
    if not text then
        return ""
    end
    return (text:gsub("%z", ""):match("^%s*(.-)%s*$")) or ""
end

function ta_decode_complete(buf28)
    if #buf28 < 1 or not ta_is_header_byte(buf28:byte(1)) then
        return false
    end
    local ta_size = bit.band(bit.rshift(buf28:byte(1), 1), 0x1F)
    local text, _, _ = ta_decode_text(buf28)
    return text ~= nil and #ta_sanitize(text) >= ta_size
end

function ta_decode_7bit(buf28, ta_size)
    local out = {}
    local t2 = 0
    local t1 = 0
    local c = 0
    for i = 1, 32 do
        local b = buf28:byte(i) or 0
        for j = 7, 0, -1 do
            c = bit.lshift(c, 1) + bit.band(bit.rshift(b, j), 1)
            t1 = t1 + 1
            if t1 == 7 then
                if i > 1 and t2 < ta_size then
                    t2 = t2 + 1
                    out[t2] = string.char(bit.band(c, 0x7F))
                end
                t1 = 0
                c = 0
            end
        end
    end
    return table.concat(out)
end

function ta_decode_text(buf28)
    if #buf28 < 1 then
        return nil, nil, nil
    end
    local header = buf28:byte(1)
    local ta_format = bit.rshift(bit.band(header, 0xC0), 6)
    local ta_size = bit.band(bit.rshift(header, 1), 0x1F)
    local text = nil
    if ta_format == 1 or ta_format == 2 then
        text = buf28:sub(2, 1 + ta_size)
    elseif ta_format == 0 then
        text = ta_decode_7bit(buf28, ta_size)
    elseif ta_format == 3 then
        local chars = {}
        local t2 = 0
        for i = 0, 14 do
            local lo = buf28:byte(2 + 2 * i) or 0
            local hi = buf28:byte(3 + 2 * i) or 0
            if t2 >= ta_size then
                break
            end
            if hi == 0 then
                t2 = t2 + 1
                chars[t2] = string.char(lo)
            else
                t2 = t2 + 1
                chars[t2] = "?"
            end
        end
        text = table.concat(chars)
    end
    return text, ta_format_name(ta_format), ta_size
end

function ta_payload_preview(block_id, payload)
    payload = ta_normalize_payload(payload)
    if block_id == 0 and #payload >= 2 then
        return ta_sanitize(payload:sub(2))
    end
    return ta_sanitize(payload)
end

function ta_assemble_partial(blocks, needed)
    local merged = ta_merge_blocks(blocks)
    if not ta_is_header_byte(merged:byte(1)) then
        return "", nil, nil
    end
    local text, fmt, ta_size = ta_decode_text(merged)
    return ta_sanitize(text), fmt, ta_size
end

function ta_store_block(stream_key, block_id, payload)
    if not ta_map[stream_key] then
        ta_map[stream_key] = { blocks = {}, last = 0 }
    end
    local entry = ta_map[stream_key]
    entry.blocks[block_id] = ta_normalize_payload(payload)
    entry.last = os.time()

    local needed = ta_expected_blocks(entry.blocks)
    local all_received = true
    for i = 0, needed - 1 do
        if entry.blocks[i] == nil then
            all_received = false
            break
        end
    end
    if not all_received then
        return nil, nil, nil, false
    end

    local merged = ta_merge_blocks(entry.blocks)
    if ta_decode_complete(merged) then
        local text, fmt, ta_size = ta_decode_text(merged)
        text = ta_sanitize(text)
        entry.decoded = text
        entry.fmt = fmt
        entry.ta_size = ta_size
        entry.partial = nil
        return text, fmt, ta_size, true
    end

    local partial, fmt, ta_size = ta_assemble_partial(entry.blocks, needed)
    if partial ~= "" then
        entry.partial = partial
        if fmt then
            entry.fmt = fmt
        end
        if ta_size then
            entry.ta_size = ta_size
        end
        return partial, fmt, ta_size, true
    end
    return nil, nil, nil, false
end

function p_mmdvm.init()
    stream_map = {}
    state_map = {}
    ta_map = {}
    ta_voice_acc = {}
end

function p_mmdvm.dissector(buf, pkt, root)
    if buf:len() == 0 then
        return
    end
    pkt.cols.protocol = p_mmdvm.name

    local _stream = f_udp_stream().value
    local _number = tostring(pkt.number)
    local _src_ip = tostring(pkt.src)
    local _src_port = tostring(pkt.src_port)
    local _dst_ip = tostring(pkt.dst)
    local _dst_port = tostring(pkt.dst_port)
    local _dst_socket = _dst_ip .. ":" .. _dst_port

    if not pkt.visited then
        if not stream_map[_stream] then
            stream_map[_stream] = {}
        end
    end

    local subtree = root:add(p_mmdvm, buf(0))
    local sig4 = tostring(buf(0, 4)):fromhex()

    if sig4 == "DMRA" and buf:len() >= 15 then
        local _src_id = tg(buf(4, 3))
        local _block_id = buf(7, 1):uint()
        local _payload = tvb_bytes(buf(8, 7))

        subtree:add(f_signature, buf(0, 4))
        subtree:add(f_src_id, buf(4, 3))
        subtree:add(f_ta_block, buf(7, 1), _block_id)
        subtree:add(f_ta_payload, buf(8, 7))

        local stream_key = tostring(_stream) .. ":" .. tostring(_src_id)
        local text, fmt, ta_size, just_completed = ta_store_block(stream_key, _block_id, _payload)

        local _pkt_info
        if socket_map[_dst_socket] then
            _pkt_info = socket_map[_dst_socket] .. ": TALKER ALIAS"
        else
            _pkt_info = "TALKER ALIAS"
        end
        _pkt_info = _pkt_info .. " [" .. _src_id .. " block " .. _block_id .. "]"

        local _, suffix = ta_annotate(
            subtree, stream_key, _block_id, _payload, text, fmt, ta_size, just_completed, "DMRA"
        )
        _pkt_info = _pkt_info .. suffix
        pkt.cols.info:set(_pkt_info)

    elseif sig4 == "DMRD" then
        local _call_type = call_type(buf(15, 1))
        local _frame_type = frame_type(buf(15, 1))
        local _data_type = data_type(buf(15, 1))
        local _vseq_num = voice_seq_num(buf(15, 1))
        local _voice_seq = voice_seq(buf(15, 1))
        local _src_id = tg(buf(5, 3))
        local _dst_id = tg(buf(8, 3))
        local _signed = buf:len() == 73

        subtree:add(f_signature, buf(0, 4))
        subtree:add(f_seq, buf(4, 1))
        subtree:add(f_src_id, buf(5, 3))
        subtree:add(f_dst_id, buf(8, 3))
        subtree:add(f_rptr_id, buf(11, 4))
        subtree:add(f_slot, buf(15, 1), call_slot(buf(15, 1)))
        subtree:add(f_call_type, buf(15, 1), _call_type)
        subtree:add(f_frame_type, buf(15, 1), _frame_type)

        local _pkt_info = "UNKNOWN"
        if _frame_type == "data_sync" then
            subtree:add(f_data_type, buf(15, 1), _data_type)
            if _data_type == "voice_head" then
                _pkt_info = "VOICE HEADER"
            elseif _data_type == "voice_term" then
                _pkt_info = "VOICE TERM"
            else
                _pkt_info = string.upper(_data_type)
            end
        else
            subtree:add(f_voice_seq, buf(15, 1), _voice_seq)
            if _frame_type == "voice_sync" then
                _pkt_info = "VOICE SYNC "
            else
                _pkt_info = "VOICE FRAME "
            end
        end

        if socket_map[_dst_socket] then
            _pkt_info = socket_map[_dst_socket] .. ": " .. _pkt_info
        else
            _pkt_info = " UNKNOWN: " .. _pkt_info
        end

        if _call_type == "unit" then
            _pkt_info = _pkt_info .. " [" .. _src_id .. " -> " .. _dst_id .. " PRIVATE]"
        else
            _pkt_info = _pkt_info .. " [" .. _src_id .. " -> " .. _dst_id .. " GROUP]"
        end

        if _signed then
            _pkt_info = _pkt_info .. " (SIGNED)"
        end

        subtree:add(f_stream_id, buf(16, 4))
        subtree:add(f_dmr_pkt, buf(20, 33))

        -- Embedded Talker Alias: voice bursts B–E (not voice_sync A / F).
        -- Key includes udp.stream so parallel RX legs (e.g. 7141 vs 7301) do not share the B–E accumulator.
        if _frame_type == "voice" and _vseq_num >= 1 and _vseq_num <= 4 and buf:len() >= 53 then
            local _stream_id = buf(16, 4):uint()
            local stream_key = string.format("%s:%u:%s", tostring(_stream), _stream_id, tostring(_src_id))
            local dmrpkt = tvb_bytes(buf(20, 33))
            local hit = try_buffer_ta_from_voice(stream_key, _vseq_num, dmrpkt)
            if hit then
                subtree:add(f_ta_flco, hit.flco)
                subtree:add(f_ta_block, hit.block_id)
                local lc_item = subtree:add(f_ta_embed_lc)
                lc_item:set_text("Embedded TA LC: " .. bytes_to_hex(hit.lc))
                _pkt_info = _pkt_info .. " TA#" .. hit.block_id
                local _, suffix = ta_annotate(
                    subtree,
                    stream_key,
                    hit.block_id,
                    hit.payload,
                    hit.text,
                    hit.fmt,
                    hit.ta_size,
                    hit.just_completed,
                    "embedded"
                )
                _pkt_info = _pkt_info .. suffix
            end
        end

        pkt.cols.info:set(_pkt_info)

        if buf:len() == 55 then
            local _ber = ber(buf(53, 1))
            local _rssi = rssi(buf(54, 1))
            subtree:add(f_ber, buf(53, 1), _ber):append_text("%")
            if tonumber(_rssi) < 0 then
                subtree:add(f_rssi, buf(54, 1), _rssi):append_text("dBm")
            end
        elseif _signed then
            subtree:add(f_dmr_sig, buf(53, 20))
        end

    elseif sig4 == "RPTP" then
        subtree:add(f_signature, buf(0, 7))
        subtree:add(f_rptr_id, buf(7, 4))
        pkt.cols.info:set("RPT->MST: PING")
        if not pkt.visited then
            socket_map[_dst_socket] = "RPT->MST"
        end

    elseif sig4 == "MSTP" then
        subtree:add(f_signature, buf(0, 7))
        subtree:add(f_rptr_id, buf(7, 4))
        pkt.cols.info:set("MST->RPT: PONG")
        if not pkt.visited then
            socket_map[_dst_socket] = "MST->RPT"
        end

    elseif tostring(buf(0, 5)):fromhex() == "RPTCL" then
        subtree:add(f_signature, buf(0, 5))
        subtree:add(f_rptr_id, buf(5, 4))
        pkt.cols.info:set("RPT->MST: CLOSING DOWN")
        if not pkt.visited then
            socket_map[_dst_socket] = "RPT->MST"
        end

    elseif sig4 == "MSTC" then
        subtree:add(f_signature, buf(0, 5))
        subtree:add(f_rptr_id, buf(5, 4))
        pkt.cols.info:set("MST->RPT: CLOSING DOWN")
        if not pkt.visited then
            socket_map[_dst_socket] = "MST->RPT"
        end

    elseif sig4 == "RPTL" then
        subtree:add(f_signature, buf(0, 4))
        subtree:add(f_rptr_id, buf(4, 4))
        pkt.cols.info:set("RPT->MST: LOGIN INIT")
        if not pkt.visited then
            stream_map[_stream]["STATE"] = "INIT"
        end

    elseif sig4 == "RPTK" then
        subtree:add(f_signature, buf(0, 4))
        subtree:add(f_rptr_id, buf(4, 4))
        subtree:add(f_hash, buf(8, buf:len() - 8))
        pkt.cols.info:set("RPT->MST: AUTH")
        if not pkt.visited then
            stream_map[_stream]["STATE"] = "AUTH"
            socket_map[_dst_socket] = "RPT->MST"
        end

    elseif sig4 == "RPTA" then
        subtree:add(f_signature, buf(0, 6))
        if not pkt.visited then
            socket_map[_dst_socket] = "MST->RPT"
            if not state_map[_number] then
                state_map[_number] = {}
            end
            if stream_map[_stream]["STATE"] == "INIT" then
                state_map[_number]["STATE"] = "INIT"
                if buf:len() == 10 then
                    subtree:add(f_salt, buf(6, 4))
                    state_map[_number]["MSG"] = "MST->RPT: AUTH CHALLENGE"
                elseif buf:len() == 14 then
                    subtree:add(f_rptr_id, buf(6, 4))
                    subtree:add(f_salt, buf(10, 4))
                    state_map[_number]["MSG"] = "MST->RPT: AUTH CHALLENGE"
                else
                    state_map[_number]["MALFORMED"] = true
                    state_map[_number]["MSG"] = "MST->RPT: AUTH CHALLENGE [MALFORMED]"
                end
                pkt.cols.info:set(state_map[_number]["MSG"])
            elseif stream_map[_stream]["STATE"] == "AUTH" then
                state_map[_number]["STATE"] = "AUTH"
                if buf:len() == 10 then
                    subtree:add(f_rptr_id, buf(6, 4))
                    state_map[_number]["MSG"] = "MST->RPT: AUTH SUCCESSFUL"
                else
                    state_map[_number]["MALFORMED"] = true
                    state_map[_number]["MSG"] = "MST->RPT: AUTH SUCCESSFUL [MALFORMED]"
                end
                pkt.cols.info:set(state_map[_number]["MSG"])
            elseif stream_map[_stream]["STATE"] == "LOGIN" or stream_map[_stream]["STATE"] == "CONF" then
                state_map[_number]["STATE"] = "LOGIN"
                if buf:len() == 10 then
                    subtree:add(f_rptr_id, buf(6, 4))
                    state_map[_number]["MSG"] = "MST->RPT: LOGIN SUCCESSFUL"
                else
                    state_map[_number]["MALFORMED"] = true
                    state_map[_number]["MSG"] = "MST->RPT: LOGIN SUCCESSFUL [MALFORMED]"
                end
                pkt.cols.info:set(state_map[_number]["MSG"])
            elseif stream_map[_stream]["STATE"] == "OPTIONS" then
                state_map[_number]["STATE"] = "LOGIN"
                if buf:len() == 10 then
                    subtree:add(f_rptr_id, buf(6, 4))
                    state_map[_number]["MSG"] = "MST->RPT: OPTIONS SUCCESSFUL"
                else
                    state_map[_number]["MALFORMED"] = true
                    state_map[_number]["MSG"] = "MST->RPT: OPTIONS SUCCESSFUL [MALFORMED]"
                end
                pkt.cols.info:set(state_map[_number]["MSG"])
            end
        elseif state_map[_number] and state_map[_number]["STATE"] ~= "INIT" then
            pkt.cols.info:set(state_map[_number]["MSG"])
            if not state_map[_number]["MALFORMED"] then
                subtree:add(f_rptr_id, buf(6, 4))
            end
        elseif state_map[_number] and state_map[_number]["STATE"] == "INIT" then
            pkt.cols.info:set(state_map[_number]["MSG"])
            if buf:len() == 10 then
                subtree:add(f_salt, buf(6, 4))
            elseif buf:len() == 14 then
                subtree:add(f_rptr_id, buf(6, 4))
                subtree:add(f_salt, buf(10, 4))
            end
        end

    elseif tostring(buf(0, 6)):fromhex() == "MSTNAK" then
        subtree:add(f_signature, buf(0, 6))
        if not pkt.visited then
            if not state_map[_number] then
                state_map[_number] = {}
            end
            if stream_map[_stream]["STATE"] == "INIT" then
                state_map[_number]["STATE"] = "INIT"
                if buf:len() == 10 then
                    subtree:add(f_salt, buf(6, 4))
                    state_map[_number]["MSG"] = "MST->RPT: LOGIN INIT FAILED"
                else
                    state_map[_number]["MALFORMED"] = true
                    state_map[_number]["MSG"] = "MST->RPT: LOGIN INIT FAILED [MALFORMED]"
                end
                pkt.cols.info:set(state_map[_number]["MSG"])
            elseif stream_map[_stream]["STATE"] == "AUTH" then
                state_map[_number]["STATE"] = "AUTH"
                if buf:len() == 10 then
                    subtree:add(f_rptr_id, buf(6, 4))
                    state_map[_number]["MSG"] = "MST->RPT: AUTH FAILED"
                else
                    state_map[_number]["MALFORMED"] = true
                    state_map[_number]["MSG"] = "MST->RPT: AUTH FAILED [MALFORMED]"
                end
                pkt.cols.info:set(state_map[_number]["MSG"])
            elseif stream_map[_stream]["STATE"] == "CONF" then
                state_map[_number]["STATE"] = "CONF"
                if buf:len() == 10 then
                    subtree:add(f_rptr_id, buf(6, 4))
                    state_map[_number]["MSG"] = "MST->RPT: CONF FAILED"
                else
                    state_map[_number]["MALFORMED"] = true
                    state_map[_number]["MSG"] = "MST->RPT: CONF FAILED [MALFORMED]"
                end
                pkt.cols.info:set(state_map[_number]["MSG"])
            elseif stream_map[_stream]["STATE"] == "OPTIONS" then
                state_map[_number]["STATE"] = "LOGIN"
                if buf:len() == 10 then
                    subtree:add(f_rptr_id, buf(6, 4))
                    state_map[_number]["MSG"] = "MST->RPT: OPTIONS FAILED"
                else
                    state_map[_number]["MALFORMED"] = true
                    state_map[_number]["MSG"] = "MST->RPT: OPTIONS FAILED [MALFORMED]"
                end
                pkt.cols.info:set(state_map[_number]["MSG"])
            else
                if buf:len() == 10 then
                    subtree:add(f_rptr_id, buf(6, 4))
                    pkt.cols.info:set("MSTNAK")
                else
                    pkt.cols.info:set("MSTNAK [MALFORMED]")
                end
            end
        elseif state_map[_number] then
            pkt.cols.info:set(state_map[_number]["MSG"])
            if not state_map[_number]["MALFORMED"] then
                subtree:add(f_rptr_id, buf(6, 4))
            end
        end

    elseif sig4 == "RPTC" then
        local _mode, _slots = mode(buf(97, 1))
        subtree:add(f_signature, buf(0, 4))
        subtree:add(f_rptr_id, buf(4, 4))
        local conftree = subtree:add(p_mmdvm_conf, buf(8))
        conftree:add(f_call_sign, buf(8, 8))
        conftree:add(f_rx_freq, buf(16, 9))
        conftree:add(f_tx_freq, buf(25, 9))
        conftree:add(f_pwr, buf(34, 2), rem_zero(buf(34, 2))):append_text("W")
        conftree:add(f_color_code, buf(36, 2), rem_zero(buf(36, 2)))
        conftree:add(f_latitude, buf(38, 8))
        conftree:add(f_longitude, buf(46, 9))
        conftree:add(f_height, buf(55, 3), rem_zero(buf(55, 3))):append_text("M")
        conftree:add(f_location, buf(58, 20))
        conftree:add(f_description, buf(78, 19))
        conftree:add(f_mode, buf(97, 1), _mode)
        if _mode == "duplex" then
            conftree:add(f_slots, buf(97, 1), _slots)
        end
        conftree:add(f_url, buf(98, 124))
        conftree:add(f_software_id, buf(222, 40))
        conftree:add(f_package_id, buf(262, 40))
        pkt.cols.info:set("RPT->MST: CONF")
        if not pkt.visited then
            stream_map[_stream]["STATE"] = "CONF"
            socket_map[_dst_socket] = "RPT->MST"
        end

    elseif sig4 == "RPTO" then
        subtree:add(f_signature, buf(0, 4))
        subtree:add(f_rptr_id, buf(4, 4))
        subtree:add(f_options, buf(8, buf:len() - 8))
        pkt.cols.info:set("RPT->MST: OPTIONS")
        if not pkt.visited then
            stream_map[_stream]["STATE"] = "OPTIONS"
            socket_map[_dst_socket] = "RPT->MST"
        end

    elseif tostring(buf(0, 6)):fromhex() == "RPTSBKN" then
        subtree:add(f_signature, buf(0, 6))
        subtree:add(f_rptr_id_ascii, buf(6, 8))
        pkt.cols.info:set("MST->RPT: BEACON")
        if not pkt.visited then
            socket_map[_dst_socket] = "MST->RPT"
        end

    elseif tostring(buf(0, 7)):fromhex() == "RPTRSSI" then
        local _bm_slot = bm_slot(buf(10, 2))
        subtree:add(f_signature, buf(0, 7))
        subtree:add(f_rptr_id_ascii, buf(7, 8))
        subtree:add(f_slots, buf(15, 2), _bm_slot)
        subtree:add(f_rssi, buf(17, 5)):append_text("dBm")
        pkt.cols.info:set("RPT->MST: RSSI")
        if not pkt.visited then
            socket_map[_dst_socket] = "RPT->MST"
        end

    elseif tostring(buf(0, 7)):fromhex() == "RPTINTR" then
        local _bm_slot = bm_slot(buf(10, 2))
        subtree:add(f_signature, buf(0, 7))
        subtree:add(f_rptr_id_ascii, buf(7, 8))
        subtree:add(f_slots, buf(15, 2), _bm_slot)
        pkt.cols.info:set("RPT->MST: CALL INTERRUPT")
        if not pkt.visited then
            socket_map[_dst_socket] = "RPT->MST"
        end
    end
end

local udp_dissector_table = DissectorTable.get("udp.port")
udp_dissector_table:add(62030, p_mmdvm)
udp_dissector_table:add(62031, p_mmdvm)
