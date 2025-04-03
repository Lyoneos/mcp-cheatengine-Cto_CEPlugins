--[[
  @description: Cheat Engine socket通信模块（服务端）
  @author: Claude
  @date: 2024-03-20
  @purpose: 用于CE环境中的TCP服务端通信，支持字节码和汇编数据传输
]]

-- 整合MemoryAPI代码
-- =============================== MemoryAPI ===============================
--[[
  @description: Cheat Engine 基础内存读写模块
  @author: Claude
  @date: 2024-03-20
  @purpose: MCP 内存读写功能，
--]]

-- 创建全局命名空间
MemoryAPI = {}

-- 常量定义
MemoryAPI.DEBUG_MODE = true
MemoryAPI.DEFAULT_STRING_MAX_LENGTH = 255

-- 数据类型映射
MemoryAPI.DATA_TYPES = {
  -- 有符号整数
  int8 = { size = 1, signed = true },
  int16 = { size = 2, signed = true },
  int32 = { size = 4, signed = true },
  int64 = { size = 8, signed = true },
  
  -- 无符号整数
  uint8 = { size = 1, signed = false },
  uint16 = { size = 2, signed = false },
  uint32 = { size = 4, signed = false },
  uint64 = { size = 8, signed = false },
  
  -- 浮点数
  float = { size = 4, float = true },
  double = { size = 8, float = true },
  
  -- 字符串
  string = { variable = true, encoding = "ascii" },
  wstring = { variable = true, encoding = "unicode" },
  
  -- 字节数组
  bytes = { variable = true }
}

-- 工具函数
MemoryAPI.Utils = {}

-- 日志输出
function MemoryAPI.Utils.log(message, level)
  if not MemoryAPI.DEBUG_MODE then return end
  level = level or "INFO"
  local msg = string.format("[MemoryAPI-%s] %s", level, message)
  print(msg)
end

-- 格式化地址
function MemoryAPI.Utils.formatAddress(address)
  -- 如果是字符串格式的十六进制地址，转换为数字
  if type(address) == "string" then
    if address:sub(1, 2):lower() == "0x" then
      address = address:sub(3)
    end
    address = tonumber(address, 16)
  end
  
  -- 确保地址是数字
  if type(address) ~= "number" then
    error("无效的内存地址格式")
  end
  
  return address
end

-- 字节序转换
function MemoryAPI.Utils.applyEndian(value, dataTypeInfo, options)
  local endian = options and options.endian or "little"
  
  -- 如果是本机字节序或者是单字节数据，则不需要转换
  if endian == "little" or dataTypeInfo.size == 1 then
    return value
  end
  
  -- TODO: 根据实际需要实现大端字节序转换
  -- 这里应该有针对各种数据类型的大端字节序转换实现
  
  return value
end

-- 主要API函数

-- 用于捕获错误的辅助函数
function tryExec(func, ...)
  local status, result = pcall(func, ...)
  if not status then
    print("执行出错: " .. tostring(result))
    return nil
  end
  return result
end

-- 读取内存（高级）
function MemoryAPI.ReadMemoryEx(address, dataType, options)
  -- 初始化选项参数
  options = options or {}
  
  -- 准备结果表
  local result = {
    address = address,
    dataType = dataType,
    value = nil,
    success = false
  }
  
  -- 格式化地址
  local formattedAddress
  local status, err = pcall(function()
    formattedAddress = MemoryAPI.Utils.formatAddress(address)
  end)
  
  if not status then
    MemoryAPI.Utils.log("地址格式化错误: " .. tostring(err), "ERROR")
    result.error = "地址格式化错误: " .. tostring(err)
    return result
  end
  
  result.address = string.format("0x%X", formattedAddress)
  
  -- 验证数据类型
  local dataTypeInfo = MemoryAPI.DATA_TYPES[dataType]
  if not dataTypeInfo then
    MemoryAPI.Utils.log("无效的数据类型: " .. tostring(dataType), "ERROR")
    result.error = "无效的数据类型"
    return result
  end
  
  -- 读取内存值
  local value, readSuccess
  
  -- 使用try-catch执行，防止读取失败导致崩溃
  local status, readResult = pcall(function()
    if dataType == "string" then
      return readString(formattedAddress)
    elseif dataType == "wstring" then
      return readWideString(formattedAddress)
    elseif dataType == "bytes" then
      local count = options.bytesSize or 4
      return readBytes(formattedAddress, count)
    elseif dataType == "float" then
      return readFloat(formattedAddress)
    elseif dataType == "double" then
      return readDouble(formattedAddress)
    elseif dataType == "int8" then
      return readByte(formattedAddress)
    elseif dataType == "int16" then
      return readSmallInteger(formattedAddress)
    elseif dataType == "int32" then
      return readInteger(formattedAddress)
    elseif dataType == "int64" then
      return readQword(formattedAddress)
    elseif dataType == "uint8" then
      return readByte(formattedAddress)
    elseif dataType == "uint16" then
      return readSmallInteger(formattedAddress)
    elseif dataType == "uint32" then
      return readInteger(formattedAddress)
    elseif dataType == "uint64" then
      return readQword(formattedAddress)
    else
      error("不支持的数据类型: " .. dataType)
    end
  end)
  
  if status then
    value = readResult
    readSuccess = (value ~= nil)
  else
    readSuccess = false
    result.error = "读取过程出错: " .. tostring(readResult)
  end
  
  -- 设置结果值
  if readSuccess then
    result.value = value
    result.success = true
  end
  
  -- 获取原始字节
  if options.rawBytes then
    local bytesSize = options.bytesSize or 16  -- 默认读取16字节
    print("读取原始字节，地址: 0x" .. string.format("%X", formattedAddress) .. ", 大小: " .. bytesSize)
    
    local status, bytesData = pcall(function()
      return readBytes(formattedAddress, bytesSize)
    end)
    
    if status and bytesData and type(bytesData) == "table" then
      result.bytes = bytesData
      print("成功读取 " .. #bytesData .. " 字节的原始数据")
    else
      print("读取原始字节失败: " .. tostring(bytesData))
    end
  end
  
  -- 获取汇编代码
  if options.assembly then
    local assemblySize = options.assemblySize or 1  -- 默认反汇编1条指令
    
    -- 检查是否存在disassemble函数
    if disassemble then
      result.assembly = {}
      local currentAddress = formattedAddress
      local instructionCount = 0
      
      -- 添加指令计数器
      result.instructionCount = 0
      
      -- 调试信息
      print("开始反汇编地址: 0x" .. string.format("%X", formattedAddress) .. ", 指令数: " .. assemblySize)
      
      for i = 1, assemblySize do
        -- 尝试反汇编当前地址的指令
        local status, disResult, disByteSize = pcall(function()
          return disassemble(currentAddress)
        end)
        
        -- 检查反汇编是否成功
        if not status or not disResult then
          print("反汇编失败, 地址: 0x" .. string.format("%X", currentAddress))
          local placeholderInst = {
            address = string.format("0x%X", currentAddress),
            instruction = string.format("%X - [无法反汇编]", currentAddress),
            comment = "",
            annotation = "",
            instructionCount = i
          }
          
          -- 设置标记
          if i == 1 then
            placeholderInst.isFirstInstruction = true
          elseif i == assemblySize then
            placeholderInst.isLastInstruction = true
          end
          
          -- 添加到结果
          table.insert(result.assembly, placeholderInst)
          instructionCount = instructionCount + 1
          currentAddress = currentAddress + 1  -- 假设长度为1字节
          goto continue
        end
        
        -- 创建指令对象
        local instruction = {}
        
        -- 获取当前地址的注释
        local comment = ""
        if getComment then
          comment = getComment(currentAddress) or ""
        end
        
        -- 格式化当前地址
        local addressString = string.format("0x%X", currentAddress)
        instruction.address = addressString
        instruction.instruction = string.format("%X - %s", currentAddress, disResult)
        instruction.comment = comment
        
        -- 标记第一条和最后一条指令
        if i == 1 then
          instruction.isFirstInstruction = true
        elseif i == assemblySize then
          instruction.isLastInstruction = true
        end
        
        -- 添加指令序号
        instruction.instructionCount = i
        
        -- 提取注释码（如果存在）
        local annotation = ""
        if type(disResult) == "string" and disResult:find("%[") and disResult:find("%]") then
          local s, e = string.find(disResult, "%[.-%]")
          if s and e then
            annotation = string.sub(disResult, s, e)
          end
        end
        instruction.annotation = annotation
        
        -- 如果需要为每条指令提供multiType
        if options.instructionMultiType then
          instruction.multiType = {}
          local multiTypeValues = {
            "int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64",
            "float", "double", "string"
          }
          
          print("  读取指令多类型内存值，地址: 0x" .. string.format("%X", currentAddress))
          
          for _, typeKey in ipairs(multiTypeValues) do
            -- 正确使用pcall，第一个返回值是状态(布尔值)，第二个是结果或错误
            local status, typeValue = pcall(function()
              local value
              if typeKey == "string" then
                value = readString(currentAddress)
              elseif typeKey == "float" then
                value = readFloat(currentAddress)
              elseif typeKey == "double" then
                value = readDouble(currentAddress)
              elseif typeKey == "int8" then
                value = readByte(currentAddress)
              elseif typeKey == "int16" then
                value = readSmallInteger(currentAddress)
              elseif typeKey == "int32" then
                value = readInteger(currentAddress)
              elseif typeKey == "int64" then
                value = readQword(currentAddress)
              elseif typeKey == "uint8" then
                value = readByte(currentAddress)
              elseif typeKey == "uint16" then
                value = readSmallInteger(currentAddress)
              elseif typeKey == "uint32" then
                value = readInteger(currentAddress)
              elseif typeKey == "uint64" then
                value = readQword(currentAddress)
              else
                value = nil
              end
              return value
            end)
            
            -- 处理读取结果
            if status then
              -- 读取成功，将值加入结果
              if typeValue ~= nil then
                instruction.multiType[typeKey] = typeValue
              end
            end
          end
          
          -- 调试输出
          local count = 0
          for k, v in pairs(instruction.multiType) do
            count = count + 1
          end
          if count > 0 then
            print("  指令多类型读取完成，成功项数: " .. count)
          end
        end
        
        -- 添加到结果数组
        table.insert(result.assembly, instruction)
        instructionCount = instructionCount + 1
        print("成功反汇编地址: 0x" .. string.format("%X", currentAddress) .. ", 结果: " .. tostring(disResult))
        
        -- 更新地址到下一条指令，增加安全检查
        if disByteSize and disByteSize > 0 then
          currentAddress = currentAddress + disByteSize
        else
          -- 如果disByteSize为nil或者0，使用默认字节数(1)
          print("警告: 地址 " .. addressString .. " 的反汇编未返回有效字节大小，使用默认值1")
          currentAddress = currentAddress + 1
        end
        
        ::continue::
      end
      
      -- 更新真实的指令计数
      result.instructionCount = instructionCount
      
      -- 设置起始和结束指令的特殊标记并创建深拷贝
      if result.assembly and #result.assembly > 0 then
        -- 明确赋值，避免引用问题
        result.startInstruction = {}
        for k, v in pairs(result.assembly[1]) do
          result.startInstruction[k] = v
        end
        
        result.endInstruction = {}
        for k, v in pairs(result.assembly[#result.assembly]) do
          result.endInstruction[k] = v
        end
        
        -- 确保startInstruction和endInstruction设置正确
        print("起始指令地址: " .. result.startInstruction.address)
        print("结束指令地址: " .. result.endInstruction.address)
      else
        print("汇编数组为空或为nil")
      end
    else
      print("disassemble函数不存在，无法反汇编")
    end
  end
  
  -- 获取操作码
  if options.opcode then
    local opcodeSize = options.opcodeSize or 10  -- 默认读取10字节的操作码
    print("读取操作码，地址: 0x" .. string.format("%X", formattedAddress) .. ", 大小: " .. opcodeSize)
    
    local status, opcodeData = pcall(function()
      return readBytes(formattedAddress, opcodeSize)
    end)
    
    if status and opcodeData and type(opcodeData) == "table" then
      result.opcode = opcodeData
      print("成功读取 " .. #opcodeData .. " 字节的操作码")
    else
      print("读取操作码失败: " .. tostring(opcodeData))
    end
  end
  
  -- 获取地址注释
  if options.comments then
    if getComment then
      result.comments = getComment(formattedAddress) or ""
    else
      result.comments = ""
    end
  end
  
  -- 获取多类型解释
  if options.multiType then
    result.multiType = {}
    local multiTypeValues = {
      "int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64",
      "float", "double", "string"
    }
    
    -- 调试输出
    print("读取多类型内存值，地址: 0x" .. string.format("%X", formattedAddress))
    
    for _, typeKey in ipairs(multiTypeValues) do
      -- 正确使用pcall，第一个返回值是状态(布尔值)，第二个是结果或错误
      local status, typeValue = pcall(function()
        local value
        if typeKey == "string" then
          value = readString(formattedAddress)
        elseif typeKey == "float" then
          value = readFloat(formattedAddress)
        elseif typeKey == "double" then
          value = readDouble(formattedAddress)
        elseif typeKey == "int8" then
          value = readByte(formattedAddress)
        elseif typeKey == "int16" then
          value = readSmallInteger(formattedAddress)
        elseif typeKey == "int32" then
          value = readInteger(formattedAddress)
        elseif typeKey == "int64" then
          value = readQword(formattedAddress)
        elseif typeKey == "uint8" then
          value = readByte(formattedAddress)
        elseif typeKey == "uint16" then
          value = readSmallInteger(formattedAddress)
        elseif typeKey == "uint32" then
          value = readInteger(formattedAddress)
        elseif typeKey == "uint64" then
          value = readQword(formattedAddress)
        else
          value = nil
        end
        
        -- 调试输出
        print("  - 类型 " .. typeKey .. " 读取" .. (value ~= nil and "成功: " .. tostring(value) or "失败"))
        
        return value
      end)
      
      -- 处理读取结果
      if status then
        -- 读取成功，将值加入结果
        if typeValue ~= nil then
          result.multiType[typeKey] = typeValue
          print("  + 添加类型 " .. typeKey .. " = " .. tostring(typeValue))
        end
      else
        -- 读取失败，记录错误
        print("  ! 读取类型 " .. typeKey .. " 失败: " .. tostring(typeValue))
      end
    end
    
    -- 调试输出结果
    local count = 0
    for k, v in pairs(result.multiType) do
      count = count + 1
    end
    print("多类型读取完成，成功项数: " .. count)
  end
  
  MemoryAPI.Utils.log(string.format("从地址 %X 读取 %s 值: %s", formattedAddress, dataType, tostring(value)))
  return result
end

-- 写入内存
function MemoryAPI.WriteMemoryEx(address, value, dataType, options)
  options = options or {}
  
  -- 初始化返回值
  local result = {
    address = address,
    dataType = dataType,
    value = value,
    success = false
  }
  
  -- 验证数据类型
  local dataTypeInfo = MemoryAPI.DATA_TYPES[dataType]
  if not dataTypeInfo then
    MemoryAPI.Utils.log("无效的数据类型: " .. tostring(dataType), "ERROR")
    result.error = "无效的数据类型"
    return result
  end
  
  -- 格式化地址
  local formattedAddress
  local status, err = pcall(function()
    formattedAddress = MemoryAPI.Utils.formatAddress(address)
  end)
  
  if not status then
    MemoryAPI.Utils.log("地址格式化错误: " .. tostring(err), "ERROR")
    result.error = "地址格式化错误: " .. tostring(err)
    return result
  end
  
  result.address = string.format("0x%X", formattedAddress)
  
  -- 条件写入
  if options.conditional and options.conditional.previousValue ~= nil then
    local currentValue, readSuccess = MemoryAPI.ReadMemoryEx(formattedAddress, dataType)
    if not readSuccess then
      result.error = "无法读取当前值进行条件比较"
      return result
    end
    
    if currentValue.value ~= options.conditional.previousValue then
      result.error = "条件不满足，当前值与期望值不匹配"
      return result
    end
  end
  
  -- 尝试写入内存
  local success = false
  local errorMsg = nil
  
  -- 使用try-catch执行，防止写入失败导致崩溃
  local status, writeResult = pcall(function()
    if dataType == "string" then
      -- 写入字符串
      return writeString(formattedAddress, value)
    elseif dataType == "wstring" then
      -- 写入宽字符串
      return writeWideString(formattedAddress, value)
    elseif dataType == "bytes" then
      -- 写入字节数组
      if type(value) ~= "table" then
        error("写入bytes类型需要提供字节数组")
      end
      return writeBytes(formattedAddress, value)
    elseif dataType == "float" then
      -- 写入浮点数
      return writeFloat(formattedAddress, value)
    elseif dataType == "double" then
      -- 写入双精度浮点数
      return writeDouble(formattedAddress, value)
    elseif dataType == "int8" then
      -- 写入8位整数
      return writeByte(formattedAddress, value)
    elseif dataType == "int16" then
      -- 写入16位整数
      return writeSmallInteger(formattedAddress, value)
    elseif dataType == "int32" then
      -- 写入32位整数
      return writeInteger(formattedAddress, value)
    elseif dataType == "int64" then
      -- 写入64位整数
      return writeQword(formattedAddress, value)
    elseif dataType == "uint8" then
      -- 写入无符号8位整数
      return writeByte(formattedAddress, value)
    elseif dataType == "uint16" then
      -- 写入无符号16位整数
      return writeSmallInteger(formattedAddress, value)
    elseif dataType == "uint32" then
      -- 写入无符号32位整数
      return writeInteger(formattedAddress, value)
    elseif dataType == "uint64" then
      -- 写入无符号64位整数
      return writeQword(formattedAddress, value)
    else
      error("不支持的数据类型: " .. dataType)
    end
  end)
  
  if status then
    success = writeResult
    if not success then
      errorMsg = "写入失败"
    end
  else
    success = false
    errorMsg = "写入过程出错: " .. tostring(writeResult)
  end
  
  -- 设置返回结果
  result.success = success
  if not success then
    result.error = errorMsg
  end
  
  -- 如果是多值写入
  if options.multiValues and type(options.multiValues) == "table" then
    result.multiValuesResult = {}
    
    for offset, valueInfo in pairs(options.multiValues) do
      if type(valueInfo) == "table" and valueInfo.value ~= nil and valueInfo.dataType then
        local offsetAddress = formattedAddress + tonumber(offset)
        local offsetValue = valueInfo.value
        local offsetType = valueInfo.dataType
        
        local offsetResult = MemoryAPI.WriteMemoryEx(offsetAddress, offsetValue, offsetType)
        result.multiValuesResult[offset] = {
          success = offsetResult.success,
          error = offsetResult.error
        }
      end
    end
  end
  
  -- 记录操作结果
  if success then
    MemoryAPI.Utils.log(string.format("向地址 %X 写入 %s 值: %s", formattedAddress, dataType, tostring(value)))
  else
    MemoryAPI.Utils.log(string.format("向地址 %X 写入 %s 值失败: %s", formattedAddress, dataType, errorMsg), "ERROR")
  end
  
  return result
end

-- 批量读取内存
function MemoryAPI.BatchReadMemory(addresses, dataType, options)
  options = options or {}
  local results = {}
  
  -- 验证数据类型
  if not MemoryAPI.DATA_TYPES[dataType] then
    MemoryAPI.Utils.log("无效的数据类型: " .. tostring(dataType), "ERROR")
    return results
  end
  
  -- 批量读取
  for i, addr in ipairs(addresses) do
    local result = {
      address = addr,
      value = nil,
      bytes = nil,
      assembly = nil,
      opcode = nil,
      comments = nil,
      multiType = nil,
      success = false,
      error = nil
    }
    
    local status, err = pcall(function()
      local formattedAddr = MemoryAPI.Utils.formatAddress(addr)
      local readResult, readSuccess = MemoryAPI.ReadMemoryEx(formattedAddr, dataType, options)
      
      if readSuccess then
        result.value = readResult.value
        result.bytes = readResult.bytes
        result.assembly = readResult.assembly
        result.opcode = readResult.opcode
        result.comments = readResult.comments
        result.multiType = readResult.multiType
        result.success = true
      else
        result.error = "读取失败"
      end
    end)
    
    if not status then
      result.error = tostring(err)
    end
    
    table.insert(results, result)
  end
  
  return results
end


-- =============================== Socket API ================================

-- 创建全局命名空间
SocketAPI = {}

-- 常量定义
SocketAPI.TIMEOUT = 0  -- 改为非阻塞模式
SocketAPI.BUFFER_SIZE = 4096
SocketAPI.DEBUG_MODE = true
SocketAPI.PORT = 8082
SocketAPI.MAX_CLIENTS = 16  -- 最大客户端数量限制
SocketAPI.MAX_PROCESS_TIME = 0.01  -- 最大处理时间(秒)

-- 事件回调函数
SocketAPI.callbacks = {
  onServerStart = nil,   -- 服务启动事件
  onClientConnect = nil, -- 客户端连接事件
  onClientDisconnect = nil, -- 客户端断开连接事件
  onDataReceived = nil,  -- 数据接收事件
  onDataSent = nil,      -- 数据发送事件
  onError = nil          -- 错误事件
}

-- 服务状态
SocketAPI.status = {
  running = false,
  lastError = nil,
  port = SocketAPI.PORT,
  clientsConnected = 0,
  bytesReceived = 0,
  bytesSent = 0,
  startTime = nil,
  isProcessing = false,
  lastProcessTime = 0    -- 上次处理时间
}

-- 日志记录
SocketAPI.logs = {}

-- 工具函数
SocketAPI.Utils = {}

-- 日志输出
function SocketAPI.Utils.log(message, level)
  if not SocketAPI.DEBUG_MODE then return end
  level = level or "INFO"
  local msg = string.format("[%s] %s", level, message)
  print(msg)
  
  -- 添加到日志记录
  local logEntry = {
    timestamp = os.time(),
    level = level,
    message = message
  }
  table.insert(SocketAPI.logs, logEntry)
  
  -- 限制日志条数
  if #SocketAPI.logs > 100 then
    table.remove(SocketAPI.logs, 1)
  end
  
  -- 触发回调
  if level == "ERROR" and SocketAPI.callbacks.onError then
    SocketAPI.callbacks.onError(message)
  end
end

-- 获取当前目录
function SocketAPI.Utils.getCurrentDir()
  local info = debug.getinfo(1, "S")
  return info.source:match("@(.*)[\\/][^\\/]+$") or ""
end

-- 字节数组转十六进制字符串
function SocketAPI.Utils.bytesToHex(bytes)
  local hex = ""
  for i = 1, #bytes do
    hex = hex .. string.format("%02X", string.byte(bytes, i))
  end
  return hex
end

-- 十六进制字符串转字节数组
function SocketAPI.Utils.hexToBytes(hex)
  local bytes = ""
  for i = 1, #hex, 2 do
    bytes = bytes .. string.char(tonumber(hex:sub(i,i+1), 16))
  end
  return bytes
end

-- 获取高精度时间
function SocketAPI.Utils.getTime()
  if os.clock then
    return os.clock()
  else
    return os.time()
  end
end

-- 数据包处理模块
SocketAPI.PacketHandler = {}

-- 数据包类型常量
SocketAPI.PacketHandler.TYPE = {
  ASSEMBLY = 0x01,    -- 汇编代码
  BYTECODE = 0x02,    -- 原始字节码
  TEXT = 0x03,        -- 文本消息
  COMMAND = 0x04,     -- 命令
  RESPONSE = 0x05,    -- 响应
  ERROR = 0xFF,        -- 错误
  MEMORY_READ = 0x10,    -- 内存读取
  MEMORY_WRITE = 0x11,   -- 内存写入
  MEMORY_BATCH = 0x12,   -- 批量内存读取
  LUA_EXEC = 0x20,        -- Lua代码执行
  ASSEMBLY_WRITE = 0x13,  -- 汇编代码修改请求
  ENUM_MODULES = 0x30,    -- 枚举进程模块
  POINTER_SCAN = 0x31,    -- 指针扫描
  POINTER_READ = 0x32     -- 模块偏移指针读取
}

-- 打包数据
function SocketAPI.PacketHandler.pack(data, dataType)
  local header = string.pack(">I2I2", dataType, #data)
  return header .. data
end

-- 解包数据
function SocketAPI.PacketHandler.unpack(packet)
  print("===== 开始解析数据包 =====")
  print("数据包长度: " .. (packet and #packet or "nil"))
  
  if not packet or #packet < 4 then
    print("数据包过短或为nil，无法解析")
    return nil, nil
  end
  
  local dataType, length = string.unpack(">I2I2", packet)
  print("解析头部: 类型=" .. dataType .. ", 长度=" .. length)
  
  if #packet < 4 + length then
    print("数据包不完整，期望" .. (4 + length) .. "字节，实际" .. #packet .. "字节")
    return nil, nil
  end
  
  local data = packet:sub(5, 4 + length)
  print("数据内容长度: " .. #data)
  if #data <= 100 and dataType ~= SocketAPI.PacketHandler.TYPE.BYTECODE then
    print("数据内容预览: " .. data:sub(1, 100))
  else
    print("数据内容过长或为二进制数据，不显示预览")
  end
  
  print("===== 数据包解析完成 =====")
  return dataType, data
end

-- 处理响应数据
function SocketAPI.PacketHandler.packResponse(response)
  return SocketAPI.PacketHandler.pack(response, SocketAPI.PacketHandler.TYPE.RESPONSE)
end

-- 处理错误数据
function SocketAPI.PacketHandler.packError(errorMsg)
  return SocketAPI.PacketHandler.pack(errorMsg, SocketAPI.PacketHandler.TYPE.ERROR)
end

-- 数据包类型描述
function SocketAPI.PacketHandler.getTypeDescription(typeId)
  local typeNames = {
    [SocketAPI.PacketHandler.TYPE.ASSEMBLY] = "汇编代码",
    [SocketAPI.PacketHandler.TYPE.BYTECODE] = "字节码",
    [SocketAPI.PacketHandler.TYPE.TEXT] = "文本消息",
    [SocketAPI.PacketHandler.TYPE.COMMAND] = "命令",
    [SocketAPI.PacketHandler.TYPE.RESPONSE] = "响应",
    [SocketAPI.PacketHandler.TYPE.ERROR] = "错误",
    [SocketAPI.PacketHandler.TYPE.MEMORY_READ] = "内存读取",
    [SocketAPI.PacketHandler.TYPE.MEMORY_WRITE] = "内存写入",
    [SocketAPI.PacketHandler.TYPE.MEMORY_BATCH] = "批量内存读取",
    [SocketAPI.PacketHandler.TYPE.LUA_EXEC] = "Lua代码执行",
    [SocketAPI.PacketHandler.TYPE.ASSEMBLY_WRITE] = "汇编代码修改",  -- 添加新类型描述
    [SocketAPI.PacketHandler.TYPE.ENUM_MODULES] = "枚举进程模块",     -- 添加枚举模块描述
    [SocketAPI.PacketHandler.TYPE.POINTER_SCAN] = "指针扫描",        -- 添加指针扫描描述
    [SocketAPI.PacketHandler.TYPE.POINTER_READ] = "模块偏移指针读取"  -- 添加新类型描述
  }
  
  return typeNames[typeId] or "未知类型"
end

-- Socket服务器管理器
SocketAPI.Manager = {}

-- 初始化socket库
function SocketAPI.Manager:init()
  print("===== 开始初始化Socket服务器 =====")
  if self.initialized then
    print("服务器已经初始化，跳过初始化步骤")
    return true
  end

  local currentDir = SocketAPI.Utils.getCurrentDir()
  local socketDllPath = currentDir .. "\\socket.dll"
  print("当前目录: " .. currentDir)
  print("尝试加载Socket库: " .. socketDllPath)
  
  -- 尝试加载socket.dll
  local socket_core = package.loadlib(socketDllPath, "luaopen_socket_core")
  
  if not socket_core then
    print("从DLL加载失败，尝试通过require加载")
    local status, socket_module = pcall(function() return require("socket") end)
    if not status then
      SocketAPI.Utils.log("Socket库加载失败: " .. tostring(socket_module), "ERROR")
      SocketAPI.status.lastError = "Socket库加载失败: " .. tostring(socket_module)
      print("===== Socket服务器初始化失败 =====")
      return false
    end
    self.socket = socket_module
    print("通过require成功加载socket模块")
  else
    SocketAPI.Utils.log("加载socket_core成功")
    print("从DLL成功加载socket_core")
    local socket_table = socket_core()
    _G.socket = socket_table or {}
    _G.socket._VERSION = "LuaSocket 3.0"
    self.socket = _G.socket
    print("Socket版本: " .. (_G.socket._VERSION or "未知"))
  end
  
  self.initialized = true
  self.clients = {}
  self.clientQueue = {}  -- 待处理客户端队列
  print("===== Socket服务器初始化完成 =====")
  return true
end

-- 启动服务器
function SocketAPI.Manager:startServer(port)
  if not self:init() then
    return false
  end

  port = port or SocketAPI.PORT
  
  -- 停止现有服务器
  if self.server then
    self:stopServer()
  end

  self.server = self.socket.tcp()
  self.server:settimeout(0) -- 非阻塞模式
  
  -- 允许端口重用
  self.server:setoption("reuseaddr", true)
  
  local result, err = self.server:bind("0.0.0.0", port)
  if not result then
    SocketAPI.Utils.log("绑定端口失败: " .. tostring(err), "ERROR")
    SocketAPI.status.lastError = "绑定端口失败: " .. tostring(err)
    return false
  end
  
  result, err = self.server:listen(5) -- 最多5个客户端排队
  if not result then
    SocketAPI.Utils.log("监听失败: " .. tostring(err), "ERROR")
    SocketAPI.status.lastError = "监听失败: " .. tostring(err)
    return false
  end

  -- 更新服务器状态
  SocketAPI.status.running = true
  SocketAPI.status.port = port
  SocketAPI.status.startTime = os.time()
  SocketAPI.status.clientsConnected = 0
  SocketAPI.status.bytesReceived = 0
  SocketAPI.status.bytesSent = 0
  
  SocketAPI.Utils.log("服务器启动成功，监听端口: " .. port)
  
  -- 触发服务器启动回调
  if SocketAPI.callbacks.onServerStart then
    SocketAPI.callbacks.onServerStart(port)
  end
  
  return true
end

-- 检查新客户端连接
function SocketAPI.Manager:checkForNewClients()
  if not self.server then
    return nil
  end
  
  -- 如果已达到最大客户端数量限制，不再接受新连接
  if SocketAPI.status.clientsConnected >= SocketAPI.MAX_CLIENTS then
    return nil
  end
  
  local client, err = self.server:accept()
  if not client then
    if err ~= "timeout" then
      SocketAPI.Utils.log("接受客户端连接错误: " .. tostring(err), "ERROR")
    end
    return nil
  end
  
  -- 设置为非阻塞模式
  client:settimeout(0)
  
  -- 获取客户端信息
  local ip, port = client:getpeername()
  local clientId = ip .. ":" .. port
  
  -- 保存客户端连接
  self.clients[clientId] = {
    socket = client,
    ip = ip,
    port = port,
    connectTime = os.time(),
    bytesReceived = 0,
    bytesSent = 0,
    buffer = "",       -- 接收数据缓冲区
    lastActivity = os.time()  -- 上次活动时间
  }
  
  SocketAPI.status.clientsConnected = SocketAPI.status.clientsConnected + 1
  
  SocketAPI.Utils.log("客户端连接: " .. clientId)
  
  -- 触发客户端连接回调
  if SocketAPI.callbacks.onClientConnect then
    SocketAPI.callbacks.onClientConnect(clientId, ip, port)
  end
  
  return clientId
end

-- 向指定客户端发送数据
function SocketAPI.Manager:sendToClient(clientId, data)
  local client = self.clients[clientId]
  if not client then
    SocketAPI.Utils.log("客户端不存在: " .. tostring(clientId), "ERROR")
    return false
  end

  local sent, err = client.socket:send(data)
  if not sent then
    SocketAPI.Utils.log("发送失败: " .. tostring(err), "ERROR")
    
    -- 如果连接已断开，移除客户端
    if err == "closed" then
      self:removeClient(clientId)
    end
    
    return false
  end
  
  -- 更新发送统计
  client.bytesSent = client.bytesSent + #data
  SocketAPI.status.bytesSent = SocketAPI.status.bytesSent + #data
  client.lastActivity = os.time()
  
  -- 触发数据发送回调
  if SocketAPI.callbacks.onDataSent then
    SocketAPI.callbacks.onDataSent(clientId, data, #data)
  end
  
  return true
end

-- 从指定客户端接收数据
function SocketAPI.Manager:receiveFromClient(clientId)
  local client = self.clients[clientId]
  if not client then
    SocketAPI.Utils.log("客户端不存在: " .. tostring(clientId), "ERROR")
    return nil
  end

  -- 使用非阻塞方式接收数据
  local data, err, partial = client.socket:receive(SocketAPI.BUFFER_SIZE)
  
  -- 如果接收到数据
  if data then
  -- 更新接收统计
    client.bytesReceived = client.bytesReceived + #data
  SocketAPI.status.bytesReceived = SocketAPI.status.bytesReceived + #data
    client.lastActivity = os.time()
  
  -- 触发数据接收回调
  if SocketAPI.callbacks.onDataReceived then
      SocketAPI.callbacks.onDataReceived(clientId, data, #data)
  end
  
  return data
  else
    -- 处理错误情况
    if err == "timeout" then
      -- 超时但有部分数据
      if partial and #partial > 0 then
        client.bytesReceived = client.bytesReceived + #partial
        SocketAPI.status.bytesReceived = SocketAPI.status.bytesReceived + #partial
        client.lastActivity = os.time()
        
        if SocketAPI.callbacks.onDataReceived then
          SocketAPI.callbacks.onDataReceived(clientId, partial, #partial)
        end
        
        return partial
      end
      -- 超时且无数据，属于正常情况
    return nil
    else
      -- 其他错误如连接关闭
      SocketAPI.Utils.log("接收数据错误: " .. tostring(err), "ERROR")
      
      -- 如果连接已断开，移除客户端
      if err == "closed" then
        self:removeClient(clientId)
      end
      
      return nil
    end
  end
end

-- 处理从客户端接收的数据
function SocketAPI.Manager:processClientRequest(clientId, request)
  print("\n===== 开始处理客户端请求 =====")
  print("客户端ID: " .. clientId)
  print("请求数据长度: " .. (request and #request or "nil"))
  
  if not request then
    print("请求为空，跳过处理")
    return nil
  end
  
  print("开始解包请求...")
  local dataType, data = SocketAPI.PacketHandler.unpack(request)
  if not dataType or not data then
    print("解包失败，无效请求格式")
    local errorResponse = SocketAPI.PacketHandler.packError("无效的请求数据格式")
    self:sendToClient(clientId, errorResponse)
    return nil
  end
  
  local typeDesc = SocketAPI.PacketHandler.getTypeDescription(dataType)
  print("请求类型: " .. typeDesc .. " (" .. dataType .. ", 0x" .. string.format("%X", dataType) .. ")")
  print("数据长度: " .. #data)

  -- 处理内存相关操作
  local response = nil
  print("开始处理具体请求类型...")

  if dataType == SocketAPI.PacketHandler.TYPE.MEMORY_READ then
    print("处理内存读取请求...")
    local success, readResult = pcall(function()
      return SocketAPI.PacketHandler.handleMemoryRead(self, data, clientId)
    end)

    if success then
      response = readResult
      print("内存读取请求处理成功")
    else
      print("内存读取请求处理失败: " .. tostring(readResult))
      response = SocketAPI.PacketHandler.packError("处理内存读取请求失败: " .. tostring(readResult))
    end

  elseif dataType == SocketAPI.PacketHandler.TYPE.MEMORY_WRITE then
    -- 处理内存写入请求
    local success, writeResult = pcall(function()
      return SocketAPI.PacketHandler.handleMemoryWrite(self, data, clientId)
    end)

    if success then
      response = writeResult
    else
      SocketAPI.Utils.log("处理内存写入请求失败: " .. tostring(writeResult), "ERROR")
      response = SocketAPI.PacketHandler.packError("处理内存写入请求失败: " .. tostring(writeResult))
    end

  elseif dataType == SocketAPI.PacketHandler.TYPE.MEMORY_BATCH then
    -- 处理批量内存读取请求
    local success, batchResult = pcall(function()
      return SocketAPI.PacketHandler.handleMemoryBatch(self, data, clientId)
    end)

    if success then
      response = batchResult
    else
      SocketAPI.Utils.log("处理批量内存读取请求失败: " .. tostring(batchResult), "ERROR")
      response = SocketAPI.PacketHandler.packError("处理批量内存读取请求失败: " .. tostring(batchResult))
    end

  elseif dataType == SocketAPI.PacketHandler.TYPE.LUA_EXEC then
    -- 处理Lua代码执行请求
    local success, execResult = pcall(function()
      return SocketAPI.PacketHandler.handleLuaExec(self, data, clientId)
    end)

    if success then
      response = execResult
    else
      SocketAPI.Utils.log("处理Lua代码执行请求失败: " .. tostring(execResult), "ERROR")
      response = SocketAPI.PacketHandler.packError("处理Lua代码执行请求失败: " .. tostring(execResult))
    end

  elseif dataType == SocketAPI.PacketHandler.TYPE.ASSEMBLY or
         dataType == SocketAPI.PacketHandler.TYPE.BYTECODE or
         dataType == SocketAPI.PacketHandler.TYPE.TEXT or
         dataType == SocketAPI.PacketHandler.TYPE.COMMAND then
    -- 处理其他现有类型请求
  if dataType == SocketAPI.PacketHandler.TYPE.ASSEMBLY then
      -- 处理汇编代码请求
      SocketAPI.Utils.log("汇编代码请求: " .. data)
      -- 这里添加汇编代码处理逻辑
      response = SocketAPI.PacketHandler.packResponse("汇编代码已接收")

  elseif dataType == SocketAPI.PacketHandler.TYPE.BYTECODE then
      -- 处理字节码请求
      SocketAPI.Utils.log("字节码请求: " .. SocketAPI.Utils.bytesToHex(data))
      -- 这里添加字节码处理逻辑
      response = SocketAPI.PacketHandler.packResponse("字节码已接收")

  elseif dataType == SocketAPI.PacketHandler.TYPE.TEXT then
      -- 处理文本请求
      SocketAPI.Utils.log("文本请求: " .. data)
      -- 这里添加文本处理逻辑
      response = SocketAPI.PacketHandler.packResponse("文本已接收: " .. data)

  elseif dataType == SocketAPI.PacketHandler.TYPE.COMMAND then
      -- 处理命令请求
      SocketAPI.Utils.log("命令请求: " .. data)
      -- 这里添加命令处理逻辑
      response = SocketAPI.PacketHandler.packResponse("命令已执行: " .. data)
    end

  elseif dataType == SocketAPI.PacketHandler.TYPE.ASSEMBLY_WRITE then
    -- 处理汇编代码修改请求
    print("处理汇编代码修改请求...")
    local success, writeResult = pcall(function()
      return SocketAPI.PacketHandler.handleAssemblyWrite(self, data, clientId)
    end)

    if success then
      response = writeResult
      print("汇编代码修改请求处理成功")
    else
      print("汇编代码修改请求处理失败: " .. tostring(writeResult))
      response = SocketAPI.PacketHandler.packError("处理汇编代码修改请求失败: " .. tostring(writeResult))
    end
  elseif dataType == SocketAPI.PacketHandler.TYPE.ENUM_MODULES then
    -- 处理枚举模块请求
    print("处理枚举模块请求...")
    local success, enumResult = pcall(function()
      return SocketAPI.PacketHandler.handleEnumModules(self, data, clientId)
    end)

    if success then
      response = enumResult
      print("枚举模块请求处理成功")
    else
      print("枚举模块请求处理失败: " .. tostring(enumResult))
      response = SocketAPI.PacketHandler.packError("处理枚举模块请求失败: " .. tostring(enumResult))
    end
  elseif dataType == SocketAPI.PacketHandler.TYPE.POINTER_SCAN then
    -- 处理指针扫描请求
    print("处理指针扫描请求...")
    local success, scanResult = pcall(function()
      return SocketAPI.PacketHandler.handlePointerScan(self, data, clientId)
    end)

    if success then
      response = scanResult
      print("指针扫描请求处理成功")
    else
      print("指针扫描请求处理失败: " .. tostring(scanResult))
      response = SocketAPI.PacketHandler.packError("处理指针扫描请求失败: " .. tostring(scanResult))
    end
  elseif dataType == SocketAPI.PacketHandler.TYPE.POINTER_READ then
    -- 处理模块偏移指针读取请求
    print("处理模块偏移指针读取请求...")
    local success, readResult = pcall(function()
      return SocketAPI.PacketHandler.handlePointerRead(self, data, clientId)
    end)

    if success then
      response = readResult
      print("模块偏移指针读取请求处理成功")
    else
      print("模块偏移指针读取请求处理失败: " .. tostring(readResult))
      response = SocketAPI.PacketHandler.packError("处理模块偏移指针读取请求失败: " .. tostring(readResult))
    end
  else
    -- 未知类型请求
    SocketAPI.Utils.log("未知类型请求: " .. dataType, "ERROR")
    response = SocketAPI.PacketHandler.packError("未知的请求类型")
  end

  -- 如果有响应，发送给客户端
  if response then
    print("向客户端发送响应，长度: " .. #response)
    self:sendToClient(clientId, response)
  else
    print("无响应数据")
  end

  print("===== 客户端请求处理完成 =====\n")

  return {
    clientId = clientId,
    type = dataType,
    typeDesc = typeDesc,
    data = data,
    hexData = dataType == SocketAPI.PacketHandler.TYPE.BYTECODE and SocketAPI.Utils.bytesToHex(data) or nil
  }
end

-- 移除客户端
function SocketAPI.Manager:removeClient(clientId)
  local client = self.clients[clientId]
  if not client then
    return
  end

  client.socket:close()
  self.clients[clientId] = nil
  SocketAPI.status.clientsConnected = SocketAPI.status.clientsConnected - 1

  SocketAPI.Utils.log("客户端断开连接: " .. clientId)

  -- 触发客户端断开连接回调
  if SocketAPI.callbacks.onClientDisconnect then
    SocketAPI.callbacks.onClientDisconnect(clientId)
  end
end

-- 停止服务器
function SocketAPI.Manager:stopServer()
  -- 断开所有客户端
  for clientId, _ in pairs(self.clients) do
    self:removeClient(clientId)
  end

  -- 关闭服务器
  if self.server then
    self.server:close()
    self.server = nil
    SocketAPI.status.running = false
    SocketAPI.Utils.log("服务器已停止")
  end
end

-- 清理超时客户端
function SocketAPI.Manager:cleanupTimeoutClients()
  local now = os.time()
  local timeout = 300 -- 5分钟无响应断开连接
  local clientsToRemove = {}

  for clientId, client in pairs(self.clients) do
    if now - client.lastActivity > timeout then
      table.insert(clientsToRemove, clientId)
    end
  end

  for _, clientId in ipairs(clientsToRemove) do
    SocketAPI.Utils.log("客户端超时断开: " .. clientId)
    self:removeClient(clientId)
  end
end

-- 服务循环
function SocketAPI.Manager:serverLoop()
  if not self.server then
    return false
  end

  -- 每350次循环输出一次服务器状态
  if not self.loopCounter then
    self.loopCounter = 0
  end

  self.loopCounter = self.loopCounter + 1
  if self.loopCounter % 350 == 0 then
    print("\n===== 服务器状态 =====")
    print("已连接客户端: " .. SocketAPI.status.clientsConnected)
    print("已接收字节: " .. SocketAPI.status.bytesReceived)
    print("已发送字节: " .. SocketAPI.status.bytesSent)
    print("上次处理时间: " .. string.format("%.2f", SocketAPI.status.lastProcessTime*1000) .. "ms")
    print("=======================\n")
  end

  -- 记录处理开始时间
  local startTime = SocketAPI.Utils.getTime()
  local processed = 0

  -- 检查新连接
  local newClient = self:checkForNewClients()
  if newClient then
    print("新客户端连接: " .. newClient)
  end

  -- 更新客户端队列 (按上次处理时间排序)
  self.clientQueue = {}
  for clientId, _ in pairs(self.clients) do
    table.insert(self.clientQueue, clientId)
  end

  -- 每次只处理部分客户端，避免长时间阻塞
  local maxClientsPerTick = 3
  local clientsToProcess = math.min(#self.clientQueue, maxClientsPerTick)

  for i = 1, clientsToProcess do
    local clientId = self.clientQueue[i]
    if self.clients[clientId] then
      local data = self:receiveFromClient(clientId)
      if data then
        print("从客户端 " .. clientId .. " 接收到数据，长度: " .. #data)
        self:processClientRequest(clientId, data)
        processed = processed + 1
      end
    end

    -- 检查处理时间是否超过限制
    if (SocketAPI.Utils.getTime() - startTime) > SocketAPI.MAX_PROCESS_TIME then
      print("服务循环处理时间超过限制，已处理 " .. i .. "/" .. clientsToProcess .. " 个客户端")
      break
    end
  end

  -- 定期清理超时连接 (每10次循环检查一次)
  if math.random(10) == 1 then
    self:cleanupTimeoutClients()
  end

  -- 记录处理时间
  local elapsed = SocketAPI.Utils.getTime() - startTime
  SocketAPI.status.lastProcessTime = elapsed

  -- 如果有处理的请求，输出一次处理时间
  if processed > 0 then
    print("本次循环处理了 " .. processed .. " 个请求，耗时: " .. string.format("%.2f", elapsed*1000) .. "ms")
  end

  return true
end

-- 公共API接口
SocketAPI.API = {}

-- 初始化
function SocketAPI.API.init()
  return SocketAPI.Manager:init()
end

-- 启动服务器
function SocketAPI.API.startServer(port)
  return SocketAPI.Manager:startServer(port)
end

-- 停止服务器
function SocketAPI.API.stopServer()
  SocketAPI.Manager:stopServer()
end

-- 服务循环
function SocketAPI.API.serverLoop()
  return SocketAPI.Manager:serverLoop()
end

-- 获取所有客户端
function SocketAPI.API.getClients()
  return SocketAPI.Manager.clients
end

-- 向指定客户端发送响应
function SocketAPI.API.sendResponse(clientId, response)
  local packet = SocketAPI.PacketHandler.packResponse(response)
  return SocketAPI.Manager:sendToClient(clientId, packet)
end

-- 向指定客户端发送错误
function SocketAPI.API.sendError(clientId, errorMsg)
  local packet = SocketAPI.PacketHandler.packError(errorMsg)
  return SocketAPI.Manager:sendToClient(clientId, packet)
end

-- 获取服务器状态
function SocketAPI.API.getStatus()
  return SocketAPI.status
end

-- 获取日志
function SocketAPI.API.getLogs()
  return SocketAPI.logs
end

-- 设置回调
function SocketAPI.API.setCallback(callbackType, func)
  if SocketAPI.callbacks[callbackType] ~= nil then
    SocketAPI.callbacks[callbackType] = func
    return true
  end
  return false
end

-- 清空日志
function SocketAPI.API.clearLogs()
  SocketAPI.logs = {}
end

-- 十六进制转字节
function SocketAPI.API.hexToBytes(hex)
  return SocketAPI.Utils.hexToBytes(hex)
end

-- 字节转十六进制
function SocketAPI.API.bytesToHex(bytes)
  return SocketAPI.Utils.bytesToHex(bytes)
end

-- 添加一个更强大的JSON解析函数
function parseJSON(str)
  print("解析JSON数据: " .. tostring(str and str:sub(1, 50) .. "..."))

  -- 使用debug功能
  local debugMode = true
  local function debugPrint(msg)
    if debugMode then
      print("[JSON解析] " .. msg)
    end
  end

  -- 简单解析JSON对象
  local result = {}
  local errorMsg = nil

  -- 检查输入
  if not str or str == "" then
    return nil, "JSON数据为空"
  end

  -- 清理外部空白和大括号
  local jsonContent = str:match("^%s*{(.-)%s*}%s*$")
  if not jsonContent then
    return nil, "JSON格式错误：缺少外部大括号"
  end

  debugPrint("开始解析内容: " .. jsonContent:sub(1, 50) .. "...")

  -- 递归解析对象函数
  local function parseObject(content)
    local obj = {}
    local pos = 1
    local len = #content

    debugPrint("解析对象，长度: " .. len)

    while pos <= len do
      -- 跳过空白
      local s, e = content:find("^%s*", pos)
      pos = e + 1
      if pos > len then break end

      -- 解析键名（必须是字符串）
      if content:sub(pos, pos) ~= '"' then
        local preview = content:sub(pos, pos+10)
        debugPrint("键名格式错误，位置: " .. pos .. ", 预览: " .. preview)
        return nil, "JSON格式错误：键名必须是字符串，位置 " .. pos
      end

      -- 提取键名
      local keyEnd = content:find('"', pos + 1)
      if not keyEnd then
        debugPrint("键名没有结束引号")
        return nil, "JSON格式错误：键名没有结束引号"
      end
      local key = content:sub(pos + 1, keyEnd - 1)
      pos = keyEnd + 1

      debugPrint("找到键名: " .. key)

      -- 跳过键名后的空白和冒号
      s, e = content:find("^%s*:%s*", pos)
      if not s then
        debugPrint("缺少冒号分隔符，键名: " .. key)
        return nil, "JSON格式错误：键值对缺少冒号分隔符，键名: " .. key
      end
      pos = e + 1

      -- 解析值
      local value, valueEnd, parseError

      -- 字符串值
      if content:sub(pos, pos) == '"' then
        -- 原有的模式有问题，会导致字符串被错误截断
        -- s, e, value = content:find('"(.-)[^\\]"', pos)
        -- 修复为更可靠的字符串匹配方法
        local startPos = pos + 1  -- 跳过开始的引号
        local endPos = startPos
        local escaped = false

        -- 手动解析字符串，正确处理转义字符
        while endPos <= len do
          local char = content:sub(endPos, endPos)

          if escaped then
            -- 已经转义，直接接受字符
            escaped = false
          elseif char == '\\' then
            -- 转义字符
            escaped = true
          elseif char == '"' then
            -- 找到未转义的结束引号
            break
          end

          endPos = endPos + 1
        end

        if endPos > len then
          debugPrint("字符串值没有结束引号，键名: " .. key)
          return nil, "JSON格式错误：字符串值没有结束引号，键名: " .. key
        end

        value = content:sub(startPos, endPos - 1)
        pos = endPos + 1

        debugPrint("字符串值: " .. value)

      -- 数字值
      elseif content:sub(pos, pos):match("[%d%-]") then
        s, e, value = content:find("^([%d%.%-]+)", pos)
        value = tonumber(value)
        if not value then
          debugPrint("无效的数字格式，键名: " .. key)
          return nil, "JSON格式错误：无效的数字格式，键名: " .. key
        end
        pos = e + 1

        debugPrint("数字值: " .. value)

      -- 布尔值或null
      elseif content:sub(pos, pos + 3) == "true" then
        value = true
        pos = pos + 4
        debugPrint("布尔值: true")
      elseif content:sub(pos, pos + 4) == "false" then
        value = false
        pos = pos + 5
        debugPrint("布尔值: false")
      elseif content:sub(pos, pos + 3) == "null" then
        value = nil
        pos = pos + 4
        debugPrint("空值: null")

      -- 对象
      elseif content:sub(pos, pos) == "{" then
        debugPrint("开始解析子对象，键名: " .. key)
        -- 找到匹配的右大括号
        local level = 1
        local subStart = pos + 1
        valueEnd = subStart

        while level > 0 and valueEnd <= len do
          local char = content:sub(valueEnd, valueEnd)
          if char == '{' then
            level = level + 1
          elseif char == '}' then
            level = level - 1
          elseif char == '"' then
            -- 跳过字符串内容
            local strEnd = content:find('"', valueEnd + 1)
            if strEnd then
              valueEnd = strEnd
            end
          end
          valueEnd = valueEnd + 1
        end

        if level > 0 then
          debugPrint("嵌套对象没有结束大括号，键名: " .. key)
          return nil, "JSON格式错误：嵌套对象没有结束大括号，键名: " .. key
        end

        -- 提取子对象内容
        local subContent = content:sub(subStart, valueEnd - 2)
        debugPrint("子对象内容: " .. subContent:sub(1, 30) .. (subContent:len() > 30 and "..." or ""))

        -- 递归解析子对象
        value, parseError = parseObject(subContent)
        if parseError then
          debugPrint("子对象解析错误: " .. parseError)
          return nil, parseError
        end

        pos = valueEnd
        debugPrint("子对象解析完成，键名: " .. key)

      -- 数组
      elseif content:sub(pos, pos) == "[" then
        debugPrint("开始解析数组，键名: " .. key)
        -- 找到匹配的右中括号
        local level = 1
        local arrayStart = pos + 1
        valueEnd = arrayStart

        while level > 0 and valueEnd <= len do
          local char = content:sub(valueEnd, valueEnd)
          if char == '[' then
            level = level + 1
          elseif char == ']' then
            level = level - 1
          elseif char == '"' then
            -- 跳过字符串内容
            local strEnd = content:find('"', valueEnd + 1)
            if strEnd then
              valueEnd = strEnd
            end
          end
          valueEnd = valueEnd + 1
        end

        if level > 0 then
          debugPrint("数组没有结束中括号，键名: " .. key)
          return nil, "JSON格式错误：数组没有结束中括号，键名: " .. key
        end

        -- 提取数组内容
        local arrayContent = content:sub(arrayStart, valueEnd - 2)
        debugPrint("数组内容: " .. arrayContent:sub(1, 30) .. (arrayContent:len() > 30 and "..." or ""))

        -- 解析数组元素
        value = {}
        if arrayContent:len() > 0 then
          -- 按逗号分割
          local arrayPos = 1
          local arrayLen = arrayContent:len()
          local itemIndex = 1

          while arrayPos <= arrayLen do
            -- 跳过空白
            local s, e = arrayContent:find("^%s*", arrayPos)
            arrayPos = e + 1
            if arrayPos > arrayLen then break end

            -- 解析元素
            local itemValue
            local itemEnd

            -- 字符串元素
            if arrayContent:sub(arrayPos, arrayPos) == '"' then
              -- 使用与对象字符串值相同的修复方法
              local startPos = arrayPos + 1  -- 跳过开始的引号
              local endPos = startPos
              local escaped = false

              -- 手动解析字符串，正确处理转义字符
              while endPos <= arrayLen do
                local char = arrayContent:sub(endPos, endPos)

                if escaped then
                  -- 已经转义，直接接受字符
                  escaped = false
                elseif char == '\\' then
                  -- 转义字符
                  escaped = true
                elseif char == '"' then
                  -- 找到未转义的结束引号
                  break
                end

                endPos = endPos + 1
              end

              if endPos > arrayLen then
                debugPrint("数组字符串元素没有结束引号")
                return nil, "JSON格式错误：数组字符串元素没有结束引号"
              end

              itemValue = arrayContent:sub(startPos, endPos - 1)
              arrayPos = endPos + 1

            -- 数字元素
            elseif arrayContent:sub(arrayPos, arrayPos):match("[%d%-]") then
              s, e, strValue = arrayContent:find("^([%d%.%-]+)", arrayPos)
              itemValue = tonumber(strValue)
              if not itemValue then
                debugPrint("数组中无效的数字格式")
                return nil, "JSON格式错误：数组中无效的数字格式"
              end
              arrayPos = e + 1

            -- 布尔值或null
            elseif arrayContent:sub(arrayPos, arrayPos + 3) == "true" then
              itemValue = true
              arrayPos = arrayPos + 4
            elseif arrayContent:sub(arrayPos, arrayPos + 4) == "false" then
              itemValue = false
              arrayPos = arrayPos + 5
            elseif arrayContent:sub(arrayPos, arrayPos + 3) == "null" then
              itemValue = nil
              arrayPos = arrayPos + 4

            -- 嵌套对象或数组 - 简化处理
            elseif arrayContent:sub(arrayPos, arrayPos) == "{" or arrayContent:sub(arrayPos, arrayPos) == "[" then
              local endChar = arrayContent:sub(arrayPos, arrayPos) == "{" and "}" or "]"
              local nestedLevel = 1
              local nestedStart = arrayPos
              itemEnd = nestedStart + 1

              while nestedLevel > 0 and itemEnd <= arrayLen do
                local char = arrayContent:sub(itemEnd, itemEnd)
                if char == "{" or char == "[" then
                  nestedLevel = nestedLevel + 1
                elseif char == "}" or char == "]" then
                  nestedLevel = nestedLevel - 1
                end
                itemEnd = itemEnd + 1
              end

              if nestedLevel > 0 then
                debugPrint("数组中嵌套元素没有结束符")
                return nil, "JSON格式错误：数组中嵌套元素没有结束符"
              end

              -- 简化处理，将嵌套对象或数组转换为空对象
              itemValue = {}
              arrayPos = itemEnd

            else
              local preview = arrayContent:sub(arrayPos, arrayPos+10)
              debugPrint("数组中未知元素类型，位置: " .. arrayPos .. ", 预览: " .. preview)
              return nil, "JSON格式错误：数组中未知元素类型"
            end

            -- 添加到数组
            value[itemIndex] = itemValue
            itemIndex = itemIndex + 1

            -- 跳过元素后的空白
            s, e = arrayContent:find("^%s*", arrayPos)
            arrayPos = e + 1

            -- 检查是否有更多元素
            if arrayPos <= arrayLen then
              if arrayContent:sub(arrayPos, arrayPos) == "," then
                arrayPos = arrayPos + 1
              else
                local preview = arrayContent:sub(arrayPos, arrayPos+10)
                debugPrint("数组元素之间缺少逗号，位置: " .. arrayPos .. ", 预览: " .. preview)
                return nil, "JSON格式错误：数组元素之间缺少逗号"
              end
            end
          end
        end

        pos = valueEnd
        debugPrint("数组解析完成，键名: " .. key .. ", 元素数量: " .. #value)

      else
        local preview = content:sub(pos, pos+10)
        debugPrint("无法识别的值类型，键名: " .. key .. ", 位置: " .. pos .. ", 预览: " .. preview)
        return nil, "JSON格式错误：无法识别的值类型，键名: " .. key .. ", 位置: " .. pos
      end

      -- 将解析的键值对加入结果表
      obj[key] = value

      -- 跳过值后的空白
      s, e = content:find("^%s*", pos)
      pos = e + 1
      if pos > len then break end

      -- 检查是否有更多键值对
      if content:sub(pos, pos) == "," then
        pos = pos + 1
      else
        break
      end
    end

    debugPrint("对象解析完成，键值对数量: " .. tableCount(obj))
    return obj
  end

  -- 开始解析
  result, errorMsg = parseObject(jsonContent)

  if result then
    print("JSON解析成功，键值对数量: " .. tableCount(result))
  else
    print("JSON解析失败: " .. tostring(errorMsg))
  end

  return result, errorMsg
end

-- 辅助函数：计算表中的键值对数量
function tableCount(t)
  local count = 0
  if type(t) == "table" then
    for _ in pairs(t) do count = count + 1 end
  end
  return count
end

-- 安全简单的JSON序列化函数
function serializeToJson(tbl, visited)
  -- 处理循环引用
  visited = visited or {}

  if type(tbl) ~= "table" then
    if type(tbl) == "string" then
      -- 转义字符串中的特殊字符
      local escaped = tbl:gsub('"', '\\"'):gsub("\\", "\\\\"):gsub("\n", "\\n"):gsub("\r", "\\r"):gsub("\t", "\\t")
      return '"' .. escaped .. '"'
    elseif type(tbl) == "number" or type(tbl) == "boolean" then
      return tostring(tbl)
    elseif tbl == nil then
      return "null"
    else
      return '"' .. tostring(tbl) .. '"'
    end
  end

  -- 检查循环引用
  if visited[tbl] then
    return '"[循环引用]"'
  end
  visited[tbl] = true

  -- 判断是否为数组
  local isArray = true
  local maxIndex = 0

  -- 检查是否是连续的数字索引
  for k, _ in pairs(tbl) do
    if type(k) ~= "number" or k <= 0 or math.floor(k) ~= k then
      isArray = false
      break
    end
    maxIndex = math.max(maxIndex, k)
  end

  -- 检查是否有空洞
  if maxIndex > #tbl * 1.5 then
    isArray = false
  end

  -- 处理表
  local result = isArray and "[" or "{"
  local first = true

  -- 数组部分
  if isArray then
    for i = 1, #tbl do
      if not first then result = result .. "," end
      first = false
      local v = tbl[i]
      if v == nil then
        result = result .. "null"
      else
        result = result .. serializeToJson(v, visited)
      end
    end
    result = result .. "]"
    return result
  end

  -- 表部分
  for k, v in pairs(tbl) do
    -- 跳过方法和特殊字段
    if type(v) ~= "function" and k ~= "__index" and k ~= "__newindex" then
      if not first then result = result .. "," end
      first = false

      if type(k) == "string" then
        -- 转义键名
        local escapedKey = k:gsub('"', '\\"'):gsub("\\", "\\\\"):gsub("\n", "\\n")
        result = result .. '"' .. escapedKey .. '":'
      else
        result = result .. '"' .. tostring(k) .. '":'
      end

      -- 处理特殊类型
      if v == nil then
        result = result .. "null"
      elseif type(v) == "function" then
        result = result .. '"[函数]"'
      elseif type(v) == "userdata" then
        result = result .. '"[用户数据]"'
      else
        result = result .. serializeToJson(v, visited)
      end
    end
  end
  result = result .. "}"
  return result
end

-- 内存读取处理函数
function SocketAPI.PacketHandler.handleMemoryRead(client, data)
  print("开始处理内存读取请求")

  -- 解析请求数据
  local request, parseError = parseJSON(data)
  if not request then
    return SocketAPI.PacketHandler.handleError(client, "JSON解析错误: " .. tostring(parseError))
  end

  -- 验证必要参数
  if not request.address then
    return SocketAPI.PacketHandler.handleError(client, "缺少address参数")
  end

  if not request.dataType then
    return SocketAPI.PacketHandler.handleError(client, "缺少dataType参数")
  end

  print("请求详情:")
  print("- 地址: " .. tostring(request.address))
  print("- 数据类型: " .. tostring(request.dataType))

  -- 处理选项
  local options = request.options or {}

  -- 输出高级选项调试信息
  print("高级选项详情:")
  for k, v in pairs(options) do
    print("  - " .. k .. ": " .. tostring(v))
  end

  -- 调用MemoryAPI读取内存
  local result = MemoryAPI.ReadMemoryEx(request.address, request.dataType, options)

  -- 如果读取成功，返回结果
  if result.success then
    print("内存读取成功，值: " .. tostring(result.value))
    return sendJsonResponse(client, result)
  else
    -- 如果读取失败，仍然返回附加信息，但添加错误消息
    print("内存读取失败: " .. tostring(result.error))
    return sendJsonResponse(client, result)
  end
end

-- 内存写入处理函数
function SocketAPI.PacketHandler.handleMemoryWrite(client, data)
  print("开始处理内存写入请求")

  -- 解析请求数据
  local request, parseError = parseJSON(data)
  if not request then
    return SocketAPI.PacketHandler.handleError(client, "JSON解析错误: " .. tostring(parseError))
  end

  -- 验证必要参数
  if not request.address then
    return SocketAPI.PacketHandler.handleError(client, "缺少address参数")
  end

  if request.value == nil then
    return SocketAPI.PacketHandler.handleError(client, "缺少value参数")
  end

  if not request.dataType then
    return SocketAPI.PacketHandler.handleError(client, "缺少dataType参数")
  end

  print("请求详情:")
  print("- 地址: " .. tostring(request.address))
  print("- 数据类型: " .. tostring(request.dataType))
  print("- 值: " .. tostring(request.value))

  -- 处理选项
  local options = request.options or {}

  -- 调用MemoryAPI写入内存
  local result = MemoryAPI.WriteMemoryEx(request.address, request.value, request.dataType, options)

  -- 返回结果
  return sendJsonResponse(client, result)
end

-- 批量内存读取处理函数
function SocketAPI.PacketHandler.handleMemoryBatch(client, data)
  print("开始处理批量内存读取请求")

  -- 解析请求数据
  local request, parseError = parseJSON(data)

  if not request then
    return SocketAPI.PacketHandler.handleError(client, "JSON解析错误: " .. tostring(parseError))
  end

  -- 验证必要参数
  if not request.addresses then
    return SocketAPI.PacketHandler.handleError(client, "缺少addresses参数")
  end

  if not request.dataType then
    return SocketAPI.PacketHandler.handleError(client, "缺少dataType参数")
  end

  if type(request.addresses) ~= "table" then
    return SocketAPI.PacketHandler.handleError(client, "addresses参数必须是数组")
  end

  -- 设置高级读取选项
  local options = request.options or {}

  -- 调用MemoryAPI批量读取内存
  print("调用BatchReadMemory: 地址数量=" .. tableCount(request.addresses))
  print("高级选项: "
        .. (options.rawBytes and "包含字节码 " or "")
        .. (options.assembly and "包含汇编 " or "")
        .. (options.opcode and "包含操作码 " or "")
        .. (options.comments and "包含注释 " or "")
        .. (options.multiType and "包含多类型解释 " or ""))

  local results = MemoryAPI.BatchReadMemory(request.addresses, request.dataType, options)

  -- 创建响应
  local response = {
    success = true,
    dataType = request.dataType,
    results = results
  }

  -- 将响应序列化为JSON格式
  return sendJsonResponse(client, response)
end

-- Lua代码执行处理函数
function SocketAPI.PacketHandler.handleLuaExec(client, data)
  print("开始处理Lua代码执行请求")

  -- 解析请求数据
  local request, parseError = parseJSON(data)

  if not request then
    return SocketAPI.PacketHandler.handleError(client, "JSON解析错误: " .. tostring(parseError))
  end

  -- 验证必要参数
  if not request.code then
    return SocketAPI.PacketHandler.handleError(client, "缺少code参数")
  end

  print("准备执行Lua代码，代码长度：" .. #request.code)

  -- 准备捕获输出
  local originalPrint = print
  local outputs = {}
  local results = {}

  -- 重写print函数以捕获输出
  _G.print = function(...)
    local args = {...}
    local output = ""
    for i, v in ipairs(args) do
      if i > 1 then output = output .. "\t" end
      output = output .. tostring(v)
    end
    table.insert(outputs, output)
    originalPrint("Lua执行输出: " .. output)
  end

  -- 准备安全环境
  local sandbox = {}

  -- 添加基本函数
  for k, v in pairs(_G) do
    -- 只复制安全的函数/变量
    if type(v) == "function" or
       type(v) == "table" or
       type(v) == "userdata" or
       type(v) == "boolean" or
       type(v) == "number" or
       type(v) == "string" then
      sandbox[k] = v
    end
  end

  -- 添加Cheat Engine特定的函数
  if readInteger then sandbox.readInteger = readInteger end
  if readFloat then sandbox.readFloat = readFloat end
  if readDouble then sandbox.readDouble = readDouble end
  if readString then sandbox.readString = readString end
  if readBytes then sandbox.readBytes = readBytes end
  if writeInteger then sandbox.writeInteger = writeInteger end
  if writeFloat then sandbox.writeFloat = writeFloat end
  if writeDouble then sandbox.writeDouble = writeDouble end
  if writeString then sandbox.writeString = writeString end
  if writeBytes then sandbox.writeBytes = writeBytes end
  if getAddress then sandbox.getAddress = getAddress end
  if getAddressSafe then sandbox.getAddressSafe = getAddressSafe end
  if getNameFromAddress then sandbox.getNameFromAddress = getNameFromAddress end
  if disassemble then sandbox.disassemble = disassemble end
  if getComment then sandbox.getComment = getComment end

  -- 添加CE的MemoryAPI和SocketAPI(只读)
  sandbox.MemoryAPI = MemoryAPI

  -- 不允许访问SocketAPI.Manager和敏感功能
  local safeSocketAPI = {}
  for k, v in pairs(SocketAPI) do
    if k ~= "Manager" and k ~= "API" then
      safeSocketAPI[k] = v
    end
  end
  sandbox.SocketAPI = safeSocketAPI

  -- 设置超时保护
  local timeoutMs = request.timeout or 5000 -- 默认5秒超时
  local startTime = os.clock() * 1000

  -- 添加超时保护钩子
  local function timeoutHook()
    if (os.clock() * 1000 - startTime) > timeoutMs then
      error("执行超时，已超过 " .. timeoutMs .. "ms", 2)
    end
  end
  debug.sethook(timeoutHook, "", 1000) -- 每执行1000条指令检查一次

  -- 定义返回值收集函数
  sandbox.returnResults = function(...)
    local args = {...}
    for i, v in ipairs(args) do
      results[i] = v
    end
  end

  -- 构建要执行的代码
  local execCode = request.code
  if request.captureReturn then
    if not execCode:find("returnResults") then
      -- 添加隐式返回值捕获
      execCode = execCode .. "\nreturnResults(" .. request.captureReturn .. ")"
    end
  end

  -- 执行代码
  local success, errorMsg

  -- 添加行号和函数包装，便于显示错误行号
  local wrappedCode = "local function __luaExecFunc()\n" .. execCode .. "\nend\n__luaExecFunc()"

  success, errorMsg = pcall(function()
    local fn, compileErr = load(wrappedCode, "LuaExec", "t", sandbox)
    if not fn then
      error("编译错误: " .. tostring(compileErr), 0)
    end
    return fn()
  end)

  -- 恢复原始print函数
  _G.print = originalPrint

  -- 清除钩子
  debug.sethook()

  -- 处理执行结果
  print("Lua代码执行完成, 成功状态: " .. tostring(success))

  -- 创建响应对象
  local response = {
    success = success,
    error = not success and tostring(errorMsg) or nil,
    output = outputs,
    returnValues = results,
    executionTime = os.clock() * 1000 - startTime
  }

  -- 将响应序列化为JSON格式
  return sendJsonResponse(client, response)
end

-- 添加汇编代码修改处理函数
function SocketAPI.PacketHandler.handleAssemblyWrite(client, data)
  print("开始处理汇编代码修改请求")

  -- 解析请求数据
  local request, parseError = parseJSON(data)
  if not request then
    return SocketAPI.PacketHandler.handleError(client, "JSON解析错误: " .. tostring(parseError))
  end

  -- 验证必要参数
  if not request.address then
    return SocketAPI.PacketHandler.handleError(client, "缺少address参数")
  end

  if not request.assembly then
    return SocketAPI.PacketHandler.handleError(client, "缺少assembly参数")
  end

  print("请求详情:")
  print("- 地址: " .. tostring(request.address))
  print("- 汇编代码: " .. tostring(request.assembly))

  -- 尝试组装汇编代码
  local result = {
    address = request.address,
    success = false,
    error = nil,
    bytesWritten = 0
  }

  -- 确保格式化地址
  local formattedAddress
  local status, err = pcall(function()
    formattedAddress = MemoryAPI.Utils.formatAddress(request.address)
  end)

  if not status then
    result.error = "地址格式化错误: " .. tostring(err)
    return sendJsonResponse(client, result)
  end

  result.address = string.format("0x%X", formattedAddress)

  -- 使用autoAssemble函数组装汇编代码（如果存在）
  if autoAssemble then
    -- 准备自动组装脚本
    local script = string.format([[
define(address, %X)

address:
%s
]], formattedAddress, request.assembly)

    -- 如果有额外选项
    if request.options then
      if request.options.registerState then
        script = "alloc\n" .. script  -- 在注入的代码前添加分配内存指令
      end
    end

    print("自动组装脚本:\n" .. script)

    -- 执行自动组装
    local success, assembleResult = pcall(autoAssemble, script)

    if success and assembleResult then
      result.success = true
      result.bytesWritten = 1  -- 实际写入的字节数取决于汇编代码
      print("汇编代码修改成功")
    else
      result.success = false
      result.error = "汇编代码修改失败: " .. tostring(assembleResult)
      print("汇编代码修改失败: " .. tostring(assembleResult))
    end
  else
    -- 如果不存在autoAssemble函数，尝试使用AA_AssembleCode（CE 7.0+）
    if AA_AssembleCode then
      local bytes, byteCount = AA_AssembleCode(formattedAddress, request.assembly)

      if bytes and byteCount > 0 then
        -- 写入汇编产生的机器码
        local writeSuccess = writeBytes(formattedAddress, bytes, byteCount)

        if writeSuccess then
          result.success = true
          result.bytesWritten = byteCount
          print("汇编代码修改成功，写入 " .. byteCount .. " 字节")
        else
          result.success = false
          result.error = "无法写入组装后的机器码"
          print("无法写入组装后的机器码")
        end
      else
        result.success = false
        result.error = "汇编代码组装失败"
        print("汇编代码组装失败")
      end
    else
      result.success = false
      result.error = "当前环境不支持汇编代码修改功能"
      print("当前环境不支持汇编代码修改功能")
    end
  end

  -- 返回结果
  return sendJsonResponse(client, result)
end

-- 在内存写入处理函数中应用增强的WriteMemoryEx
function SocketAPI.PacketHandler.handleMemoryWrite(client, data)
  print("开始处理内存写入请求")

  -- 解析请求数据
  local request, parseError = parseJSON(data)
  if not request then
    return SocketAPI.PacketHandler.handleError(client, "JSON解析错误: " .. tostring(parseError))
  end

  -- 验证必要参数
  if not request.address then
    return SocketAPI.PacketHandler.handleError(client, "缺少address参数")
  end

  if request.value == nil then
    return SocketAPI.PacketHandler.handleError(client, "缺少value参数")
  end

  if not request.dataType then
    return SocketAPI.PacketHandler.handleError(client, "缺少dataType参数")
  end

  print("请求详情:")
  print("- 地址: " .. tostring(request.address))
  print("- 数据类型: " .. tostring(request.dataType))
  print("- 值: " .. tostring(request.value))

  -- 处理选项
  local options = request.options or {}

  -- 调用MemoryAPI写入内存
  local result = MemoryAPI.WriteMemoryEx(request.address, request.value, request.dataType, options)

  -- 返回结果
  return sendJsonResponse(client, result)
end

-- 在内存写入处理函数中应用增强的WriteMemoryEx
function SocketAPI.PacketHandler.handleMemoryWrite(client, data)
  print("开始处理内存写入请求")

  -- 解析请求数据
  local request, parseError = parseJSON(data)
  if not request then
    return SocketAPI.PacketHandler.handleError(client, "JSON解析错误: " .. tostring(parseError))
  end

  -- 验证必要参数
  if not request.address then
    return SocketAPI.PacketHandler.handleError(client, "缺少address参数")
  end

  if request.value == nil then
    return SocketAPI.PacketHandler.handleError(client, "缺少value参数")
  end

  if not request.dataType then
    return SocketAPI.PacketHandler.handleError(client, "缺少dataType参数")
  end

  print("请求详情:")
  print("- 地址: " .. tostring(request.address))
  print("- 数据类型: " .. tostring(request.dataType))
  print("- 值: " .. tostring(request.value))

  -- 处理选项
  local options = request.options or {}

  -- 调用MemoryAPI写入内存
  local result = MemoryAPI.WriteMemoryEx(request.address, request.value, request.dataType, options)

  -- 返回结果
  return sendJsonResponse(client, result)
end

-- 服务器自动启动
local function autoStartServer()
  SocketAPI.Utils.log("正在自动启动服务器...")
  SocketAPI.API.init()

  if SocketAPI.API.startServer() then
    SocketAPI.Utils.log("服务器启动成功，端口: " .. SocketAPI.PORT)

    -- 注册定时器持续执行服务循环
    if createTimer then
      -- Cheat Engine环境中使用createTimer
      local timer = createTimer(nil)
      timer.Interval = 250 -- 修改为250毫秒执行一次
      timer.OnTimer = function()
        -- 添加错误处理，防止崩溃
        local status, result = pcall(function()
          return SocketAPI.API.serverLoop()
        end)

        if not status then
          SocketAPI.Utils.log("服务循环执行错误: " .. tostring(result), "ERROR")
        elseif not result then
          -- 服务器已停止，销毁定时器
          timer.destroy()
        end
      end
    else
      -- 普通Lua环境，提示用户需要手动调用serverLoop
      SocketAPI.Utils.log("请在主循环中调用SocketAPI.API.serverLoop()")
    end
  end
end

-- 在Cheat Engine中执行自动启动
if executeCodeEx then
  SocketAPI.Utils.log("在Cheat Engine环境中执行")
  autoStartServer()
else
  SocketAPI.Utils.log("在标准Lua环境中执行")
  autoStartServer()
end

-- JSON响应处理函数
function sendJsonResponse(client, result)
  -- 确保result是一个表格
  if type(result) ~= "table" then
    result = {
      success = false,
      error = "返回结果不是有效的表格格式",
      originalResult = tostring(result)
    }
  end

  -- 深度清理，处理特殊字段
  local function cleanTable(t, depth)
    if depth > 20 then  -- 限制递归深度
      return "[嵌套过深]"
    end

    local cleaned = {}
    for k, v in pairs(t) do
      -- 跳过内部字段
      if k ~= "__index" and k ~= "__newindex" and type(v) ~= "function" and type(v) ~= "userdata" then
        if type(v) == "table" then
          cleaned[k] = cleanTable(v, depth + 1)
        else
          cleaned[k] = v
        end
      end
    end
    return cleaned
  end

  -- 清理结果对象
  local cleanResult = cleanTable(result, 0)

  -- 尝试序列化为JSON
  local success, responseJson = pcall(function()
    return serializeToJson(cleanResult)
  end)

  if not success then
    print("JSON序列化失败: " .. tostring(responseJson))
    -- 失败时尝试一个更简单的结果
    local simpleResult = {
      success = result.success or false,
      address = result.address,
      dataType = result.dataType,
      value = result.value,
      error = result.error or "复杂结果序列化失败: " .. tostring(responseJson)
    }

    success, responseJson = pcall(function()
      return serializeToJson(simpleResult)
    end)

    if not success then
      return SocketAPI.PacketHandler.handleError(client, "JSON序列化失败，无法生成简化结果")
    end
  end

  -- 检查JSON是否有效
  if not responseJson or responseJson == "" then
    print("生成的JSON为空")
    return SocketAPI.PacketHandler.handleError(client, "生成的JSON为空")
  end

  local packedResponse = SocketAPI.PacketHandler.packResponse(responseJson)
  print("JSON响应长度: " .. #packedResponse)

  return packedResponse
end

-- 处理枚举模块请求
function SocketAPI.PacketHandler.handleEnumModules(self, data, clientId)
  print("===== 开始处理枚举模块请求 =====")
  print("---------- 开始枚举模块 ----------")
  local client = self.clients[clientId].socket

  -- 解析请求参数
  local requestData = {}
  if data and #data > 0 then
    local success, parsed = pcall(function() return parseJSON(data) end)
    if success and parsed then
      requestData = parsed
    else
      print("解析参数失败，将使用默认值")
    end
  end

  -- 获取当前打开的进程ID
  local pid = getOpenedProcessID()
  if pid == 0 then
    print("未打开任何进程")
    return sendJsonResponse(client, {
      success = false,
      error = "未打开任何进程，请先附加到目标进程"
    })
  end

  print("当前进程ID: " .. pid)

  -- 创建一个表来存储DLL信息
  local dllList = {}

  -- 枚举模块并填充DLL列表
  local moduleList = enumModules()
  if not moduleList then
    return sendJsonResponse(client, {
      success = false,
      error = "模块枚举失败，CE可能无法访问进程模块列表"
    })
  end

  print("找到 " .. #moduleList .. " 个模块")

  -- 获取包含路径的选项
  local includePath = false  -- 默认为false，不包含路径
  if requestData.options and requestData.options.includePath ~= nil then
    includePath = requestData.options.includePath
  end

  -- 获取只包含DLL的选项
  local onlyDLL = false
  if requestData.options and requestData.options.onlyDLL ~= nil then
    onlyDLL = requestData.options.onlyDLL
  end

  -- 处理模块列表
  for i, module in ipairs(moduleList) do
    local isModule = true

    -- 如果只包含DLL，则跳过非DLL模块
    if onlyDLL then
      -- 添加非空检查，避免nil值引用
      if not module.PathToFile then
        isModule = false
        print("警告: 模块 #" .. i .. " 缺少PathToFile属性")
      elseif not module.PathToFile:lower():match("%.dll$") then
        isModule = false
      end
    end

    if isModule then
      local moduleInfo = {
        name = module.Name or "未知模块",
        baseAddress = string.format("0x%X", module.Address or 0),
        size = module.Size or 0
      }

      -- 如果包含路径，添加路径信息
      if includePath and module.PathToFile then
        moduleInfo.path = module.PathToFile
      end

      table.insert(dllList, moduleInfo)
    end
  end

  -- 按名称排序
  table.sort(dllList, function(a, b) return a.name:lower() < b.name:lower() end)

  -- 构建结果
  local response = {
    success = true,
    processID = pid,
    processName = getProcesslist()[pid] or "Unknown",
    totalModules = #dllList,
    modules = dllList
  }

  print("返回模块数量: " .. #dllList)
  print("===== 枚举模块请求处理完成 =====")

  return sendJsonResponse(client, response)
end

-- 处理指针扫描请求
function SocketAPI.PacketHandler.handlePointerScan(self, data, clientId)
  print("===== 开始处理指针扫描请求 =====")
  local client = self.clients[clientId].socket

  -- 解析请求参数
  local requestData = {}
  if data and #data > 0 then
    local success, parsed = pcall(function() return parseJSON(data) end)
    if success and parsed then
      requestData = parsed
    else
      print("解析参数失败: " .. tostring(parsed))
      return sendJsonResponse(client, {
        success = false,
        error = "无效的请求参数: " .. tostring(parsed)
      })
    end
  else
    return sendJsonResponse(client, {
      success = false,
      error = "缺少请求参数"
    })
  end

  -- 验证请求参数
  if not requestData.address then
    return sendJsonResponse(client, {
      success = false,
      error = "缺少必要参数: address"
    })
  end

  -- 格式化地址
  local targetAddress
  local status, err = pcall(function()
    targetAddress = MemoryAPI.Utils.formatAddress(requestData.address)
  end)

  if not status then
    print("地址格式化错误: " .. tostring(err))
    return sendJsonResponse(client, {
      success = false,
      error = "无效的地址格式: " .. tostring(err)
    })
  end

  print("目标地址: 0x" .. string.format("%X", targetAddress))

  -- 获取可选参数
  local maxLevel = requestData.options and requestData.options.maxLevel or 3
  local maxResults = requestData.options and requestData.options.maxResults or 10
  local moduleFilter = requestData.options and requestData.options.moduleFilter or nil

  -- 验证参数范围
  maxLevel = math.min(math.max(1, maxLevel), 5) -- 限制范围1-5
  maxResults = math.min(math.max(1, maxResults), 30) -- 限制范围1-30

  print("指针参数: 最大级别=" .. maxLevel .. ", 最大结果数=" .. maxResults)
  if moduleFilter then print("模块过滤: " .. moduleFilter) end

  -- 创建结果表
  local pointerResults = {}
  local resultCount = 0

  -- 获取所有模块
  local moduleList = enumModules()
  if not moduleList then
    return sendJsonResponse(client, {
      success = false,
      error = "无法枚举进程模块"
    })
  end

  -- 过滤模块
  local filteredModules = {}
  for i, module in ipairs(moduleList) do
    if not moduleFilter or module.Name:lower():find(moduleFilter:lower()) then
      table.insert(filteredModules, module)
    end
  end

  print("模块总数: " .. #moduleList .. ", 过滤后: " .. #filteredModules)

  -- 找出目标所在模块
  local targetModule = nil
  for i, module in ipairs(moduleList) do
    if targetAddress >= module.Address and targetAddress < (module.Address + module.Size) then
      targetModule = module
      break
    end
  end

  -- 计算目标相对偏移
  local targetOffset = nil
  if targetModule then
    targetOffset = targetAddress - targetModule.Address
    print("目标模块: " .. targetModule.Name)
    print("相对偏移: 0x" .. string.format("%X", targetOffset))
  else
    print("目标地址不在任何模块中")
  end

  -- 简单指针搜索
  -- 为了演示，仅实现基本功能，实际需要更复杂的指针扫描算法

  -- 添加一级指针结果
  if targetModule then
    table.insert(pointerResults, {
      baseModule = targetModule.Name,
      baseAddress = string.format("0x%X", targetModule.Address),
      offsetsText = string.format("+0x%X", targetOffset),
      offsets = {targetOffset},
      level = 1,
      resolvedAddress = string.format("0x%X", targetAddress)
    })
    resultCount = resultCount + 1
  end

  -- 添加直接引用结果
  local memoryValue = readInteger(targetAddress)
  if memoryValue then
    print("内存值: 0x" .. string.format("%X", memoryValue))

    for i, module in ipairs(filteredModules) do
      if resultCount >= maxResults then break end

      -- 简化搜索，实际应使用更高效的扫描方法
      local searchAddresses = {
        module.Address,            -- 模块开始
        module.Address + 0x1000,   -- 模块+0x1000
        module.Address + 0x10000   -- 模块+0x10000
      }

      for _, searchAddr in ipairs(searchAddresses) do
        if resultCount >= maxResults then break end

        local status, value = pcall(function() return readInteger(searchAddr) end)
        if status and value then
          -- 检查是否指向目标附近
          local diff = math.abs(value - targetAddress)
          if diff < 0x1000 then  -- 如果指向目标附近
            local offset = targetAddress - value
            table.insert(pointerResults, {
              baseModule = module.Name,
              baseAddress = string.format("0x%X", module.Address),
              pointerAddress = string.format("0x%X", searchAddr),
              pointerOffset = string.format("0x%X", searchAddr - module.Address),
              offsetsText = string.format("[0x%X]+0x%X", searchAddr, offset),
              offsets = {offset},
              level = 1,
              resolvedAddress = string.format("0x%X", targetAddress)
            })
            resultCount = resultCount + 1
          end
        end
      end
    end
  end

  -- 如果没有找到指针，添加硬编码地址结果
  if #pointerResults == 0 then
    table.insert(pointerResults, {
      baseModule = "硬编码地址",
      baseAddress = string.format("0x%X", targetAddress),
      offsetsText = "",
      offsets = {},
      level = 0,
      resolvedAddress = string.format("0x%X", targetAddress)
    })
  end

  -- 构建响应
  local response = {
    success = true,
    targetAddress = string.format("0x%X", targetAddress),
    targetModuleName = targetModule and targetModule.Name or "Unknown",
    targetModuleOffset = targetOffset and string.format("0x%X", targetOffset) or nil,
    pointers = pointerResults,
    totalResults = #pointerResults
  }

  print("返回指针数量: " .. #pointerResults)
  print("===== 指针扫描请求处理完成 =====")

  return sendJsonResponse(client, response)
end

-- 处理模块偏移指针读取请求
function SocketAPI.PacketHandler.handlePointerRead(self, data, clientId)
  print("===== 开始处理模块偏移指针读取请求 =====")
  local client = self.clients[clientId].socket

  -- 解析请求参数
  local requestData = {}
  if data and #data > 0 then
    local success, parsed = pcall(function() return parseJSON(data) end)
    if success and parsed then
      requestData = parsed
    else
      print("解析参数失败: " .. tostring(parsed))
      return sendJsonResponse(client, {
        success = false,
        error = "无效的请求参数: " .. tostring(parsed)
      })
    end
  else
    return sendJsonResponse(client, {
      success = false,
      error = "缺少请求参数"
    })
  end

  -- 验证请求参数
  if not requestData.pointerPath then
    return sendJsonResponse(client, {
      success = false,
      error = "缺少必要参数: pointerPath"
    })
  end

  -- 解析指针路径
  local pointerPath = requestData.pointerPath
  print("指针路径: " .. pointerPath)

  -- 支持的格式:
  -- 1. "模块名称+偏移" 如 "kernel32.dll+0x1234"
  -- 2. "模块名称+偏移,偏移2,偏移3..." 如 "kernel32.dll+0x1234,0x8,0x4"

  -- 分割模块名和偏移
  local moduleName, offsets = nil, {}

  -- 查找模块名和第一个偏移
  local modulePart, offsetsPart = pointerPath:match("([^%+]+)%+(.+)")
  if not modulePart or not offsetsPart then
    return sendJsonResponse(client, {
      success = false,
      error = "无效的指针路径格式，应为'模块名+偏移'"
    })
  end

  moduleName = modulePart:gsub("%s+", "")  -- 移除空格

  -- 解析所有偏移（支持多级偏移，用逗号分隔）
  local firstOffset = true
  for offsetStr in offsetsPart:gmatch("[^,]+") do
    local offset = offsetStr:gsub("%s+", "")  -- 移除空格

    -- 处理十六进制或十进制
    local value = nil
    if firstOffset then
      -- 第一个偏移处理方式不变
      if offset:match("^0x") or offset:match("^0X") then
        -- 有显式0x前缀的十六进制
        value = tonumber(offset:sub(3), 16)
      elseif offset:match("[a-fA-F]") then
        -- 包含a-f字母的隐式十六进制
        value = tonumber(offset, 16)
      else
        -- 纯数字优先按十进制处理
        value = tonumber(offset, 10)
      end
      firstOffset = false
    else
      -- 后续偏移（逗号后的值）始终按十六进制处理
      if offset:match("^0x") or offset:match("^0X") then
        value = tonumber(offset:sub(3), 16)
      else
        -- 没有0x前缀，但仍按十六进制处理
        value = tonumber(offset, 16)
      end
    end

    if not value then
      return sendJsonResponse(client, {
        success = false,
        error = "无效的偏移值: " .. offset
      })
    end

    table.insert(offsets, value)
  end

  print("模块名: " .. moduleName)
  print("偏移数量: " .. #offsets)
  for i, offset in ipairs(offsets) do
    print("偏移 #" .. i .. ": 0x" .. string.format("%X", offset))
  end

  -- 获取数据类型
  local dataType = requestData.dataType or "int32"
  print("数据类型: " .. dataType)

  -- 验证数据类型
  local dataTypeInfo = MemoryAPI.DATA_TYPES[dataType]
  if not dataTypeInfo then
    return sendJsonResponse(client, {
      success = false,
      error = "无效的数据类型: " .. dataType
    })
  end

  -- 获取模块列表
  local moduleList = enumModules()
  if not moduleList then
    return sendJsonResponse(client, {
      success = false,
      error = "无法枚举进程模块"
    })
  end

  -- 查找指定模块
  local targetModule = nil
  for _, module in ipairs(moduleList) do
    if module.Name:lower() == moduleName:lower() then
      targetModule = module
      break
    end
  end

  if not targetModule then
    return sendJsonResponse(client, {
      success = false,
      error = "找不到指定的模块: " .. moduleName
    })
  end

  -- 计算基址
  local currentAddress = targetModule.Address + offsets[1]
  print("基址计算: " .. targetModule.Name .. " (0x" .. string.format("%X", targetModule.Address) .. ") + 0x" .. string.format("%X", offsets[1]) .. " = 0x" .. string.format("%X", currentAddress))

  -- 跟踪多级指针
  local resolvedValues = {}
  local resolvedAddresses = {}
  table.insert(resolvedAddresses, string.format("0x%X", currentAddress))

  local finalValue = nil
  local success = true

  -- 如果有多级偏移，逐级解析
  if #offsets > 1 then
    for i = 2, #offsets do
      -- 读取当前地址的指针值
      local status, value = pcall(function() return readInteger(currentAddress) end)

      -- 记录解析过程
      if status and value then
        table.insert(resolvedValues, string.format("0x%X", value))
        currentAddress = value + offsets[i]
        table.insert(resolvedAddresses, string.format("0x%X", currentAddress))
        print("解析 #" .. (i-1) .. ": 0x" .. string.format("%X", value) .. " + 0x" .. string.format("%X", offsets[i]) .. " = 0x" .. string.format("%X", currentAddress))
      else
        success = false
        print("指针解析失败: 无法读取地址 0x" .. string.format("%X", currentAddress))
        break
      end
    end
  end

  -- 最终地址
  local finalAddress = currentAddress
  print("最终地址: 0x" .. string.format("%X", finalAddress))

  -- 读取最终地址的值
  local value = nil
  local readSuccess = false

  if success then
    -- 读取最终值
    local status, readResult = pcall(function()
      if dataType == "string" then
        return readString(finalAddress)
      elseif dataType == "wstring" then
        return readWideString(finalAddress)
      elseif dataType == "bytes" then
        local count = requestData.options and requestData.options.bytesSize or 4
        return readBytes(finalAddress, count)
      elseif dataType == "float" then
        return readFloat(finalAddress)
      elseif dataType == "double" then
        return readDouble(finalAddress)
      elseif dataType == "int8" then
        return readByte(finalAddress)
      elseif dataType == "int16" then
        return readSmallInteger(finalAddress)
      elseif dataType == "int32" then
        return readInteger(finalAddress)
      elseif dataType == "int64" then
        return readQword(finalAddress)
      elseif dataType == "uint8" then
        return readByte(finalAddress)
      elseif dataType == "uint16" then
        return readSmallInteger(finalAddress)
      elseif dataType == "uint32" then
        return readInteger(finalAddress)
      elseif dataType == "uint64" then
        return readQword(finalAddress)
      else
        error("不支持的数据类型: " .. dataType)
      end
    end)

    if status then
      value = readResult
      readSuccess = true
      print("读取值: " .. tostring(value))
    else
      print("读取值失败: " .. tostring(readResult))
    end
  end

  -- 构建偏移字符串表示
  local offsetsStr = moduleName .. "+0x" .. string.format("%X", offsets[1])
  for i = 2, #offsets do
    -- 保留原始输入格式，对于纯数字保持十进制表示
    local offsetValue = offsets[i]
    local isPureDecimal = tonumber(tostring(offsetValue), 10) == offsetValue and
                         not tostring(offsetValue):match("[a-fA-F]")

    if isPureDecimal then
      -- 使用原始十进制格式
      offsetsStr = offsetsStr .. "," .. tostring(offsetValue)
    else
      -- 使用十六进制格式
      offsetsStr = offsetsStr .. ",0x" .. string.format("%X", offsetValue)
    end
  end
  
  -- 构建响应
  local response = {
    success = success and readSuccess,
    pointerPath = offsetsStr,
    dataType = dataType,
    baseModule = targetModule.Name,
    baseAddress = string.format("0x%X", targetModule.Address),
    offsets = offsets,
    resolvedAddresses = resolvedAddresses,
    resolvedValues = resolvedValues,
    finalAddress = string.format("0x%X", finalAddress),
    value = value,
    error = not (success and readSuccess) and "指针解析或读取失败" or nil
  }
  
  print("===== 模块偏移指针读取请求处理完成 =====")
  
  return sendJsonResponse(client, response)
end
