local cjson = require "cjson.safe"
local Multipart = require "multipart"

local utils = require "kong.tools.utils"
local BasePlugin = require "kong.plugins.base_plugin"
local responses = require "kong.tools.responses"
local config = require "kong.plugins.signature-auth.config"

local SignatureAuthHandler = BasePlugin:extend()

SignatureAuthHandler.PRIORITY = 1000

local SIGNATURE = "X-Signature"
local NONCE = "X-Signature-Nonce"
local TIMESTAMP = "X-Signature-Timestamp"
local ACCESS_KEI_ID = "X-Signature-AccessKeyId"

local CONTENT_TYPE = "content-type"
local TEN_MINUTES_IN_SECOND = 600

local SIGNATURE_NOT_CORRECT = '10030'
local SIGNATURE_TIMESTAMP_ILLEGAL = '10031'
local MISSING_PARAMS = '10032'



local function explode_version(str)
    local result = {}
    while true do
        local from, to = ngx.re.find(str, [[\.]])
        local item = string.sub(str, 0, to-1)
        table.insert(result, tonumber(item))

        str = string.gsub(str, item .. '.', "", 1)
        local from, to = ngx.re.find(str, [[\.]])
        if not from then
            table.insert(result, tonumber(str))
            break
        end
    end

    return result
end

local function version_compare(version1, version2)
    local v1 = explode_version(version1)
    local v2 = explode_version(version2)

    local v1Length = table.getn(v1)
    local v2Length = table.getn(v2)

    local minLen = math.min(v1Length, v2Length);

    local r = 0
    for i = 1, minLen do
        if v1[i] > v2[i] then
            r = 1
            break
        elseif v1[i] < v2[i] then
            r = -1
            break
        else
            r = 0
        end
    end
    if r == 0 then
        if v1Length > v2Length then
            r = 1
        elseif v1Length < v2Length then
            r = -1
        end
    end

    return r
end

local function urlencode(url)
    local newstr, n, err = ngx.re.gsub(url, "([^A-Za-z0-9\\-_.~])", function(m) return string.format("%%%02X", string.byte(m[0])) end)

    return newstr
end

local function retrieve_parameters()
    ngx.req.read_body()
    -- OAuth2 parameters could be in both the querystring or body
    local body_parameters, err
    local content_type = ngx.req.get_headers()[CONTENT_TYPE]
    if content_type and string.find(content_type:lower(), "multipart/form-data", nil, true) then
        body_parameters = {}
    elseif content_type and string.find(content_type:lower(), "application/json", nil, true) then
        body_parameters, err = cjson.decode(ngx.req.get_body_data())
        if err then body_parameters = {} end
    else
        body_parameters = ngx.req.get_post_args()
    end

    return utils.table_merge(ngx.req.get_uri_args(), body_parameters)
end

local function get_keys(params)
    local keys = {}

    for key in pairs(params) do
        if key then
            table.insert(keys, key)
        end
    end

    return keys
end

local function get_hmac_key(accessKeyId)
    local key = ''
    if config['appAccess'][accessKeyId] then
        key = config['appAccess'][accessKeyId]['secret']
    else
        -- 为空时给个默认key或者报错
        key = 'h376VqGHH5bi3lAc7MiUVWiAT8nLjtu5'
    end

    return key
end
local function allow_access()
    local headers = ngx.req.get_headers()
    local regex = [[(\.jpg|\.png|\.gif|\.js|\.css|\.ttf|\.woff|\.htm|\.htm|\.jsonp)$]]
    local m, err = ngx.re.match(string.lower(ngx.var.uri), regex)

    -- 版本大于等于5.3
    local isLessThanVersion53 = 0
    if headers['X-Release-Version'] and version_compare(headers['X-Release-Version'], '5.3') < 0 then
        isLessThanVersion53 = 1
    end

    return m or isLessThanVersion53
end

local function validate_timestamp(time)
    local serverTime = ngx.time()
    local subtractResult = serverTime - headers[TIMESTAMP]

    return subtractResult > TEN_MINUTES_IN_SECOND or subtractResult < -TEN_MINUTES_IN_SECOND
end

local function get_params()
    local params = retrieve_parameters() or {}

    local signatureParams = {}
    signatureParams[TIMESTAMP] = headers[TIMESTAMP]
    signatureParams[NONCE] = headers[NONCE]
    signatureParams[ACCESS_KEI_ID] = headers[ACCESS_KEI_ID]

    return utils.table_merge(params, signatureParams)
end

local function get_string_to_sign(params)
    local keys = get_keys(params)
    table.sort(keys)

    local paramStringToSign = ''
    for i, v in pairs(keys) do
        paramStringToSign = (paramStringToSign .. '&' .. urlencode(v) .. '=' .. urlencode(params[v]))

    end

    local stringToSign = ngx.var.request_method .. '&' .. urlencode(ngx.var.uri);
    paramStringToSign = ngx.re.gsub(paramStringToSign, "^&", "")
    return (stringToSign .. '&' .. urlencode(paramStringToSign))
end

local function do_signature(stringToSign)
    return urlencode(ngx.encode_base64(ngx.hmac_sha1(get_hmac_key(headers[ACCESS_KEI_ID]), stringToSign)))
end

local function do_authentication()
    local headers = ngx.req.get_headers()
    -- If both headers are missing, return 401
    if not (headers[SIGNATURE] and headers[NONCE] and headers[TIMESTAMP] and headers[ACCESS_KEI_ID]) then
        ngx.header['X-ErrorCode'] = MISSING_PARAMS
        ngx.log(ngx.ERROR, "[MISSING_PARAMS] client platform:" .. headers['X-Release-Platform'] .. ",uri:" .. ngx.var.uri)
        return false, MISSING_PARAMS
    end

    local timestamp_ok = validate_timestamp(headers[TIMESTAMP])
    if not timestamp_ok then
        ngx.header['X-ServerTime'] = ngx.time()
        ngx.header['X-ErrorCode'] = SIGNATURE_TIMESTAMP_ILLEGAL
        ngx.log(ngx.ERROR, "[SIGNATURE_TIMESTAMP_ILLEGAL] client timestamp:" .. headers[TIMESTAMP] ..  ",server timestamp:" .. ngx.time() .. ",client platform:" .. headers['X-Release-Platform'] .. ",uri:" .. ngx.var.uri)
        return false, SIGNATURE_TIMESTAMP_ILLEGAL
    end

    local params = get_params()
    local stringToSign = get_string_to_sign(params)
    local signature = do_signature(stringToSign)

    if signature == headers[SIGNATURE] then
        return true
    else
        ngx.log(ngx.ERROR, "[SIGNATURE_NOT_CORRECT] signature:" .. signature ..  ",stringToSign:" .. stringToSign)
        ngx.header['X-ErrorCode'] = SIGNATURE_NOT_CORRECT
        return false, SIGNATURE_NOT_CORRECT
    end
end

function SignatureAuthHandler:new()
    SignatureAuthHandler.super.new(self, "signature-auth")
end

function SignatureAuthHandler:access(conf)
    SignatureAuthHandler.super.access(self)
    local needsToCheck = allow_access()
    if not needsToCheck then
        local res, err = do_authentication(conf)
        ngx.log(ngx.DEBUG, "signature-auth finished")

        if not res then
            return responses.send(401)
        end
    end

end

return SignatureAuthHandler
