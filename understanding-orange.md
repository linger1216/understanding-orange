# 深入理解 Orange

[TOC]



## 前言

本文在分析`orange`是时候满足了以下**约束**, 请观众老爷们知晓.

* 为了格式美观, 在讲解代码的时候会酌情删减.
* 本文涉及到的[orange](https://github.com/sumory/orange)代码版本为v0.6.3
* [orange](https://github.com/sumory/orange)的**Api Server**部分, 以及**Dashboard**部分不涉及分析.
* 分析代码是以**basic\_auth**插件为例子来进行讲解
* [orange](https://github.com/sumory/orange)安装环境是mac, 网关端口是18888, 而不是默认的8888






## 安装

安装过程比较简单, 请参考[orange install]()

or

你也可以使用docker 安装, 下面简单说明下安装过程



**1. 首先创建mysql数据库**

你也可以选择你喜欢的mysql tag

```
docker run --name orange-database -e MYSQL_ROOT_PASSWORD=ur_pwd -p 3306:3306 -d mysql:5.7
```



**2. 连接mysql**

连接mysql后创建根据自己需要创建数据库, 用户, 并导入[orange table](https://raw.githubusercontent.com/sumory/orange/master/install/orange-v0.6.0.sql).




**3. 创建orange**

```
docker run -d --name orange \
    --link orange-database:orange-database \
    -p 7777:7777 \
    -p 8888:8888 \
    -p 9999:9999 \
    --security-opt seccomp:unconfined \
    -e ORANGE_DATABASE=ur_db \
    -e ORANGE_HOST=orange-database \
    -e ORANGE_PORT=3306 \
    -e ORANGE_USER=ur_user \
    -e ORANGE_PWD=ur_pwd \
    syhily/orange
```






## 一. 需要了解的概念



### 1.1 orange缓存



`nginx.conf`

```
lua_shared_dict orange_data 20m; # should not removed. used for orange data, e.g. plugins configurations..

lua_shared_dict status 1m; # used for global statistic, see plugin: stat
lua_shared_dict waf_status 1m; # used for waf statistic, see plugin: waf
lua_shared_dict monitor 10m; # used for url monitor statistic, see plugin: monitor
lua_shared_dict rate_limit 10m; # used for rate limiting count, see plugin: rate_limiting
lua_shared_dict property_rate_limiting 10m; # used for rate limiting count, see plugin: rate_limiting
```



这玩意主要为了`orange`在运行期间的效率, 内存肯定比io快, 毕竟网关不能有耗时操作.

以`orange_db`为例子, 在`orange`运行期间会从mysql数据库读取相关配置, 并保存在orange cache中, 详细可见`store/orange_db.lua`文件





### 1.2 store

打开store文件夹, 会发现如下文件

```
.
├── base.lua
├── dao.lua
├── mysql_db.lua
├── mysql_store.lua
└── orange_db.lua
```



光看dao,mysql,db的字样也能大概了解是负责数据读取等的工作

以`mysql_store`为例, MySQLStore只是一个封装, `mysql_db`才是真正的执行mysql语句的类





### 1.3 Object

据作者说, 这一块包括插件主要参考的是[kong](https://getkong.org/), 参考谁我也不管了, 反正学啥都是学.



这是`orange`最底层的类, 实现也没什么, 就一普通父类, 加了`super`等字段属性, 另外还实现了`tostring`元方法, `call`元方法:

```
local Object = {}
Object.__index = Object

function Object:extend()
  local cls = {}
  for k, v in pairs(self) do
    if k:find("__") == 1 then
      cls[k] = v
    end
  end
  cls.__index = cls
  cls.super = self
  setmetatable(cls, self)
  return cls
end

...

function Object:__call(...)
  local obj = setmetatable({}, self)
  obj:new(...)
  return obj
end
```



提醒一下, 如果实现了`call`的元方法, 那么这个类可以以仿函数的形式调用, 而仿函数中又委托new函数来实现





### 1.4 meta & selector & rule



![](./img/orange/db.png)



orange之前的commit我没有阅读, 但根据作者的介绍:



> Orange v0.6.0版本是一个重构版本， 着重为了解决之前版本在有大量规则配置时性能损耗的问题。 基本的设计思路是将原来的规则细分成两层， 第一层叫做[selector](http://orange.sumory.com/docs/concept/selector/), 用于将流量进行第一步划分， 在进入某个selector后才按照之前的设计进行[规则](http://orange.sumory.com/docs/concept/rule/)匹配， 匹配到后进行相关处理。



**meta**

是辅助记录, 主要存放着selector的id



**selector**

选择器, 设计为流量筛选的第一道大门



**rule**

规则, 每个选择器有很多规则, orange根据规则进行第二次流量筛选





## 二. 启动过程



### 2.1 init

`nginx.conf`

```
init_by_lua_block {
    local orange = require("orange.orange")
    local env_orange_conf = os.getenv("ORANGE_CONF")
    local config_file = env_orange_conf or ngx.config.prefix().. "/conf/orange.conf"
    local config, store = orange.init({
        config = config_file
    })

    context = {
        orange = orange,
        store = store,
        config = config
    }
}
```



上述代码就是读取orange.conf的配置, 并且进行init的过程, 返回的orange, store, 作为orange的上下文, 供其他场景使用, 值得一提的是ORANGE_CONF环境变量一直为空, 所以配置档的路径是通过`ngx.config.prefix()`拿到的, 原因环境变量在master读取不到, 在worker中可以.



不废话继续分析

`orange.lua`

```
function Orange.init(options)
    options = options or {}
    local store, config
    local conf_file_path = options.config
    config = config_loader.load(conf_file_path)
    store = require("orange.store.mysql_store")(config.store_mysql)
    loaded_plugins = load_node_plugins(config, store)
    ngx.update_time()
    config.orange_start_at = ngx.now()
    return config, store
end
```



这段代码主要就干了两件事

- 实例化对象store
- 加载插件



store的加载是通过仿函数, 因为mysql_store间接继承了Object.





**store初始化**

```
function MySQLStore:new(options)
    self._name = options.name or "mysql-store"
    MySQLStore.super.new(self, self._name)
    self.store_type = "mysql"
    local connect_config = options.connect_config
    self.mysql_addr = connect_config.host .. ":" .. connect_config.port
    self.data = {}
    self.db = mysql_db:new(options)
end
```



前面没什么, 都是一堆赋值, 注意db对象是mysql_db类



`store/mysql_db`

```
function DB:new(conf)
    local instance = {}
    instance.conf = conf
    setmetatable(instance, { __index = self})
    return instance
end
```



这里并没有直接连接数据库, 而且在exec期间连接, 原因很简单, 防止重新连接..要防止就得加上连接检查, 说不定还会弄出来连接池啥的...咱要的就是不麻烦.



*其实这一段代码, 隐隐约约能感觉出作者可能当初是想写多数据库支持的,通过定义store的type能看出, 后来肯定因为一些事情没有写了, 如果是这样就我个人感觉应该还少一个更上层的Store类, 或者干脆就MysqlStore改个名字也可以, 不同的是实例化db对象的时候, 通过orange.conf字段去加载不同数据库的xxx_db, 再加上store定义好的通用interface, 这事没毛病.*



不扯远了, 让我们继续, storeok后, 我们开始加载插件



**加载插件**



```
local function load_node_plugins(config, store)

    local sorted_plugins = {}
    local loaded, plugin_handler = utils.load_module_if_exists("orange.plugins." .. v .. ".handler")

    table.insert(sorted_plugins, {
        name = v,
        handler = plugin_handler(store),
    })

    table.sort(sorted_plugins, function(a, b)
        local priority_a = a.handler.PRIORITY or 0
        local priority_b = b.handler.PRIORITY or 0
        return priority_a > priority_b
    end)

    return sorted_plugins
end
```



上述代码其实是循环加载插件, 我把循环的部分给注释了, v就是插件的名字, 加载完成根据插件的priority的进行排序, 如果你的插件是有依赖关系的, 请把priority给填上.



orange.conf配置插件部分

```
"plugins": [
  "stat",
  "monitor",
  "redirect",
  "rewrite",
  "rate_limiting",
  "property_rate_limiting",
  "basic_auth",
  "key_auth",
  "signature_auth",
  "waf",
  "divide",
  "kvstore"
]
```




`utils/utils.lua`

```
function _M.load_module_if_exists(module_name)
    local status, res = pcall(require, module_name)
    if status then
        return true, res
    elseif type(res) == "string" and string_find(res, "module '"..module_name.."' not found", nil, true) then
        return false
    else
        error(res)
    end
end
```



这个真没啥, pcall调用,主要是为了hold住一些错误, 如果是basic_auth, 如下

```
require("orange.plugins.basic_auth.handler")
```



那`plugin_handler(store)`其实就是

```
function BasicAuthHandler:new(store)
    BasicAuthHandler.super.new(self, "basic_auth-plugin")
    self.store = store
end
```

将store保存起来, 也就是说具备了操作db的能力, 后面排个序完事.



看到现在init其实没做什么干货, 其实也不用去干, 正如其名初始化一些东西而已, 为后面的init_worker做准备





### 2.2 init_worker



`nginx.conf`

```
init_worker_by_lua_block {
    local orange = context.orange
    orange.init_worker()
}
```


上面没啥, 直接看下方实现

```
function Orange.init_worker()
    if Orange.data and Orange.data.store and Orange.data.config.store == "mysql" then
        local ok, err = ngx.timer.at(0, function(premature, store, config)
            local available_plugins = config.plugins
            for _, v in ipairs(available_plugins) do
                local load_success = dao.load_data_by_mysql(store, v)
                if not load_success then
                    os.exit(1)
                end
            end
        end, Orange.data.store, Orange.data.config)
    end

    for _, plugin in ipairs(loaded_plugins) do
        plugin.handler:init_worker()
    end
end
```


这里面的store, config就是context对象, 从第一行可以看出, orange只支持mysql

后面会使用ngx.timer.at执行.



让我把代码再精简一下, 上述代码主要在做如下2句代码

```
dao.load_data_by_mysql(store, plugin)
plugin.handler:init_worker()
```


`orange/store/dao.lua`

```
function _M.load_data_by_mysql(store, plugin)
    if v == "stat" then
        return
    elseif v == "kvstore" then
        local init_enable = _M.init_enable_of_plugin(v, store)
    else -- ignore `stat` and `kvstore`
        local init_enable = _M.init_enable_of_plugin(v, store)
        local init_meta = _M.init_meta_of_plugin(v, store)
        local init_selectors_and_rules = _M.init_selectors_of_plugin(v, store)
    end
end
```


这里可以看到stat和kvstore插件初始化过程是较其他插件不一样的, 我们选择的basic_auth走的是else流程,也是最多的代码, 运气真不好, 早知道选stat了..

![](./img/orange/sad.jpg)





咳咳, 划重点了, 下面可是很重要.



`orange/store/dao.lua`

```
function _M.init_enable_of_plugin(plugin, store)
    -- 查找enable
    local enables, err = store:query({
        sql = "select `key`, `value` from meta where `key`=?",
        params = {plugin .. ".enable"}
    })

    if enables and type(enables) == "table" and #enables > 0 then
        orange_db.set(plugin .. ".enable", enables[1].value == "1")
    else
        orange_db.set(plugin .. ".enable", false)
    end

    return true
end
```


进行一次sql查询

```
select `key`, `value` from meta where `key`='basic_auth.enable'
```

然后把basic_auth.enable 为key, 值为value, 保存到orange_db内存中, 保存在内存中肯定是必要的, 不能让未来的judge query 成为性能瓶颈



如果启用了:

```
basic_auth.enable=true
```





顺便再说下store.query的过程, 之前咱们说到初始化时实际上没有进行数据库连接.

`store/mysql_db.lua`

```
function DB:query(sql, params)
    sql = self:parse_sql(sql, params)
    return self:exec(sql)
end

function DB:exec(sql)
    local conf = self.conf
    local db, err = mysql:new()
    db:set_timeout(conf.timeout)
    local ok, err, errno, sqlstate = db:connect(conf.connect_config)
    db:query("SET NAMES utf8")
    local res, err, errno, sqlstate = db:query(sql)
    local ok, err = db:set_keepalive(conf.pool_config.max_idle_timeout, conf.pool_config.pool_size)
    return res, err, errno, sqlstate
end
```



因为mysql的增删改查不是本文的重点, 就不深入分析了, 大概每次执行

- 连接
- 设置超时时间
- sql执行
- 返回





`orange/store/dao.lua`

```
function _M.init_meta_of_plugin(plugin, store)
    local meta, err = store:query({
        sql = "select * from " .. plugin .. " where `type` = ? limit 1",
        params = {"meta"}
    })

    if meta and type(meta) == "table" and #meta > 0 then
        local success, err, forcible = orange_db.set(plugin .. ".meta", meta[1].value or '{}')
    end

    return true
end
```


操作类似, 对数据库进行type为meta的查询, 因为meta记录的是selector的id, 所以数据大概如下:

```
basic_auth.meta={
	["selectors"] = {
		[1] = "6e6c7e97-8ece-45bd-9f88-d816c574ba40",
	},
}
```



`orange/store/dao.lua`

```
function _M.init_selectors_of_plugin(plugin, store)
    local selectors, err = store:query({
        sql = "select * from " .. plugin .. " where `type` = ?",
        params = {"selector"}
    })

    local to_update_selectors = {}
    if selectors and type(selectors) == "table" then
        for _, s in ipairs(selectors) do
            to_update_selectors[s.key] = json.decode(s.value or "{}")
            local init_rules_of_it = _M.init_rules_of_selector(plugin, store, s.key)
        end

        local success, err, forcible = orange_db.set_json(plugin .. ".selectors", to_update_selectors)
    else
        local success, err, forcible = orange_db.set_json(plugin .. ".selectors", {})
    end

    return true
end
```


上面的代码大同小异, 实际写入的数据大概是:

```
basic_auth.selector.6e6c7e97-8ece-45bd-9f88-d816c574ba40.rules={
	[1] = {
		["time"] = "2017-06-07 11:24:12",
		["enable"] = true,
		["id"] = "0b9cf684-6202-4676-b82d-a80b93f0b282",
		["judge"] = {
			["conditions"] = {
				[1] = {
					["value"] = "test_url",
					["operator"] = "match",
					["type"] = "URI",
				},
			},
			["type"] = 0,
		},
		["name"] = "r_single_match",
		["handle"] = {
			["log"] = true,
			["credentials"] = {
				[1] = {
					["username"] = "test_user",
					["password"] = "test_password",
				},
			},
			["code"] = 401,
		},
	},
}
```



**handler:init_worker**

执行完load_data_by_mysql, 接着就执行插件本身的init_worker函数, 具体逻辑得看插件的功能与特性, 就本文来说, basic_auth 插件不需要执行任何代码.



![](./img/orange/happy.jpg)







## 三. 插件



### 3.1 BasePlugin

这是所有插件的基类, 所有的插件都必须继承于此, 他实现了一系列的虚函数, 留给自己的子类继承

```
local BasePlugin = Object:extend()

function BasePlugin:new(name)
    self._name = name
end

function BasePlugin:init_worker()
function BasePlugin:redirect()
function BasePlugin:rewrite()
function BasePlugin:access()
function BasePlugin:header_filter()
function BasePlugin:body_filter()
function BasePlugin:log()


local BasicAuthHandler = BasePlugin:extend()
BasicAuthHandler.PRIORITY = 200
```



### 3.2 Handler

这玩意就是插件自身的逻辑了, 具体逻辑我们后文详细说明



### 3.3 文件命名

根据初始化逻辑

```
local loaded, plugin_handler = utils.load_module_if_exists("orange.plugins." .. v .. ".handler")
```

由上面代码看出, 插件需要满足一下约束

- 插件要放在plugins文件夹下面
- 插件文件夹里面一定要有handler.lua文件




### 3.4 配置登记

插件是按照在orange.conf中记录的插件名字加载的.

```
    "plugins": [
        "basic_auth"
        ...
    ],
```


*这里在叨叨两句, 个人感觉在插件的handler处理部分还可以继续封装, 因为selector和ruleda大多数时候都是common的, 插件与插件的不同应该体现在其他的逻辑, 所以handler部分应该不用写那么多代码, 框架层可以做更多事*









## 四. 执行过程



### 4.1 单一条件匹配



![](./img/orange/s_all_continue_s_no_log.png)



![](./img/orange/r_single_match.png)

老司机们分析前得做点准备工作:



首先得有个正常的API

```
MacBook-Pro:~ tuyou$ curl http://your_host:12000/api/v1/test
{"res":[],"message":"success","code":0}
```



配置nginx的upstream

```
upstream default_upstream {
    server test.aituyou.me:12000;
}

set $upstream_host $host;
set $upstream_url 'http://default_upstream';
```



ok, 那立即试验一下, 记得把basic_auth plugin, selector, rule都开启啊

```
MacBook-Pro:~ tuyou$ curl -i http://localhost:18888/api/v1/test
HTTP/1.1 401 Unauthorized
Server: openresty/1.11.2.3
Date: Wed, 07 Jun 2017 03:57:44 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 201
Connection: keep-alive

<html>
<head><title>401 Authorization Required</title></head>
<body bgcolor="white">
<center><h1>401 Authorization Required</h1></center>
<hr><center>openresty/1.11.2.3</center>
</body>
</html>
```



我们看到了, 报Authorization Required错, 下面让我们看看, 到底怎么出错的.



首先看ngxin配置, 基本是一个代理模式

```
...
access_by_lua_block {
    local orange = context.orange
    orange.access()
}
...
```



在不同的时期调用orange不同的函数, 由于`basic_auth.handler`只重载了access函数, 那么此插件的关键逻辑就在于此.



```
function BasicAuthHandler:access(conf)
    BasicAuthHandler.super.access(self)
    
    local enable = orange_db.get("basic_auth.enable")
    local meta = orange_db.get_json("basic_auth.meta")
    local selectors = orange_db.get_json("basic_auth.selectors")
    local ordered_selectors = meta and meta.selectors

    if not enable or enable ~= true or not meta or not ordered_selectors or not selectors then
        return
    end

    local ngx_var_uri = ngx.var.uri
    local headers = ngx.req.get_headers()
    local authorization = headers and (headers["Authorization"] or headers["authorization"])
end
```



这一段是准备过程, 主要是把当时init_xxx_of_plugin赋值的变量, 再给提取出来

1. meta主要存放的是selectors的id
2. selectors存放的是真正的selectors数据



大概如下:

```
meta:{
	["selectors"] = {
		[1] = "0d7f2265-a914-4bc8-ae0f-3115c0e6c845",
	},
}

selector:{
	["0d7f2265-a914-4bc8-ae0f-3115c0e6c845"] = {
		["time"] = "2017-06-06 08:38:11",
		["enable"] = true,
		["rules"] = {
			[1] = "900740f0-9e6f-4a38-ad9d-4429d4788b8e",
		},
		["id"] = "0d7f2265-a914-4bc8-ae0f-3115c0e6c845",
		["judge"] = {
		},
		["name"] = "s_all_continue_s_no_log",
		["handle"] = {
			["continue"] = true,
			["log"] = false,
		},
		["type"] = 0,
	},
}
```



接着看

```
for i, sid in ipairs(ordered_selectors) do
    ngx.log(ngx.INFO, "==[BasicAuth][PASS THROUGH SELECTOR:", sid, "]")
    local selector = selectors[sid]
    if selector and selector.enable == true then
        local selector_pass
        if selector.type == 0 then -- 全流量选择器
            selector_pass = true
        else
            selector_pass = judge_util.judge_selector(selector, "basic_auth")-- selector judge
        end

        if selector_pass then
            local stop = filter_rules(sid, "basic_auth", ngx_var_uri, authorization)
            if stop then -- 不再执行此插件其他逻辑
                return
            end
        end
    end
end
```



对于我们的情况, 其实只有一个selector, 所以for循环只有一次, 但如果一个插件有多个selector的情况下, 就涉及到一个selector能处理还要不要继续的过程, 这个字段判断主要由continue负责

```
-- if continue or break the loop
if selector.handle and selector.handle.continue == true then
    -- continue next selector
else
    break
end
```



另外还有个log字段, 负责打印出更多的日志, 如果不需要, 就设置为false



由于我们是全流量`selector.type = 0`, 那么很自然的代码执行到`filter_rules`

```
local function filter_rules(sid, plugin, ngx_var_uri, authorization)
    local rules = orange_db.get_json(plugin .. ".selector." .. sid .. ".rules")

    for i, rule in ipairs(rules) do
        if rule.enable == true then
            -- judge阶段
            local pass = judge_util.judge_rule(rule, plugin)

            -- handle阶段
            local handle = rule.handle or {}
            if pass then
                if handle.credentials then
                    local authorized = is_authorized(authorization, handle.credentials)
                    if authorized then
                        return true
                    else
                        ngx.exit(tonumber(handle.code) or 401)
                        return true
                    end
                else
                    ngx.exit(tonumber(handle.code) or 401)
                    return true
                end
            end
        end
    end
    return false
end
```



同理我们只有一条rule, for循环只有一次, 但如果有很多的rule, 都会进行judge处理, 如果某一条rule没有匹配, 就继续执行, 直到完结或命中为止.

代码分为2个阶段:

- judge阶段, 主要处理url的match
- handle阶段, 主要处理插件逻辑, 也就是basic_auth的authorization逻辑






**judge阶段**




`utils/judge.lua`

```
function _M.judge_rule(rule, plugin_name)
    if not rule or not rule.judge then return false end

    local judge = rule.judge
    local judge_type = judge.type
    local conditions = judge.conditions
    local pass = false
    if judge_type == 0 or judge_type == 1 then
        pass = _M.filter_and_conditions(conditions)
    elseif judge_type == 2 then
        pass = _M.filter_or_conditions(conditions)
    elseif judge_type == 3 then
        pass = _M.filter_complicated_conditions(judge.expression, conditions, plugin_name)
    end

    return pass
end
```



这段基本是个马甲, 大概意思是根据type的字段去不同的condition进行下一步判断:



参考作者的注释即可

> - 0表示只有一个匹配条件，1表示对所有条件**与**操作，2表示对所有条件**或**操作，3表示按照表达式(另一个字段`expression`)对所有条件求值
> - 注意当使用type为3的表达式求值时性能有一定损耗，请自行做好相关测试工作
> - expression当type为3时，此字段不为空，它的格式是一个lua的逻辑判断表达式表达式中每个值的格式为`v[index]`, 比如v[1]对应的就是第一个条件的值。示例：(v[1] or v[2]) and v[3]，即前两个条件至少一个为真并且第三个条件为真时，规则为真



我们的type=0所以直接`filter_and_conditions`



`utils/judge.lua`

```
function _M.filter_and_conditions(conditions)
    if not conditions then return false end

    local pass = false
    for i, c in ipairs(conditions) do
        pass = condition.judge(c)
        if not pass then
            return false
        end
    end

    return pass
end
```



如果有多个条件就一个一个验证, 只要有一个没通过就领盒饭, 这代码还是没到肉, 我们继续看



`utils/condition.lua`

```
function _M.judge(condition)
    local condition_type = condition and condition.type
    local operator = condition.operator
    local expected = condition.value
    local real
    
    if condition_type == "URI" then
        real = ngx.var.uri
    elseif
        -- 其他逻辑 参考 http://orange.sumory.com/docs/concept/condition/
    end
    return assert_condition(real, operator, expected)
end
```



代码精简了不少, 实际上最后就是一个断言, 当然这是个假断言, 它并不会再release模式下消失. 它要做的就是个比较工作





`utils/condition.lua`

```
local function assert_condition(real, operator, expected)
    if operator == 'match' then
        if ngx_re_find(real, expected, 'isjo') ~= nil then
            return true
        end
    end
    return false
end
```



ngx_re_find是正则表达式, 看到这里内心很鸡冻

- operator = match
- real = /api/v1/test
- expected = /api/v1/test




妥妥的PASS.



![](./img/orange/perfect.jpg)





虽然很高兴, 但事情还没完, 老司机要稳, 毕竟调试是报错了, 接着是第二阶段 





**handle阶段**

```
local handle = rule.handle or {}
if pass then
    if handle.credentials then
        local authorized = is_authorized(authorization, handle.credentials)
        if authorized then
            return true
        else
            ngx.exit(tonumber(handle.code) or 401)
            return true
        end
    else
        ngx.exit(tonumber(handle.code) or 401)
        return true
    end
end
```



首先是看handle有没有, 这个实际上在配置rule的时候就自动生成了, 接着判断有没有credentials, 这玩意是藏在header里面的.

```
local authorization = headers and (headers["Authorization"] or headers["authorization"])
```



但我们其实没有header, 所以进入else流程, 返回了handle.code, 杯具在此...



那么问题来了, 什么才是打开basic_auth的正确姿势呢?



`utils/basic_auth/handler.lua`

```
local function get_encoded_credential(origin)
    local result = string_gsub(origin, "^ *[B|b]asic *", "")
    result = string_gsub(result, "( *)$", "")
    return result
end

local function is_authorized(authorization, credentials)
    if type(authorization) == "string" and authorization ~= "" then
        local encoded_credential = get_encoded_credential(authorization)
        for j, v in ipairs(credentials) do
            local allowd = encode_base64(string_format("%s:%s", v.username, v.password))
            if allowd == encoded_credential then -- authorization passed
                return true
            end
        end
    end
    return false
end
```



authorization是你在http 头中传递的字符串, credentials是rule中记录的规则

首先把basic字样从authorization去掉, 然后base64(user:password)去比较, 如果对就PASS,不对就拒绝



嗯, 应该是这样...让我们来装个逼, 突然想起来侯捷大师经常说的一句话…



![](./img/orange/zhuangbi.jpg)





算了不装了.



再来调一把:

```
MacBook-Pro:~ tuyou$ curl -H "Authorization: Basic dGVzdF91c2VyOnRlc3RfcGFzc3dvcmQ=" http://localhost:18888/api/v1/test
{"res":[],"message":"success","code":0}
```






### 4.2 多模式匹配



有了上一节的基础, 在看这个会清楚很多





**or匹配**

`utils/judge.lua`

```
function _M.filter_or_conditions(conditions)
    local pass = false
    for i, c in ipairs(conditions) do
        pass = condition.judge(c)
        if pass then
            return true
        end
    end
    return pass
end
```



很明显只要有一个rule pass就return, 大家自己根据下图体会

![](./img/orange/or_rule.png)









### 4.3 流量



上面说了rule的match规则, 还有个全流量, 半流量, 1/3流量的概念, 哈哈, 后面是我编的, 实际上作者叫 自定义流量



> ```
> 0指该选择器是“全流量”选择器， 1指该选择器有一个“条件判断”模块，筛选出的流量才能进入此选择器
> ```



![](./img/orange/custom_liuliang.png)



那我们就来看看这个, 再回到当初的地方



`plugins/basic_auth/handler.lua`

```
for i, sid in ipairs(ordered_selectors) do
    ngx.log(ngx.INFO, "==[BasicAuth][PASS THROUGH SELECTOR:", sid, "]")
    local selector = selectors[sid]
    if selector and selector.enable == true then
        local selector_pass
        if selector.type == 0 then -- 全流量选择器
            selector_pass = true
        else
            selector_pass = judge_util.judge_selector(selector, "basic_auth")-- selector judge
        end

        if selector_pass then
            local stop = filter_rules(sid, "basic_auth", ngx_var_uri, authorization)
            if stop then -- 不再执行此插件其他逻辑
                return
            end
        end
    end
end
```





这次我们不是全流量了, 我们进去judge_selector

`utils/judge.lua`

```
function _M.judge_selector(selector, plugin_name)
    local selector_judge = selector.judge
    local judge_type = selector_judge.type
    local conditions = selector_judge.conditions

    local selector_pass = false
    if judge_type == 0 or judge_type == 1 then
        selector_pass = _M.filter_and_conditions(conditions)
    elseif judge_type == 2 then
        selector_pass = _M.filter_or_conditions(conditions)
    elseif judge_type == 3 then
        selector_pass = _M.filter_complicated_conditions(selector_judge.expression, conditions, plugin_name)
    end

    return selector_pass
end
```



我擦一模一样, 依靠同一套底层封装, 同时筛选selector和rule.

这么看来, 本质上就是处理和不处理, 只是发生在不同阶段罢了, 作者利用对逻辑操作符的封装, 通过小粒度组合成成千上万的可能, 这点上是非常灵活,敏捷的.





## 最后



非常感谢作者, 写了那么优秀代码, 在此收益良多, 万分感谢.







## 附录



### lua_shared_dict

> 语法：*lua_shared_dict <name> <size>*
>
> 
>
> 该命令主要是定义一块名为name的共享内存空间，内存大小为size。通过该命令定义的共享内存对象对于Nginx中所有worker进程都是可见的，当Nginx通过reload命令重启时，共享内存字典项会从新获取它的内容，当时当Nginx退出时，字典项的值将会丢失





### init_by_lua

> 语法：init_by_lua <lua-script-str>
>
> 语境：http
>
> 阶段：loading-config
>
> 当nginx master进程在加载nginx配置文件时运行指定的lua脚本，通常用来注册lua的全局变量或在服务器启动时预加载lua模块：



### ngx.timer.at

> ## ngx.timer.at
>
> **syntax:** *hdl, err = ngx.timer.at(delay, callback, user_arg1, user_arg2, ...)*
>
> **context:** *init_worker_by_lua\*, set_by_lua*, rewrite_by_lua*, access_by_lua*, content_by_lua*, header_filter_by_lua*, body_filter_by_lua*, log_by_lua*, ngx.timer.*, balancer_by_lua*, ssl_certificate_by_lua*, ssl_session_fetch_by_lua*, ssl_session_store_by_lua**
>
> Creates an Nginx timer with a user callback function as well as optional user arguments.
>
> The first argument, `delay`, specifies the delay for the timer, in seconds. One can specify fractional seconds like `0.001` to mean 1 millisecond here. `0` delay can also be specified, in which case the timer will immediately expire when the current handler yields execution.
>
> The second argument, `callback`, can be any Lua function, which will be invoked later in a background "light thread" after the delay specified. The user callback will be called automatically by the Nginx core with the arguments `premature`, `user_arg1`, `user_arg2`, and etc, where the `premature` argument takes a boolean value indicating whether it is a premature timer expiration or not, and `user_arg1`, `user_arg2`, and etc, are those (extra) user arguments specified when calling `ngx.timer.at` as the remaining arguments.
>
> Premature timer expiration happens when the Nginx worker process is trying to shut down, as in an Nginx configuration reload triggered by the `HUP` signal or in an Nginx server shutdown. When the Nginx worker is trying to shut down, one can no longer call `ngx.timer.at` to create new timers with nonzero delays and in that case `ngx.timer.at` will return a "conditional false" value and a string describing the error, that is, "process exiting".
>
> Starting from the `v0.9.3` release, it is allowed to create zero-delay timers even when the Nginx worker process starts shutting down.
>
> When a timer expires, the user Lua code in the timer callback is running in a "light thread" detached completely from the original request creating the timer. So objects with the same lifetime as the request creating them, like [cosockets](https://github.com/openresty/lua-nginx-module#ngxsockettcp), cannot be shared between the original request and the timer user callback function.





## 参考

1. https://moonbingbing.gitbooks.io/openresty-best-practices
2. http://geek.csdn.net/news/detail/37345
3. http://openresty.org/download/agentzh-nginx-tutorials-zhcn.html
4. http://www.cnblogs.com/wangxusummer/p/4309007.html
5. http://jinnianshilongnian.iteye.com/blog/2280928



