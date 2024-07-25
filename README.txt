https://dns.hnsmmg.com/guwVKkXqxI.php    



我想要为内部用户提供DNS服务。通过dns白名单管理系统的api来获取白名单列表。
收到DNS请求后先判断是否为白名单内域名。
如果非白名单域名使用180.76.76.76 解析并返回解析内容。

如果是白名单域名。则使用1.1.1.1 解析并返回解析内容。

请求接口的测试节点     
节点标识：  ShangHai-test-01     
api_key:911f255ae5d40243e9280fe323ece87d


通用：
  
签名生成规则:

将请求的参数以key的ascii码排列进行排序，然后组成key=value&key1=value1&key2=key2格式，并拼接上&key=api_key 然后进行md5加密（小写）



接口：
1、获取节点下域名列表
请求地址：   https://dns.hninpop.com/api/dns_node/domainList
请求参数：  node_code  节点的唯一标识
            time   时间戳  

Header中参数：   sign  签名 

成功返回：
{
    "code": 1,
    "msg": "请求成功",
    "time": "1719222126",
    "data": {
        "domain_list": [
            "news.qq.com",
            "*.ly.com",
            "www.mafengwo.cn",
            "www.cnad.com",
            "*.a.com.cn",
            "www.a.com.cn"
        ]
    }
}


失败返回：
{
    "code": 0,
    "msg": "DNS节点不存在或已禁用",
    "time": "1719222115",
    "data": null
}


2、DNS解析
请求地址：   https://dns.hninpop.com/api/dns_node/domainResolution
请求参数：  node_code  节点的唯一标识
domain   网站域名
            time   时间戳  

Header中参数：   sign  签名 

成功返回：
{
    "code": 1,
    "msg": "success",
    "time": "1719221580",
    "data": [
        {
            "id": 11,
            "domain": "news.qq.com",
            "virtual_ip": "100.119.183.14",     //虚拟IP地址
            "dns_ip": "43.175.12.133",			//google获取的dns地址
            "ttl": 60,						//有效时间
            "expire_at": 1719221610,			//过期的时间戳
            "create_at": 1719221560
        }
    ]
}

失败返回：
{
    "code": 0,
    "msg": "不在白名单中",
    "time": "1719222322",
    "data": null
}



使用docker-compose up -d部署
