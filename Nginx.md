#### 一、Nginx安装（安装看第二个段落）

- 下载压缩包 并上传

  - http://nginx.org/en/download.html

- 安装依赖

  - yum -y install gcc zlib zlib-devel pcre-devel openssl openssl-devel

- 创建一个文件夹，上传本地提供的nginx包

  ```
  tar -zxvf nginx-1.18.0.tar.gz
  ./configure
  make
  make install 
  ```

- 默认安装路径

  /usr/local/nginx

- 启动Nginx

  ```
  cd /usr/local/nginx/sbin   
  ./nginx
  ```

- 开启Nginx默认防火墙端口（80）

  开放80端口 firewall-cmd --permanent --add-port=80/tcp （--permanent永久生效，没有此参数重启后就失效）

  加载生效开放的端口: firewall-cmd --reload

- 命令

  ```
  ./nginx  #默认配置文件启动
  ./nginx -s reload #重启，加载默认配置文件
  ./nginx -c /usr/local/nginx/conf/nginx.conf #启动指定某个配置文件
  ./nginx -s stop #停止
  #关闭进程，nginx有master process 和worker process,关闭master即可
  ps -ef | grep "nginx" 
  kill -9 PID 
  ```

#### 二、Nginx整合lua

- centos安装openresty：http://openresty.org/cn/ （openresty中包含了Nginx）

  ```
  wget https://openresty.org/package/centos/openresty.repo 
  sudo mv openresty.repo /etc/yum.repos.d/
  sudo yum check-update
  sudo yum install -y openresty
  sudo yum install -y openresty-resty
  列出所有 `openresty` 仓库里头的软件包：
  sudo yum --disablerepo="*" --enablerepo="openresty" list available
  ```

#### 三、Nginx.conf配置文件解析

- 全局块：配置影响nginx全局的指令。一般有运行nginx服务器的用户组，nginx进程pid存放路径，日志存放路径，配置文件引入，允

- 许生成worker process数等。

- events块：配置影响nginx服务器或与用户的网络连接。有每个进程的最大连接数，选取哪种事件驱动模型处理连接请求，是否允许同时接受多个网路连接，开启多个网络连接序列化等。

- http块：可以嵌套多个server，配置代理，缓存，日志定义等绝大多数功能和第三方模块的配置。如文件引入，mime-type定义，日志自定义，是否使用sendfile传输文件，连接超时时间，单连接请求数等。

- server块：配置虚拟主机的相关参数，一个http中可以有多个server。

- location块：配置请求的路由，以及各种页面的处理情况。


  ```
  user  root; #配置用户或者组，默认为nobody nobody
  worker_processes  auto;#允许生成的进程数，默认为1
  
  error_log  logs/error.log;#制定日志路径，级别。这个设置可以放入全局块，http块，server块，级别以此为：			                               #debug|info|notice|warn|error|crit|alert|emerg
  pid   logs/nginx.pid; #指定nginx进程运行文件存放地址
  
  events {
      worker_connections  1024;#最大连接数
      use epoll;#事件驱动模型，select|poll|kqueue|epoll|resig|/dev/poll|eventport
  }
  
  http {
      include       mime.types;   #文件扩展名与文件类型映射表
      default_type  application/octet-stream;  #默认文件类型，默认为text/plain
      log_format json '{"createdate":"$time_iso8601",'  #配置日志格式
                        '"client":"$remote_addr",'
                        '"url":"$uri",'
                        '"status":"$status",'
                        '"domain":"$host",'
                        '"host":"$server_addr",'
                        '"size":$body_bytes_sent,'
                        '"responsetime":$request_time,'
                        '"referer": "$http_referer",'
                        '"cookie": "$http_cookie",'
                        '"ua": "$http_user_agent"'
                       '}';
  access_log  logs/access.log  json; #combined为日志格式的默认值
  
  sendfile        on; #是否开启高效传输模式 on开启 off关闭
  tcp_nopush      on; #减少网络报文段的数量
  
  keepalive_timeout  65; # 客户端连接保持活动的超时时间，超过这个时间之后，服务器会关闭该连接
  
  gzip  on; #开启gzip,减少我们发送的数据量
  gzip_min_length 1k;
  gzip_buffers 4 16k;
  gzip_types text/plain application/javascript application/octet-stream application/css  text/css application/xml text/javascript application/x-javascript;
  gzip_vary off;
  gzip_disable "MSIE [1-6]\.";
  
  # lua_package_path可以配置openresty的文件寻址路径，$PREFIX 为openresty安装路径
  # 文件名使用“?”作为通配符，多个路径使用“;”分隔，默认的查找路径用“;;”
  # 设置纯 Lua 扩展库的搜寻路径
  lua_package_path "$prefix/lualib/?.lua;;";
  #设置 C 编写的 Lua 扩展模块的搜寻路径(也可以用 ';;')
  lua_package_cpath "$prefix/lualib/?.so;;";
  # 这里设置为 off，是为了避免每次修改之后都要重新 reload 的麻烦。
  # 在生产环境上需要 lua_code_cache 设置成 on。
  lua_code_cache off; 
  
  #负载均衡
  upstream testserver {
      #ip_hash;#根据请求按访问ip的hash结果分配，这样每个用户就可以固定访问一个后端服务器
      #server 192.168.3.205:8023 weight=5;#weight和访问比率成正比，数字越大，分配得到的流量越高
      #server 192.168.159.133:8080 down;#表示当前的server暂时不参与负载
      server 192.168.3.205:8023 max_fails=1 fail_timeout=60s;#max_fails 允许请求失败的次数，默认为1.当超过最大次数时就不会请求，fail_timeout : max_fails次失败后，暂停的时间，默认：fail_timeout为10s
      server 192.168.3.206:8023 max_fails=1 fail_timeout=60s;
      server 192.168.3.207:8023 backup;#backup 其它所有的非backup机器down的时候，会请求backup机器，这台机器压力会最轻，配置也会相对低
  }
  
  server {
      listen       80;  #监听端口
      server_name  192.168.3.202; #用来指定IP地址或域名，多个域名之间用空格分开
  
      #charset koi8-r;
  
      access_log  logs/host.access.log  json;
  
  #   访问前端资源 
  #	location / {
  #			root /data/www;  
  #			index index.html index.php;
  #	}
  	#配置静态资源
      location /static{
              alias /usr/local/static/;
      }
  # root和alias的区别  https://blog.csdn.net/bjash/article/details/8596538
      location /test {   #URL地址匹配
              #跨域配置
              add_header 'Access-Control-Allow-Origin' $http_origin;
              add_header 'Access-Control-Allow-Credentials' 'true';
              add_header 'Access-Control-Allow-Headers' 'DNT,web-token,app-token,Authorization,Accept,Origin,Keep-Alive,User-Agent,X-Mx-ReqToken,X-Data-Type,X-Auth-Token,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range';
              add_header Access-Control-Allow-Methods 'GET,POST,OPTIONS';
  
              if ($request_method = 'OPTIONS') {
                      add_header 'Access-Control-Max-Age' 1728000;
                      add_header 'Content-Type' 'text/plain; charset=utf-8';
                      add_header 'Content-Length' 0;
                      return 200;
              }
              
              proxy_pass http://testserver;
      }
  
      location /qiyekexie {
              rewrite "/" https://www.qiyekexie.com; 
      }
      
      location / {
              access_by_lua_block{
                        ngx.exit(ngx.HTTP_FORBIDDEN)
                        return;
              }
      }
      
      #错误状态码的显示页面
      error_page   500 502 503 504  /50x.html;  
      location = /50x.html {
          root   html;
      }
      
      # 不加 =200，则返回的就是原先的http错误码；配上后如果出现500等错误都返回给用户200状态，并跳转至/default_api
  #    error_page  404 500 502 503 504  =200  /default_api;
  #    location = /default_api {
  #    default_type application/json;
  #    return 200 '{"code":"-1","msg":"invoke fail, not found "}';
  #    }
  }
  # HTTPS server
  #
  #server {
  #    listen       443 ssl;
  #    server_name  localhost;
  
  #    ssl_certificate      cert.pem;
  #    ssl_certificate_key  cert.key;
  
  #    ssl_session_cache    shared:SSL:1m;
  #    ssl_session_timeout  5m;
  
  #    ssl_ciphers  HIGH:!aNULL:!MD5;
  #    ssl_prefer_server_ciphers  on;
  
  #    location / {
  #        root   html;
  #        index  index.html index.htm;
  #    }
  #}
  }
  ```

  

#### 四、Nginx内置变量

| 名称                  | 说明                                                         |
| --------------------- | ------------------------------------------------------------ |
| $arg_name             | 请求中的name参数                                             |
| $args                 | 请求中的参数                                                 |
| $content_length       | HTTP请求信息里的"Content-Length"                             |
| $content_type         | 请求信息里的"Content-Type"                                   |
| $host                 | 请求信息中的"Host"，如果请求中没有Host行，则等于设置的服务器名 |
| $hostname             | 机器名使用 gethostname系统调用的值                           |
| $http_cookie          | cookie 信息                                                  |
| $http_referer         | 引用地址                                                     |
| $http_user_agent      | 客户端代理信息                                               |
| $http_via             | 最后一个访问服务器的Ip地址。                                 |
| $http_x_forwarded_for | 相当于网络访问路径                                           |
| $is_args              | 如果请求行带有参数，返回“?”，否则返回空字符串                |
| $limit_rate           | 对连接速率的限制                                             |
| $nginx_version        | 当前运行的nginx版本号                                        |
| $pid                  | worker进程的PID                                              |
| $query_string         | 与$args相同                                                  |
| $remote_addr          | 客户端IP地址                                                 |
| $remote_port          | 客户端端口号                                                 |
| $request              | 用户请求                                                     |
| $request_method       | 请求的方法，比如"GET"、"POST"等                              |
| $request_uri          | 请求的URI，带参数                                            |
| $scheme               | 所用的协议，比如http或者是https                              |
| $server_name          | 请求到达的服务器名                                           |
| $server_port          | 请求到达的服务器端口号                                       |
| $server_protocol      | 请求的协议版本，"HTTP/1.0"或"HTTP/1.1"                       |
| $uri                  | 请求的URI，可能和最初的值有不同，比如经过重定向之类的        |

####  五、Nginx日志

- Nginx封禁ip

  ```
  单独网站屏蔽IP的方法，把include xxx; 放到网址对应的在server{}语句块,虚拟主机
  所有网站屏蔽IP的方法，把include xxx; 放到http {}语句块。
  
  nginx配置如下：
  
  http{
      # ....
      include blacklist.conf;
  }
  
  location / {
                  proxy_pass http://lbs;
                  proxy_redirect default;
  }
  
  
  #blacklist.conf目录下文件内容
  deny 192.168.159.2;
  deny 192.168.159.32;
  
  查询高频ip
  date=`date "+%Y-%m-%d"`; s=`date "+%S"`;tail -10000 access.log | awk  -F '"' '{printf $4}{printf " "}{print $8}' |awk -v var=${date}  -F 'T' '{if($1==var) print $0}'| sed 's/T/:/g'|awk -v var=${s} -F ":" '{if($2==var)print $0}' | awk '{print $2}' | sort | uniq -c | sort -rn  | head -20 | more
  
  编写shell脚本
  AWK统计access.log，记录每秒访问超过60次的ip，然后配合nginx或者iptables进行封禁
  crontab定时跑脚本
  ```



#### 六、location规则

- 正则

  ```
  ^ 以什么开始
  $ 以什么结束
  ^/api/user$
  ```

- location 路径匹配

  语法 **location [ = | ~ | ~\* | ^~ ] uri { ...... }**

- location = /uri

- = 表示精准匹配，只要完全匹配上才能生效

- location /uri

  不带任何修饰符，表示前缀匹配

- location ^~ /uri/

  匹配任何已 /uri/ 开头的任何查询并且停止搜索

- location /

  通用匹配，任何未匹配到其他location的请求都会匹配到

- 正则匹配

  区分大小写匹配（~）

  不区分大小写匹配（~*）

- 优先级(不要写复杂，容易出问题和遗忘)

- 精准匹配 > 字符串匹配(若有多个匹配项匹配成功，那么选择匹配长的并记录) > 正则匹配



#### 七、rewrite规则

- 重写-重定向

- rewrite 地址重定向，实现URL重定向的重要指令，他根据regex(正则表达式)来匹配内容跳转到

  语法 rewrite regex replacement[flag]

  ```
  rewrite ^/(.*)  https://127.0.0.1/$1 permanent
  # 这是一个正则表达式，匹配完整的域名和后面的路径地址
  # replacement部分是https://127.0.0.1/$1，$1是取自regex部分()里的内容
  ```

- 常用正则表达式：

| 字符      | 描述                         |
| --------- | ---------------------------- |
| ^         | 匹配输入字符串的起始位置     |
| $         | 匹配输入字符串的结束位置     |
| *         | 匹配前面的字符零次或者多次   |
| +         | 匹配前面字符串一次或者多次   |
| ?         | 匹配前面字符串的零次或者一次 |
| .         | 匹配除“\n”之外的所有单个字符 |
| (pattern) | 匹配括号内的pattern          |

- rewrite 最后一项flag参数

| 标记符号  | 说明                                               |
| --------- | -------------------------------------------------- |
| last      | 本条规则匹配完成后继续向下匹配新的location URI规则 |
| break     | 本条规则匹配完成后终止，不在匹配任何规则           |
| redirect  | 返回302临时重定向                                  |
| permanent | 返回301永久重定向                                  |



#### 八、Nginx缓存

- **/root/cache**

  - 本地路径，用来设置Nginx缓存资源的存放地址

  

- **levels=1:2**

  - 默认所有缓存文件都放在上面指定的根路径中，可能影响缓存的性能，推荐指定为 2 级目录来存储缓存文件；1和2表示用1位和2位16进制来命名目录名称。第一级目录用1位16进制命名，如a；第二级目录用2位16进制命名，如3a。所以此例中一级目录有16个，二级目录有16*16=256个,总目录数为16 * 256=4096个。
  - 当levels=1:1:1时，表示是三级目录，且每级目录数均为16个

   

- **key_zone**

  - 在共享内存中定义一块存储区域来存放缓存的 key 和 metadata

   

- **max_size**

  - 最大 缓存空间, 如果不指定会使用掉所有磁盘空间。当达到 disk 上限后，会删除最少使用的 cache

   

- **inactive**

  - 某个缓存在inactive指定的时间内如果不访问，将会从缓存中删除

   

- **proxy_cache_valid**

  - 配置nginx cache中的缓存文件的缓存时间,proxy_cache_valid 200 304 2m 对于状态为200和304的缓存文件的缓存时间是2分钟

   

- **use_temp_path**

  - 建议为 off，则 nginx 会将缓存文件直接写入指定的 cache 文件中

   

- **proxy_cache**

  - 启用proxy cache，并指定key_zone，如果proxy_cache off表示关闭掉缓存

   

- **add_header Nging-Cache "$upstream_cache_status"**

  - 用于前端判断是否是缓存，miss、hit、expired(缓存过期)、updating(更新，使用旧的应答)

```
proxy_cache_path /root/cache levels=1:2 keys_zone=xd_cache:10m max_size=1g inactive=60m use_temp_path=off;

server {

      location /{
        ...     
        proxy_cache xd_cache;
        proxy_cache_valid 200 304 10m;
        proxy_cache_valid 404 1m; 
        proxy_cache_key $host$uri$is_args$args;
        add_header Nginx-Cache "$upstream_cache_status";
      }
  }
```



#### 九、Nginx静态资源压缩

```
#开启gzip,减少我们发送的数据量
gzip on;
gzip_min_length 1k;

#4个单位为16k的内存作为压缩结果流缓存
gzip_buffers 4 16k;

#gzip压缩比，可在1~9中设置，1压缩比最小，速度最快，9压缩比最大，速度最慢，消耗CPU
gzip_comp_level 4;

#压缩的类型
gzip_types application/javascript text/plain text/css application/json application/xml    text/javascript; 

#给代理服务器用的，有的浏览器支持压缩，有的不支持，所以避免浪费不支持的也压缩，所以根据客户端的HTTP头来判断，是否需要压缩
gzip_vary on;

#禁用IE6以下的gzip压缩，IE某些版本对gzip的压缩支持很不好
gzip_disable "MSIE [1-6].";
```

#### 十、Nginx配置https

- 删除原先的nginx，新增ssl模块

  ```
  ./configure --prefix=/usr/local/nginx --with-http_stub_status_module --with-http_ssl_module
  make
  make install
  #查看是否成功
  /usr/local/nginx/sbin/nginx -V
  ```

- Nginx配置https证书

  ```
  server {
         listen       443 ssl;
         server_name  16web.net;
         ssl_certificate      /usr/local/software/biz/key/4383407_16web.net.pem;
         ssl_certificate_key  /usr/local/software/biz/key/4383407_16web.net.key;
         ssl_session_cache    shared:SSL:1m;
         ssl_session_timeout  5m;
         ssl_ciphers  HIGH:!aNULL:!MD5;
         ssl_prefer_server_ciphers  on;
         
         location / {
              root   html;
              index  index.html index.htm;
          }
     }
  ```

  

#### 十一、Nginx+OpenRestry网络访问限制

nginx对于请求的处理分多个阶段,Nginx , 从而让第三方模块通过挂载行为在不同的阶段来控制, 大致如下

- 初始化阶段（Initialization Phase）
  - init_by_lua_file
  - init_worker_by_lua_file
- 重写与访问阶段（Rewrite / Access Phase）
  - rewrite_by_lua_file
  - access_by_lua_file
- 内容生成阶段（Content Phase）
  - content_by_lua_file
- 日志记录阶段（Log Phase）

```
http{

# 这里设置为 off，是为了避免每次修改之后都要重新 reload 的麻烦。
# 在生产环境上需要 lua_code_cache 设置成 on。

lua_code_cache off;

# lua_package_path可以配置openresty的文件寻址路径，$PREFIX 为openresty安装路径
# 文件名使用“?”作为通配符，多个路径使用“;”分隔，默认的查找路径用“;;”
# 设置纯 Lua 扩展库的搜寻路径
lua_package_path "$prefix/lualib/?.lua;;";

# 设置 C 编写的 Lua 扩展模块的搜寻路径(也可以用 ';;')
lua_package_cpath "$prefix/lualib/?.so;;";

server {
     location / {
     access_by_lua_file lua/white_ip_list.lua;
     proxy_pass http://lbs;
     }
}
```

- lua/white_ip_list.lua

  ```
  local black_ips = {["127.0.0.1"]=true}
  
  local ip = ngx.var.remote_addr
  if true == black_ips[ip] then
      ngx.exit(ngx.HTTP_FORBIDDEN)
      return;
  end
  ```

  

#### 十二、Nginx+keepalived实现高可用

- keepalived安装

  ```
  yum install -y keepalived
  ```

- 启动和查看命令

  ```
  #启动
  service keepalived start
  #停止
  service keepalived stop
  #查看状态
  service keepalived status
  #重启
  service keepalived restart
  #停止防火墙
  systemctl stop firewalld.service
  ```

- Keepalived配置（/etc/keepalived/keepalived.conf）

  ```
  ! Configuration File for keepalived
  
  global_defs {
  
     router_id LVS_DEVEL # 设置lvs的id，在一个网络内应该是唯一的
     enable_script_security #允许执行外部脚本
  }
  
  
  #配置vrrp_script，主要用于健康检查及检查失败后执行的动作。
  vrrp_script chk_real_server {
  #健康检查脚本，当脚本返回值不为0时认为失败
      script "/usr/local/software/conf/chk_server.sh"
  #检查频率，以下配置每2秒检查1次
      interval 2
  #当检查失败后，将vrrp_instance的priority减小5
      weight -5
  #连续监测失败3次，才认为真的健康检查失败。并调整优先级
      fall 3
  #连续监测2次成功，就认为成功。但不调整优先级
      rise 2
  
      user root
  }
  
  
  
  #配置对外提供服务的VIP vrrp_instance配置
  
  vrrp_instance VI_1 {
  
  #指定vrrp_instance的状态，是MASTER还是BACKUP主要还是看优先级。
      state MASTER
  
  #指定vrrp_instance绑定的网卡，最终通过指定的网卡绑定VIP
      interface ens33
  
  #相当于VRID，用于在一个网内区分组播，需要组播域内内唯一。
      virtual_router_id 51
  
  #本机的优先级，VRID相同的机器中，优先级最高的会被选举为MASTER
      priority 100
  
  #心跳间隔检查，默认为1s，MASTER会每隔1秒发送一个报文告知组内其他机器自己还活着。
      advert_int 1
  
      authentication {
          auth_type PASS
          auth_pass 1111
      }
  
  #定义虚拟IP(VIP)为192.168.159.100，可多设，每行一个
      virtual_ipaddress {
          192.168.159.100
      }
  
      #本vrrp_instance所引用的脚本配置，名称就是vrrp_script 定义的容器名
    track_script {
        chk_real_server
      }
  }
  
  # 定义对外提供服务的LVS的VIP以及port
  virtual_server 192.168.159.100 80 {
      # 设置健康检查时间，单位是秒
      delay_loop 6
  
      # 设置负载调度的算法为rr
      lb_algo rr
  
      # 设置LVS实现负载的机制，有NAT、TUN、DR三个模式
      lb_kind NAT
  
      # 会话保持时间
      persistence_timeout 50
  
     #指定转发协议类型(TCP、UDP)
      protocol TCP
  
      # 指定real server1的IP地址
  
      real_server 192.168.159.146 80 {
          # 配置节点权值，数字越大权重越高
          weight 1
  
          # 健康检查方式
          TCP_CHECK {                  # 健康检查方式
              connect_timeout 10       # 连接超时
              retry 3           # 重试次数
              delay_before_retry 3     # 重试间隔
              connect_port 80          # 检查时连接的端口
          }
      }
  }
  ```

- 配置注意

  ```
  router_id后面跟的自定义的ID在同一个网络下是一致的
  state后跟的MASTER和BACKUP必须是大写；否则会造成配置无法生效的问题
  interface 网卡ID；要根据自己的实际情况来看，可以使用以下方式查询 ip a  查询
  在BACKUP节点上，其keepalived.conf与Master上基本一致，修改state为BACKUP，priority值改小即可
  authentication主备之间的认证方式，一般使用PASS即可；主备的配置必须一致，不能超过8位
  ```

- 脚本监听

  ```
  #配置vrrp_script，主要用于健康检查及检查失败后执行的动作。
  vrrp_script chk_real_server {
  #健康检查脚本，当脚本返回值不为0时认为失败
      script "/usr/local/software/conf/chk_server.sh"
  #检查频率，以下配置每2秒检查1次
      interval 2
  #当检查失败后，将vrrp_instance的priority减小5
      weight -5
  #连续监测失败3次，才认为真的健康检查失败。并调整优先级
      fall 3
  #连续监测2次成功，就认为成功。但不调整优先级
      rise 2
  
      user root
  }
  ```

  

- chk_server.sh脚本内容（需要 chmod +x chk_server.sh）

  ```
  #!/bin/bash
  #检查nginx进程是否存在
  counter=$(ps -C nginx --no-heading|wc -l)
  if [ "${counter}" -eq "0" ]; then
      service keepalived stop
      echo 'nginx server is died.......'
  fi
  ```

- 常见问题

  ```
  vip能ping通，vip监听的端口不通: 第一个原因:nginx1和nginx2两台服务器的服务没有正常启动
  vip ping不通: 核对是否出现裂脑,常见原因为防火墙配置所致导致多播心跳失败,核对keepalived的配置是否正确
  ```

- 特别注意： 需要关闭selinux，不然sh脚本可能不生效
  - getenforce 查看
  - setenforce 0 关闭