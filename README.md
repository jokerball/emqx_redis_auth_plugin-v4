# emqx_redis_auth_plugin-v4

EMQX 4.4 Redis 鉴权插件，等价于 `unmtr369auth` 服务的 `POST /mqtt/verify` 逻辑，
注册在 `client.authenticate` 钩子上（优先级 1000，先于内置认证器执行）。

## 日志行为

| 事件 | 级别 | 输出位置 |
|---|---|---|
| 插件启动 / 停止 | info | `emqx.log` |
| Redis 连接失败 | warning（原因变化时、以及每 5 分钟提醒一次） | `emqx.log` |
| Redis 连接恢复 | 由 eredis 自身输出 | `emqx.log` |
| 鉴权成功 | info | 独立审计文件 |
| 鉴权失败 | warning | 独立审计文件 |

审计文件默认是 `log/emqx_plugin_redis_auth.log`（与 `emqx.log` 同目录），
内容形如：

```
2026-10-21T07:09:56.284Z [info] result=success clientid=dev-001 username=u1 peerhost={10,0,0,1} reason=allow
2026-10-21T07:09:56.284Z [warning] result=failure clientid=dev-002 username=dev-002 peerhost={10,0,0,2} reason=device_not_exists
```

失败原因取值：`conn_info_incomplete`、`unm_password_mismatch`、`device_not_exists`、
`main_channel_online`、`redis_error`。

注意：EMQX 内核在 `emqx_channel` 中还会为每次登录失败输出一条
`Client ... login failed` 的 warning，这条属于内核日志，不受本插件控制。

## 配置

配置文件：`etc/plugins/emqx_plugin_redis_auth.conf`。

```erlang
## 鉴权审计日志，留空表示关闭
redis_auth.auth_log_file = log/emqx_plugin_redis_auth.log

## 单个文件大小上限（字节）与保留的滚动文件数量
redis_auth.auth_log_max_size = 10485760
redis_auth.auth_log_max_files = 5
```

其余配置项（Redis 地址、密码、DB、连接池、业务键前缀、白名单、AES 密钥、
降级放行开关）见 `etc/emqx_plugin_redis_auth.conf` 与
`priv/emqx_plugin_redis_auth.schema`。

## 编译

作为 EMQX 社区插件编译：在 EMQX 源码树的 `lib-extra/plugins` 中声明依赖，
并把插件名加入 `Makefile` 的 `EMQX_EXTRA_PLUGINS`。单独编译：

```bash
make
```
