# boolSQL

boolSQL是一款支持Mysql、SQL Server、Oracle、DB2、Access、SQLite、PostgreSQL、Sybase八种数据库注入的脚本，脚本支持自动识别数据库的功能。目前支持GET和POST两种请求方式的注入。
##### 使用方法
```
python3 boolSQL.py -r ppack.txt
```
在手工测试确定存在bool注入后，将(1=1)替换为($)，然后将完整数据包放入指定文件内即可。

![image-20220914161602810](/Users/micanpu/Library/Application Support/typora-user-images/image-20220914161602810.png) 