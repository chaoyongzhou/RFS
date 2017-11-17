# RFS
RFS- Random Access File System


【介绍】

RFS是一个面向小文件的高性能存储系统，文件带目录存储。

定义：在RFS中，小文件是指不超过64MB大小的文件。 

通常， 一个RFS进程管理一块磁盘，RFS以宿主机的目录为准，元数据和用户文件数据存于此目录下。

RFS进程由name node和data node构成。单个data node最大支持64TB存储空间，单个name node最大支持的文件数约为830万个。
以管理4T磁盘为例，一个RFS进程可以由两个name node，一个data node构成，最大支持1600万个文件。 

【架构图】

略

【编译】

环境：centos 5.8及以上
依赖包：libxml2-devel, pcre-devel, expat-devel, openssl-devel, readline

需要编译生成三个可执行文件：

（1）编译RFS主可执行文件

	make rfs -f Makefile.rfs

（2）编译RFS的CONSOLE口执行文件

	make rfs_console -f Makefile.console

（3）编译RFS元数据创建工具可执行文件

	make rfs_tool -f Makefile.tool


【创建】

RFS主要有三个可执行文件和一个配置文件构成。

配置文件在bin目录下，名为config.xml。缺省运行无须修改配置。

以单个RFS，元数据的创建过程分两步进行：

（1）路径划分

     假定RFS管理的宿主机的目录为: /data/rnode1

     创建目录： make -p /data/rnode1/rfs00


（2）创建元数据

	 创建一个支持25万个小文件、管理1TB磁盘的RFS：

	 ./rfs_tool "set loglevel 5;open rfs /data/rnode1 ;create np 4 1;create dn;add disk 0;close rfs"


【启停】

（1） RFS启动

	./rfs -tcid 10.10.67.18 -node_type rfs -rfs_path /data/rnode1 -sconfig ./config.xml -logp . -d

（2） RFS停止

	kill -15 <RFS进程号>

【使用】

 RFS提供三种访问接口

 （1） RESTFUL API接口

   举例：

   写文件：	  curl -d "hello world" http://127.0.0.1:718/rfs/setsmf/top/level01/level02/level03/a.dat

   读文件：   curl -v http://127.0.0.1:718/rfs/getsmf/top/level01/level02/level03/a.dat
   
   列举文件： curl -v http://127.0.0.1:718/rfs/qtree/top/level01/level02/level03
   
   删文件：   curl -v http://127.0.0.1:718/rfs/dsmf/top/level01/level02/level03/a.dat
   
   删目录：	  curl -v http://127.0.0.1:718/rfs/ddir/top/level01 


（2）CONSOLE口
 
 启动CONSOLE口： ./rfs_console -tcid 0.0.0.64

 举例：

 查看name node信息：hsrfs 0 show npp on tcid 10.10.67.18 at console

 查看data node信息：hsrfs 0 show dn on tcid 10.10.67.18 at console


（3）BGN接口：
 
 RFS是BGN平台的一个模块，因此自动具备BGN接口访问能力。具体略。
