### FuzSub V2.0
+ AppName: FuzSub(Fuzz Sub-domain)
+ Create: 2015-04-08
+ Author: Dave, AAA

FuzSub可以通过用户输入的域名进行自动化Fuzz，并可根据用户自身需求选择爆破方式。例如:

```
➜  FuzSub git:(master) python fuzz.py alitrip.com
[*] FuzSub is hot.
[*] Target: alitrip.com
[+] Name Server:  ['ns4.taobao.com', 'ns5.taobao.com', 'ns6.taobao.com', 'ns7.taobao.com']
[*] Checking: alitrip.com NS: ns4.taobao.com
[*] Checking: alitrip.com NS: ns5.taobao.com
[*] Checking: alitrip.com NS: ns6.taobao.com
[*] Checking: alitrip.com NS: ns7.taobao.com
[*] < alitrip.com > FUZZING...
[*] Pan Analysis: [['sh.wagbridge.alitrip.com'], ['140.205.230.45']]
[+] <Found> 1111.alitrip.com	['113.107.235.241', '113.107.235.242', '113.107.239.108', '113.107.239.109', '183.61.180.195', '183.61.180.236']
[+] <Found> 61.alitrip.com	['119.147.69.236', '119.147.70.253', '121.14.89.253', '183.61.241.252']
[+] <Found> australia.alitrip.com	['140.205.250.51']
[+] <Found> bzy.alitrip.com	['106.11.55.235']
[+] <Found> decision.alitrip.com	['10.150.71.130']
...
[*] Done!
[*] Total Time Consumption: 0s
```

### TODO

+ 尝试控制域名枚举深度,即递归枚举到N级域名

### Usage

```
pip install -r requirements.txt
```

安装完Python的相关支持库之后就可以直接食用。

```
# 一级域名枚举
python fuzz.py qq.com
# 无穷极域名枚举
python fuzz.py qq.com full
```

### Feature

+ 支持Python 2.7 & 3.0+
+ 支持域传送漏洞检测
+ 较完美解决泛解析误报问题
+ 高效节能环保(在网络环境较好的情况80s跑完2.4W子域名)
+ 支持递归子域名枚举,即无穷级子域名爆破(python fuzz.py <DOMAIN> full)

### Note

+ `config.py`中设定线程数和DNS服务器
+ 默认进程数为50，可以根据自己机器的性能进行在源代码内进行调整。
+ 采用Gevent模式进行爆破提高效率
