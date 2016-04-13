### FuzSub V1.1
+ AppName: FuzSub(Fuzz Sub-domain)
+ Create: 2015-04-08
+ Author: Dave, AAA

FuzSub可以通过用户输入的域名进行自动化Fuzz，并可根据用户自身需求选择爆破方式。例如:

    ➜  FuzSub git:(master) python3 Fuzz.py qq.com
    [*] FuzSub is hot.
    [*] Target: qq.com
    [*] TOP-LEVEL DOMAIN FUZZING...
    [+] <Found> 11.qq.com
    [+] <Found> 110.qq.com
    [+] <Found> 1111.qq.com
    [+] <Found> 114.qq.com
    [+] <Found> 12.qq.com
    [+] <Found> 123.qq.com
    [+] <Found> 1314.qq.com
    ...
    [*] Done!
    [*] Total Time Consumption: 0s


### Note

+ 默认进程数为30，可以根据自己机器的性能进行在源代码内进行调整。
+ 采用Gevent模式进行爆破提高效率
+ 建议在墙外使用本脚本，并采用8.8.8.8作为DNS。

### Update

+ 已经将该脚本部署在 [Fuzz All](http://www.fuzzall.com) 上，加入任务队列机制
