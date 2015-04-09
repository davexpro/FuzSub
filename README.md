### FuzSub V1.0
+ AppName: FuzSub(Fuzz Sub-domain)
+ Create: 2015-04-08
+ Author: Dave, AAA

FuzSub可以通过用户输入的域名进行自动化Fuzz，并可根据用户自身需求选择爆破方式。例如:

    ➜  FuzSub git:(master) python Fuzz.py qq.com
    [*] FuzSub is hot.
    [*] Target: qq.com
    [*] TOP-LEVEL DOMAIN FUZZING...
    [+] <Discovered> 0.qq.com
    [+] <Discovered> 00.qq.com
    [+] <Discovered> 01.qq.com
    [+] <Discovered> 02.qq.com
    [+] <Discovered> 04.qq.com
    [+] <Discovered> 05.qq.com
    ...
    [*] Done!
    [*] Total Time Consumption: 0s

FuzSub暂时没有写输出部分，下一次更新将添加上。
