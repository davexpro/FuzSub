### FuzSub V1.0
+ AppName: FuzSub(Fuzz Sub-domain)
+ Create: 2015-04-08
+ Author: Dave, AAA

FuzSub可以通过用户输入的域名进行自动化Fuzz，并可根据用户自身需求选择爆破方式。例如:

    ➜  FuzSub git:(master) python Fuzz.py qq.com
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

+ Fuzz完成后，将输出一个精美的report界面，可在里面查看。
+ 默认进程数为64，可以根据自己机器的性能进行在源代码内进行调整。
+ 采用了Gevent(目前还在调试)，建议在非Win环境下使用。
+ 建议在墙外使用本脚本，并采用8.8.8.8作为DNS。

### Update

+ 添加了E-Mail Notification的功能(在output.py中进行设置)
