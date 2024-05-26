---
share: "true"
---
# 漏洞介绍

CSV公式注入(CSV Injection)是一种会造成巨大影响的攻击向量，攻击者可以向Excel文件中注入可以输出或以CSV文件读取的恶意攻击载荷，当用户打开Excel文件时，文件会从CSV描述转变为原始的Excel格式，包括Excel提供的所有动态功能，在这个过程中，CSV中的所有Excel公式都会执行，当该函数有合法意图时，很易被滥用并允许恶意代码执行。

网站提供文件导出功能，但是却没有对导出的数据进行适当的过滤，攻击者可以通过修改供应商信息，联系方式等功能，来控制导出到本地CSV文件中的内容。通过应用程序将恶意的命令，函数插入到CSV文件中，打开文件会执行函数，造成系统命令执行，信息泄露等；

对单元格的内容进行特殊字符过滤（+-@=），确保单元格不以这些特殊字符开头；
# 漏洞复现

1. 在Office的"文件 —> 选项 —> 信任中心"处 开启"启用动态数据交换服务器启动"功能：
	{{< figure src="/static/Untitled (20).png"  width="625" height="">}}
2. 之后构造以下恶意载荷：
    ```jsx
    =1+cmd|' /C calc'!A0
    ```
   {{< figure src="/static/Untitled (21).png"  width="675" height="">}}
3. 保存后打开该文件，恶意载荷已被执行
	{{< figure src="/static/Untitled (22).png"  width="725" height="">}}
# 修复建议
1、确保单元格不以特殊字符（“+、-、@、=”）开头；
2、对单元格的内容进行特殊字符（“+、-、@、=”）过滤；
3、先对原始输入内容进行转义（双引号前多加一个双引号），然后在添加tab键和双引号防止注入；
4、禁止导出CSV、Excel格式；
5、导出为Excel格式前，利用代码把单元格的格式设置为文本（对CSV不生效）。
**防御措施面临的困难：**
1、对单元格内容进行处理势必会改变原始内容，对于需要数据导出后在导入其他系统进行执行的场景，对业务会有影响；
2、对于数据量大的场景，如果在导出进行过滤、转义等操作，会影响导出效率。

# 参考链接
[https://mp.weixin.qq.com/s/3jfyZgsmLomMDML2z9MpEA](https://mp.weixin.qq.com/s/3jfyZgsmLomMDML2z9MpEA)
[https://www.cnblogs.com/Eleven-Liu/p/12397857.html](https://www.cnblogs.com/Eleven-Liu/p/12397857.html)