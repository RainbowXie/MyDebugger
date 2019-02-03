# 调试器使用手册
## 一、用户可输入的命令列表
| 序号 | 命令名 |	命令码 | 英文说明 | 参数1 | 参数2 | 参数3 |  
| --- | --- | --- | --- | --- | --- | --- |  
| 1 |	单步步入 | t | Step | 无 |	| |  
| 2 | 单步步过 | p | Step | Go | 无 | |  	 　
|3 | 运行 |	g|Run|	无/地址	　	　|||	　	　	　	　
|4|	反汇编 |u	|Display Asmcode|	无/地址	　	|　||
|5|	显示内存数据 |	dd	|Display Data|	无/地址	　|	||　
|6|	寄存器 |r	|Register|	无	　|	　||
|7|	修改内存数据 |e|	Edit Data|	无/地址	|	||	　	　	　	　
|8|	一般断点 |bp|	Break Point|	地址|	||	　
|9|	一般断点列表 |bpl|	Bp List|	无	|　	　||
|10| 删除一般断点 |bpc|	Clear bp|	序号|	　	||　	　	　	　
|11| 硬件断点 |bh|	Bp Hard|　	地址|	断点长度(1,2,4)|	e(执行)/w(写入)/a(访问)|
|12| 硬件断点列表 |bhl	|Bp Hard List|　	无|　	||　
|13| 删除硬件断点 |	bhc	|Clear Bp Hard| 	序号|	　	||　	　	　	　	　
|14| 内存断点 |	bm	Bp |Memory|　	地址|	长度|	r(读)/w(写)|
|15| 内存断点列表 |	bml	|Bp Memory List|　	无	|　||	　
|16| 分页断点列表 |	bmpl|	Bp Page List|　	无|	　||	　
|17| 删除内存断点 |	bmc|	Clear bp Memory|	序号|		||　
|18| 导入脚本 |	ls	|Load Script|	无|　||	　	　
|19| 导出脚本 |	es	|Export Script|	无|　||	　	　
|20| 退出程序 |　	q　|	　Quit|	无|　||	　	　
|21|查看模块 |	Ml	|Module List|	无|		||
|22| API提示 |	|||||				
|23| 自动跟踪 |	trace |||||
