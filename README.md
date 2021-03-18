# BaiduNetdiskAutoSaver

百度盘保存自动化工具：

详细介绍请参考：


>**老规矩，多说无益，直接亮成品**
![在这里插入图片描述](https://img-blog.csdnimg.cn/20190624133415205.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L01yX0p1bmU=,size_16,color_FFFFFF,t_70)

#### 一、背景分析

>相信做过爬虫的各位都会发现各大网站为了缓解自家服务器压力，而将我们需要的保存在云盘中，仅以分享分享链接的方式来分享文件。其中云盘分享又以百度云盘最为常见。
>
>
>虽然说百度网盘除了限速等方面不够良心外，对普通用户还是比较善良的。但是，对于拥有大量链接需要进行保存的用户则不够方便。因此，一个自动保存的工具便十分有存在的必要了。

#### 二、可行性分析
>经使用**fidder等抓包工具**分析百度云盘接口，可以发现：
>

>1、百度云保存所需字段需要用户登录才能够请求获得
>2、百度云盘用户登录信息保存在Cookie中BDUSS字段中
>3、百度云盘用户保存指定链接有无**提取码**仅仅是所需字段能否直接请求到的区别
>4、存在**提取码**的链接，需要的是进行多个请求，请求到正确的Cookie中的一个字段后，用户便能够请求到该分享保存所需的字段
>
#### 三、流程设计
>1、首次登陆
>
```mermaid
flowchat
st=>start: 尝试登陆
e=>end: 登陆成功 保存Cookie
op=>operation: 进行登陆验证
cond=>condition: 验证成功？


st->op->cond
cond(yes)->e
cond(no)->op
```
>2、文件分析及保存
>
```mermaid
flowchat
st=>start: 加载Cookie信息
e=>end: 提取成功 保存至网盘指定目录
login=>operation: 登陆
op=>operation: 由分享链接提取所需字段
cond=>condition: 有无提取码？
anlink=>operation: 获取所需Cookie字段
acnd=>condition: 请求成功？


st->login->op->cond->anlink->acnd
cond(no)->e
cond(yes)->anlink
acnd(yes)->op
acnd(no)->anlink

```

>3、系统整体设计
>
```mermaid
flowchat
st=>start: 开始
e=>end: 退出
login=>operation: 进行登录，并保存Cookie
firststep=>operation: 加载现有Cookie进行登录
cond=>condition: 有无Cookie文件？
anlink=>operation: 加载Cookie字段，登陆成功
lcond=>condition: 登陆成功？
sharesave=>operation: 保存分享文件
acnd=>condition: 需要保存下一个？


st->firststep->cond->login->lcond->anlink->sharesave->acnd
cond(no)->login
cond(yes)->anlink
lcond(yes)->anlink
lcond(no)->login
acnd(yes)->sharesave
acnd(no)->e

```
#### 四、一些建议

>###### 1、内容请求函数的建议
>相信有时候大家都会因为爬虫网络请求过程中，由于访问过于频繁等原因，会出现对方服务器拒绝连接，而导致连接中断，程序报错停止等问题。这在爬虫过程中是致命的。
>在这里给出一种解决方案，仅供参考

```python
//伪代码如下

def youRequest(url,maxFailTime=5,method='GET',parmas...):
	#进行监控
	try:
		#判断请求
		if 'get' in method.lower():
			#get请求
			resp=requests.get()
		elif 'post' ....   #其他请求同理
	except Exception:  #你想要捕捉的错误
		if maxFailTime < 0：
			return None
		else:
			print('错误信息，请求失败')  #打印提示信息
			time.sleep(5)              #暂停一会
			return youRequest(url,maxFailTime=maxFailTime-1,params)
	else:
		#请求成功  
		return resp
		
	

```

>**注意**：该方法需要检测请求得到的内容是否为空，但是这总比程序意外停止好吧。由于是批量保存，所以可以跳过。

>###### 2、结构的建议
>可以单独创建一个登陆的类，然后文件保存类继承这个类。当然以后要实现其他功能时，可以继承这个登陆类。

#### 五、最后

>感谢大家的阅读，该过程较为简单，**具体实现**以及**相关参数构造**可以自己通过抓包分析，当然也可以通过阅读博主后续博客。

>有需要的同学可以下载该工具
>**链接：https://blog.csdn.net/Mr_June/article/details/93487301**

>**再次谢谢大家愿意花费宝贵时间阅读本文**
