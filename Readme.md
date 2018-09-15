#Windows进程注入:  ConsoleWindowClass

[原文在这里](https://modexp.wordpress.com/2018/09/12/process-injection-user-data/)

##0x00 简介

每个窗口对象(tagWND)都有与之关联的一片内存区域,被称为UserData,通过`SetWindowLongPtr`和`GetWindowLongPtr`这两个API,并指定nIndex成员为 **GWLP_USERDATA ** 就可以访问该内存区域.

对于Console Window Host(控制台窗口宿主程序,在任务管理器中名为conhost.exe)来说,这片内存存放着一个结构体,该结构体包含着当前窗口的坐标,对象句柄,最重要的,Userdata的前8个字节(64位下)存放着一个虚函数表(vtable)的地址

该内存属于**可读写**的堆内存,这使得我们有机会覆盖一些函数地址,从而改变程序执行流程,达到注入的目的.


##0x01 ConsoleWindowClass

关于conhost.exe与一个控制台程序的关系可以参考https://baike.baidu.com/item/conhost.exe/3483885?fr=aladdin



打开一个cmd.exe

![](https://i.imgur.com/88hvmts.png)


在process explorer中我们可以看见cmd.exe 和conhost.exe的关系

![](https://i.imgur.com/XvnaQu9.png)

conhost的父进程为cmd.exe,cmd并不具有窗口对象

打开windbg,附加到id为13120的conhost.exe,按下F5恢复程序执行


编译运行以下代码
```
int pre_test()
{
	char* ClassName = NULL;
	int length = 0;


	do
	{
		//找到目标窗口
		HWND hWND = FindWindow(NULL, "命令提示符");
		if (NULL == hWND)
			break;

		//获得控制台宿主程序的Class Name,即"ConsoleWindowClass"
		ClassName = (char*)LocalAlloc(0, MAXMUM_CLASS_NAME);  //MAXMUM_CLASS_NAME =256
		if (NULL == ClassName)
			break;

		memset(ClassName, 0, MAXMUM_CLASS_NAME);

		length = GetClassName(hWND, ClassName, MAXMUM_CLASS_NAME);
		if (length == 0)
			break;
		printf("conhost class name: %s\r\n", ClassName);


		//获得userdata,使用windbg 的 dps poi(user_data)指令可以看见user_data处存放着一个vtable
		ULONG_PTR user_data = GetWindowLongPtr(hWND, GWLP_USERDATA);


		//在userdata处下读断点后向窗口发送该消息,可以发现其中一个虚函数 GetWindowHandle被调用
		SendMessage(hWND, WM_SETFOCUS, 0, 0);

	} while (FALSE);


	if (ClassName != NULL)
	{
		LocalFree(ClassName);
	}
	return 0;
}
```
首先局部变量ClassName的值为`"ConsoleWindowClass"`,这是所有conhost的窗口对象所属的CLASS

获得了user_data的值后,我们可以在windbg中使用dps指令dump出Userdata的一些信息

```
0:007> dps 0x0000020059431ff0
00000200`59431ff0  00007ff7`176ab0a8 conhost!Microsoft::Console::Interactivity::Win32::Window::`vftable'
00000200`59431ff8  00000200`593e73d0
00000200`59432000  00000000`00060dd4
00000200`59432008  00000000`00000000
00000200`59432010  0000007e`000001cc
00000200`59432018  0000025e`0000059d
00000200`59432020  00000000`00000000
00000200`59432028  00000000`00000000
00000200`59432030  00000000`00000000
00000200`59432038  00000000`00000000

```

很明显,能看到第一个符号就是vtable,现在我们转储出vtable里的函数指针

```
0:007> dps poi(0x0000020059431ff0)
00007ff7`176ab0a8  00007ff7`176540e0 conhost!Microsoft::Console::Interactivity::Win32::Window::EnableBothScrollBars
00007ff7`176ab0b0  00007ff7`17654060 conhost!Microsoft::Console::Interactivity::Win32::Window::UpdateScrollBar
00007ff7`176ab0b8  00007ff7`17653f80 conhost!Microsoft::Console::Interactivity::Win32::Window::IsInFullscreen
00007ff7`176ab0c0  00007ff7`1769e9a0 conhost!Microsoft::Console::Interactivity::Win32::Window::SetIsFullscreen
00007ff7`176ab0c8  00007ff7`17654100 conhost!Microsoft::Console::Interactivity::Win32::Window::SetViewportOrigin
00007ff7`176ab0d0  00007ff7`17653f70 conhost!Microsoft::Console::Interactivity::Win32::Window::SetWindowHasMoved
00007ff7`176ab0d8  00007ff7`1769e790 conhost!Microsoft::Console::Interactivity::Win32::Window::CaptureMouse
00007ff7`176ab0e0  00007ff7`1769e990 conhost!Microsoft::Console::Interactivity::Win32::Window::ReleaseMouse
00007ff7`176ab0e8  00007ff7`176531f0 conhost!Microsoft::Console::Interactivity::Win32::Window::GetWindowHandle
00007ff7`176ab0f0  00007ff7`17653f40 conhost!Microsoft::Console::Interactivity::Win32::Window::SetOwner
00007ff7`176ab0f8  00007ff7`1769e800 conhost!Microsoft::Console::Interactivity::Win32::Window::GetCursorPosition
00007ff7`176ab100  00007ff7`1769e7f0 conhost!Microsoft::Console::Interactivity::Win32::Window::GetClientRectangle
00007ff7`176ab108  00007ff7`1769e970 conhost!Microsoft::Console::Interactivity::Win32::Window::MapPoints
00007ff7`176ab110  00007ff7`1769e7e0 conhost!Microsoft::Console::Interactivity::Win32::Window::ConvertScreenToClient
00007ff7`176ab118  00007ff7`176a0570 conhost!Microsoft::Console::Interactivity::Win32::Window::SendNotifyBeep
00007ff7`176ab120  00007ff7`17653ee0 conhost!Microsoft::Console::Interactivity::Win32::Window::PostUpdateScrollBars

```


如何触发这些虚函数的执行呢,答案就是向conhost的窗口发送对应的信息,对vtable下读取断点
```
0:007> ba r 8 0x0000020059431ff0
```

单步执行代码中的`SendMessage(hWND, WM_SETFOCUS, 0, 0);`

触发断点:

```
Breakpoint 0 hit
conhost!Microsoft::Console::Interactivity::Win32::Window::ConsoleWindowProc+0x777:
00007ff7`17653b27 488b4040        mov     rax,qword ptr [rax+40h] ds:00007ff7`176ab0e8={conhost!Microsoft::Console::Interactivity::Win32::Window::GetWindowHandle (00007ff7`176531f0)}
```

当我们向conhost窗口发送WM_SETFOCUS信息时,虚函数表中的GetWindowHandle将得到执行,由于Userdata的内存是可写的,所以可以容易的实现shellcode的执行


需要指出的是,GetWindowHandle函数不接受任何参数,是理想的覆盖点,所以我们这次的演示将覆盖GetWindowHandle函数

#0x02 代码

我对原作者的代码做了一点小修改,主要是加入了pre_test(),这是为了方便在windbg中进行调试,顺便也对一些函数参数做了修改,现在代码支持指定conhost的窗口名来寻找目标conhost

