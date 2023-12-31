# 基于原生Win32 API实现的Process Hooker

本仓库是基于原生Win32实现的API hooking，使用C/C++编写，Visual Studio 2022编译。

写Process Hooker的缘由主要是之前用过提取Galgame/visual novel文本的[MisakaHookFinder](https://github.com/hanmin0822/MisakaHookFinder)，但是不能提取到秽翼的尤斯蒂娅的文本（提取出来是乱码），让人很困惑，所以想自己动手写一个试试效果如何。单论秽翼的话，使用本项目的DLL来Hook文本是没问题的。

当然，本项目并没有使用到开源库的代码，全部是从头开始实现的。

### 快速开始

从Release下载用于Hook的DLL和主程序，然后将`HookDll.dll`放置在要提取文本的程序目录

然后打开主窗口程序，选中要Hook的进程（如果不知道哪个进程是要找的，可以使用Windows的Process Explorer选中查看）。此时可以看见选中的进程详细信息：

![](https://files.catbox.moe/86ank5.png)

之后点击API Hooking!按钮即可。运行信息和获取的文本会显示在下面的文本框中。

![](https://files.catbox.moe/z5wp7d.png)

### 开发细节

Win32设计UI很麻烦，但直接调用操作系统的底层API很方便。

本仓库使用基于创建远程线程的**DLL注入**和**inline hook**实现API hooking，这两部分都不是很复杂，如果有人感兴趣直接看源码就好，我写了很详细的注释。

注意：为了方便扩展，并不是所有的代码都被调用。

编译环境是visual studio 2022和Windows SDK 10，不需要其他依赖。
