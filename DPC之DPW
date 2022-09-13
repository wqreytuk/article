Title: DPW是新的DPC，win10 21H1中的Deferred Procedure Wait
Date: 2022-09-13
Category: 逆向



翻译



references:

- [https://windows-internals.com/dpws-are-the-new-dpcs-deferred-procedure-waits-in-windows-10-21h1/](https://windows-internals.com/dpws-are-the-new-dpcs-deferred-procedure-waits-in-windows-10-21h1/)



windows 21H1代号Fe（铁），增加了一些有趣的特性，其中有一个比较有趣的特性——对象等待分发



新的构建版本引入了几个新的函数



- `KeRegisterObjectDpc` (despite the name, it’s an internal non-exported function)
- `ExQueueDpcEventWait`
- `ExCancelDpcEventWait`
- `ExCreateDpcEvent`
- `ExDeleteDpcEvent`



尽管`KeRegisterObjectDpc`函数名中有`e`，他仍然是一个内部函数，一般情况下，`Ke`中的`e`代表exported，即导出函数，也就是说可以直接使用GetProcAddress获取到该函数的地址并进行使用的



这些函数都服务于一个功能，等待一个对象并在该对象signaled时执行一个DPC



直到现在，如果一个驱动想要在一个对象上进行等待，那么他必须以同步的方式进行，也就是说需要阻塞，当前等待的线程会被设置为等待状态，直到被等待的对象signaled或者等待时间超时（或者apc执行了，如果这个wait是alertable的）



用户模式下的应用程序基本上都是这么工作的



尽管如此，从win8开始，也拥有执行异步等待的能力，这种能力是通过Thread Pool API来实现的



这个新引入的功能将I/O完成端口和一个叫做`Wait Packet`的东西联系在了一起，这样就不必阻塞线程了





21H1版本中的这些改变，通过引入内核模式下的异步等待，引入了一个内核模式级别的等待的关键改动：现在的驱动可以提供一个DPC，这个DPC会在被等待的事件对象signaled的时候执行，并且与此同时，线程不会被阻塞





## 运行机制



要想使用这个新功能，驱动必须要先初始化一个所谓的`DPC事件`，这个可以通过ExCreateDpcEvent函数来完成

```c
NTSTATUS
ExCreateDpcEvent (
    _Outptr_ PVOID *DpcEvent,
    _Outptr_ PKEVENT *Event,
    _In_ PKDPC Dpc
);
```

在内部，这个函数会分配一个没有文档的结构体，这里姑且称做`DPC_WAIT_EVENT`

```c
typedef struct _DPC_WAIT_EVENT
{
    KWAIT_BLOCK WaitBlock;
    PKDPC Dpc;
    PKEVENT Event;
} DPC_WAIT_EVENT, *PDPC_WAIT_EVENT;
```

ExCreateDpcEvent函数接受一个DPC，这个DPC必须事先由调用者进行初始化，初始化DPC的工作由函数KeInitializeDpc完成，（原作者忘了调用这个函数，浪费了一天的时间进行调试），

ExCreateDpcEvent会创建出来一个事件对象，并分配一个DPC_WAIT_EVENT结构体，返回给调用者（第一个传出参数），还会填充第三个参数，Dpc指针所指向的结构体，新创建出来的事件，设置等待阻塞状态为`WaitBlockInactive`



然后，驱动要调用ExQueueDpcEventWait函数，传递下面的结构



```c
BOOLEAN
ExQueueDpcEventWait (
    _In_ PDPC_WAIT_EVENT DpcEvent,
    _In_ BOOLEAN QueueIfSignaled
    )
{
    if (DpcEvent->WaitBlock.BlockState != WaitBlockInactive)
    {
        RtlFailFast(FAST_FAIL_INVALID_ARG);
    }
    return KeRegisterObjectDpc(DpcEvent->Event,
                               DpcEvent->Dpc,
                               &DpcEvent->WaitBlock,
                               QueueIfSignaled);
}
```

如上所示，这个函数非常简单，他解开传入的结构体，并将其内容发送给内部的函数`KeRegisterObjectDpc`

```c
BOOLEAN
KeRegisterObjectDpc (
    _In_ PVOID Object,
    _In_ PRKDPC Dpc,
    _In_ PKWAIT_BLOCK WaitBlock,
    _In_ BOOLEAN QueueIfSignaled
);
```

要想使用这个功能（DPW），那么`KWAIT_BLOCK`结构体将会保存一个`KDPC`到队列中，然后其中的`WAIT_TYPE`枚举类型应该是`WaitDpc`

```c
typedef struct _KWAIT_BLOCK
{
    LIST_ENTRY WaitListEntry;
    UCHAR WaitType;
    volatile UCHAR BlockState;
    USHORT WaitKey;
#if defined(_WIN64)
    LONG SpareLong;
#endif
    union {
        struct KTHREAD* Thread;
        struct KQUEUE* NotificationQueue;
        struct KDPC* Dpc;
    };
    PVOID Object;
    PVOID SparePtr;
} KWAIT_BLOCK, *PKWAIT_BLOCK, *PRKWAIT_BLOCK;

typedef enum _WAIT_TYPE
{
    WaitAll,
    WaitAny,
    WaitNotification,
    WaitDequeue,
    WaitDpc,
} WAIT_TYPE;
```

现在我们来看一下`KeRegisterObjectDpc`函数都干了啥



- 初始化
