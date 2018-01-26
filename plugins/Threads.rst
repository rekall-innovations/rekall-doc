
The **threads** plugin iterates over all processes and lists all threads in all
processes. This is the list walking version of the [thrdscan](ThrdScan.html)
plugin.


### Sample output

..  code-block:: text

     _ETHREAD       PID    TID Start Address  Process          Symbol
  -------------- ------ ------ -------------- ---------------- ------
  0xe00000089880      4      8 0xf802d3509ec8 System           nt!Phase1Initialization
  0xe0000011f040      4     12 0xf802d3154c04 System           nt!PopIrpWorkerControl
  0xe0000011f880      4     16 0xf802d312f868 System           nt!PopIrpWorker
  0xe0000011e040      4     20 0xf802d312f868 System           nt!PopIrpWorker
  0xe0000011e880      4     24 0xf802d31551c0 System           nt!PopFxEmergencyWorker
  0xe0000011d040      4     28 0xf802d3520f14 System           nt!ExpWorkerThreadBalanceManager
  0xe0000011d880      4     32 0xf802d30533a8 System           nt!ExpWorkerThread
  0xe0000011c880      4     36 0xf802d314cb04 System           nt!ExpWorkerFactoryManagerThread
  0xe00000120040      4     40 0xf802d3146fdc System           nt!KiExecuteDpc
  0xe00000120880      4     44 0xf802d314f764 System           nt!MiDereferenceSegmentThread
  0xe00000124040      4     48 0xf802d3151a8c System           nt!MiModifiedPageWriter
  0xe00000124880      4     52 0xf802d314de28 System           nt!KeBalanceSetManager
  0xe00000123040      4     56 0xf802d314bc18 System           nt!KeSwapProcessOrStack
  0xe00000122040      4     64 0xf802d314cd68 System           nt!CcQueueLazyWriteScanThread
  0xe00000122880      4     68 0xf802d3154b9c System           nt!FsRtlWorkerThread
  0xe00000121040      4     72 0xf802d3154b9c System           nt!FsRtlWorkerThread
  0xe00000133040      4     76 0xf802d3492540 System           nt!EtwpLogger
  0xe00000133880      4     80 0xf802d30533a8 System           nt!ExpWorkerThread
  0xe00000137040      4     84 0xf802d314c94c System           nt!MiMappedPageWriter
  ....


