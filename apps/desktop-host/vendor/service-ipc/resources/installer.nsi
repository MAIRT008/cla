; 产品网络服务的 Tauri NSIS 安装器钩子，由 tauri.conf.json 的 bundle.windows.nsis.installerHooks 引入。
; 改自上游 resources/installer.nsi：不再是独立安装器，也没有构建期占位替换。批准用户由安装助手取安装器所在会话的桌面用户，
; 不取提权令牌的用户；宿主程序路径在安装时取实际值，作为带引号的参数交给安装助手，由它再严格校验。
; 只调用本产品服务目录下的安装、卸载助手；不碰上游服务、不改网络；只结束本产品自己的桌面程序（先征得同意）。
;
; 依据 Tauri 2.11.5 模板（evidence/development/rc6-round3/upstream-tauri-2.11.5/installer.nsi）的实际顺序：
; - 本文件在模板定义 ${UNINSTKEY}、${MAINBINARYNAME}、${VERSION} 等常量之前被 include。顶层函数编译时还没有这些常量，
;   只能用变量；常量只在钩子宏里用（宏插进区段时才展开）。
; - 预安装钩子在模板的「应用是否在运行」检查和文件复制之前执行，后安装钩子在区段末尾。
; - 模板没有占用 .onInstFailed，也没设 AllowSkipFiles。
; - 新安装器从不带 /UPDATE 调旧卸载器：升级时用户选「先卸载」就是一次普通卸载（要明确选择停止管理），选「不卸载」就走这里的维护流程。
;
; 修复与升级：先关掉正在运行的桌面程序，把整个安装目录复制到旁边的 <安装目录>.rollback，再在它旁边写下标记 <安装目录>.rollback.ini
; （独立文件，不随目录交换），然后由现有助手确认保护、备份安装记录与运行状态、停服务。从停服务到提交之间任何一步失败——
; 新版本起不来、模板的应用检查被取消、文件写不进后选了取消、安装中断后再次运行——都整份换回旧版、复原卸载项版本号，
; 再由旧助手复原安装记录并启动旧服务。标记只在提交或旧助手成功之后删除，中途任何一刻中断，下次运行都从标记接着恢复。
; 每次 ExecWait 之前先把退出码置为 -1：程序启动不了时 ExecWait 不改写这个变量，残留的 0 会被当成成功。

!include LogicLib.nsh

!define STEWARD_STATE_NAME "ai-environmental-steward-service"

; 文件写不进时只能重试或取消：跳过会留下新旧混装的安装目录。
AllowSkipFiles off

Var StewardProgramData
Var StewardLogDir
Var StewardLog
Var StewardTemp
Var StewardName
Var StewardLen
Var StewardHandle
Var StewardMode
Var StewardInstalled
Var StewardExit
Var StewardBackup
Var StewardMarker
Var StewardFlags
Var StewardMaintenance
Var StewardUninstKey
Var StewardFailed
Var StewardRollbackContext
Var StewardRestored

; 安装器日志：<ProgramData>\ai-environmental-steward-service\logs\installer-<唯一名>.log，统一日志收集会带走它。
!macro STEWARD_OPEN_LOG_BODY
  ReadEnvStr $StewardProgramData ProgramData
  StrCpy $StewardLogDir "$StewardProgramData\${STEWARD_STATE_NAME}\logs"
  CreateDirectory $StewardLogDir
  GetTempFileName $StewardTemp $StewardLogDir
  StrLen $StewardLen $StewardLogDir
  IntOp $StewardLen $StewardLen + 1
  StrCpy $StewardName $StewardTemp "" $StewardLen
  StrCpy $StewardName $StewardName -4
  StrCpy $StewardLog "$StewardLogDir\installer-$StewardName.log"
  Rename $StewardTemp $StewardLog
!macroend

!macro STEWARD_LOG TEXT
  FileOpen $StewardHandle $StewardLog a
  FileSeek $StewardHandle 0 END
  FileWrite $StewardHandle "${TEXT}$\r$\n"
  FileClose $StewardHandle
  DetailPrint "${TEXT}"
!macroend

Function StewardOpenLog
  !insertmacro STEWARD_OPEN_LOG_BODY
FunctionEnd

Function un.StewardOpenLog
  !insertmacro STEWARD_OPEN_LOG_BODY
FunctionEnd

; 回到维护前的完整旧版本，分两段；标记 $StewardMarker 在安装目录旁边、不随目录交换，一直留到第二段成功：
; 1. 副本还在：让安装目录里现有的助手停服务，离开安装目录，把当前目录整个改名挪开、把副本整个改名放回。
;    用改名对调而不是先删：目录里有文件被占用时第一次改名整步失败、什么都不动，副本与标记留着，下次运行安装包会先回滚。
; 2. 写回卸载项版本号，由放回来的旧助手复原安装记录与运行状态并启动旧服务。它退出码为 0 才删标记、才算恢复；
;    否则标记留着，下次运行发现副本已经不在，就直接重做这一段，不开新维护、不覆盖原来的状态备份。
; 只回滚一次：一开始就清掉维护标志。这里不调插件（模板在 include 本文件之后才加入插件目录）；需要关掉桌面程序的地方由调用方在钩子宏里先做。
; $StewardRollbackContext 为 recover（上次维护或回滚没有完成，本次安装随后继续）时，成功只记日志，不弹成功提示。
Function StewardRollback
  StrCpy $StewardMaintenance "0"
  StrCpy $StewardRestored "0"
  StrCpy $StewardFailed "$INSTDIR.failed"
  !insertmacro STEWARD_LOG "rollback.begin to=$StewardInstalled context=$StewardRollbackContext"
  DetailPrint "维护没有完成：回到原来的版本 $StewardInstalled。"
  ${If} ${FileExists} "$StewardBackup\*.*"
    ${If} ${FileExists} "$INSTDIR\service\ai-environmental-steward-service-install.exe"
      StrCpy $StewardExit "-1"
      ExecWait '"$INSTDIR\service\ai-environmental-steward-service-install.exe" --action stop-for-rollback' $StewardExit
      !insertmacro STEWARD_LOG "rollback.stop exit=$StewardExit"
    ${EndIf}
    SetOutPath "$TEMP"
    RMDir /r "$StewardFailed"
    ClearErrors
    ${If} ${FileExists} "$INSTDIR\*.*"
      Rename "$INSTDIR" "$StewardFailed"
    ${EndIf}
    ${If} ${Errors}
      !insertmacro STEWARD_LOG "rollback.in_use"
      MessageBox MB_OK|MB_ICONSTOP "维护没有完成，安装目录里还有文件正被占用，暂时没能换回原来的版本；产品网络服务暂停，受保护程序保持阻断。请关闭所有 AI Environmental Steward 窗口后重新运行本安装包，它会先把原来的版本 $StewardInstalled 整份放回。$\r$\n日志：$StewardLog" /SD IDOK
      Return
    ${EndIf}
    Rename "$StewardBackup" "$INSTDIR"
    ${If} ${Errors}
      Rename "$StewardFailed" "$INSTDIR"
      !insertmacro STEWARD_LOG "rollback.restore_failed"
      MessageBox MB_OK|MB_ICONSTOP "维护没有完成，也没能把原来的版本放回去。原版本的完整副本在 $StewardBackup：请关闭所有 AI Environmental Steward 窗口后重新运行本安装包；仍失败时把这个目录改名为 $INSTDIR，再重新运行上一版安装包修复。$\r$\n日志：$StewardLog" /SD IDOK
      Return
    ${EndIf}
    RMDir /r "$StewardFailed"
    !insertmacro STEWARD_LOG "rollback.swapped"
  ${EndIf}
  WriteRegStr SHCTX "$StewardUninstKey" "DisplayVersion" "$StewardInstalled"
  StrCpy $StewardExit "-1"
  ExecWait '"$INSTDIR\service\ai-environmental-steward-service-install.exe" --action rollback-upgrade' $StewardExit
  !insertmacro STEWARD_LOG "rollback.helper exit=$StewardExit"
  ${If} $StewardExit == "0"
    Delete "$StewardMarker"
    StrCpy $StewardRestored "1"
    !insertmacro STEWARD_LOG "rollback.done"
  ${EndIf}
  ${If} $StewardRestored != "1"
    MessageBox MB_OK|MB_ICONSTOP "原来的版本 $StewardInstalled 已整份放回，但旧版安装助手没能复原服务状态并启动服务；产品网络服务暂停时受保护程序保持阻断。重新运行本安装包会从这一步继续恢复；仍失败时请用 support\collect-logs.cmd -Export -CaseId upgrade 导出日志后联系支持。$\r$\n日志：$StewardLog" /SD IDOK
  ${ElseIf} $StewardRollbackContext == "recover"
    DetailPrint "上一次安装没有完成，已经回到原来的版本 $StewardInstalled，现在继续安装。"
  ${Else}
    MessageBox MB_OK|MB_ICONEXCLAMATION "维护没有完成，已经回到原来的版本 $StewardInstalled：桌面程序、页面、控制端、服务与安装记录都已复原，服务在运行。$\r$\n日志：$StewardLog" /SD IDOK
  ${EndIf}
FunctionEnd

; 安装在维护阶段失败或被中止（模板的应用检查被取消、文件写不进后选了取消、后安装钩子回滚后以失败结束）时由 NSIS 调用。
; 后安装钩子自己回滚过的，维护标志已经清掉，这里不再做一次。
Function .onInstFailed
  ${If} $StewardMaintenance == "1"
    StrCpy $StewardRollbackContext "failed"
    Call StewardRollback
  ${EndIf}
FunctionEnd

; 停服务之前先关掉正在运行的桌面程序：模板自己的应用检查排在预钩子之后，用户在那里取消时服务已经停了。
; 在这里取消就在停服务之前退出，现有版本与保护都不动。插件调用与返回码沿用模板的 CheckIfAppIsRunning。
!macro STEWARD_CLOSE_RUNNING_APP
  !if "${INSTALLMODE}" == "currentUser"
    nsis_tauri_utils::FindProcessCurrentUser "${MAINBINARYNAME}.exe"
  !else
    nsis_tauri_utils::FindProcess "${MAINBINARYNAME}.exe"
  !endif
  Pop $StewardExit
  ${If} $StewardExit = 0
    ${If} $PassiveMode <> 1
      ${If} ${Cmd} `MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION "${PRODUCTNAME} 正在运行。点「确定」关闭它并继续；点「取消」退出，现有版本与保护都不变。" /SD IDOK IDCANCEL`
        !insertmacro STEWARD_LOG "app_check.cancelled"
        Abort "已取消：${PRODUCTNAME} 仍在运行，现有版本与保护都不变。"
      ${EndIf}
    ${EndIf}
    !if "${INSTALLMODE}" == "currentUser"
      nsis_tauri_utils::KillProcessCurrentUser "${MAINBINARYNAME}.exe"
    !else
      nsis_tauri_utils::KillProcess "${MAINBINARYNAME}.exe"
    !endif
    Pop $StewardExit
    Sleep 500
    ${If} $StewardExit <> 0
    ${AndIf} $StewardExit <> 2
      !insertmacro STEWARD_LOG "app_check.cannot_close exit=$StewardExit"
      Abort "没能关闭正在运行的 ${PRODUCTNAME}，现有版本与保护都不变。"
    ${EndIf}
    !insertmacro STEWARD_LOG "app_check.closed"
  ${EndIf}
!macroend

; 维护准备：先把整个安装目录（桌面程序、页面、控制端、服务、内核、许可、卸载程序）复制到回滚副本并写下标记，
; 成功后才让现有助手确认保护、备份安装记录与运行状态、停服务。停服务之前任何一步失败都删掉副本并中止，现有版本照常运行；
; 服务停下之后才进入需要回滚的阶段。停服务期间 WFP 基线阻断仍在。
!macro STEWARD_MAINTENANCE_BEGIN
  RMDir /r "$StewardBackup"
  CreateDirectory "$StewardBackup"
  ClearErrors
  CopyFiles /SILENT "$INSTDIR\*.*" "$StewardBackup"
  WriteINIStr "$StewardMarker" "maintenance" "version" "$StewardInstalled"
  ${If} ${Errors}
    !insertmacro STEWARD_LOG "maintenance.backup_failed"
    Delete "$StewardMarker"
    RMDir /r "$StewardBackup"
    MessageBox MB_OK|MB_ICONSTOP "没能备份现有安装（磁盘空间或权限不足）。安装已中止，现有版本照常运行。$\r$\n日志：$StewardLog" /SD IDOK
    Abort
  ${EndIf}
  !insertmacro STEWARD_LOG "maintenance.backup_ready version=$StewardInstalled"
  DetailPrint "维护阶段：确认保护后暂停产品网络服务以替换程序；受保护程序在此期间保持阻断。"
  StrCpy $StewardExit "-1"
  ExecWait '"$INSTDIR\service\ai-environmental-steward-service-install.exe" --action prepare-upgrade' $StewardExit
  ${If} $StewardExit != "0"
    !insertmacro STEWARD_LOG "maintenance.refused exit=$StewardExit"
    Delete "$StewardMarker"
    RMDir /r "$StewardBackup"
    MessageBox MB_OK|MB_ICONSTOP "无法进入维护阶段（保护没有确认，或服务停不下来）。安装已中止，现有版本照常运行。$\r$\n日志：$StewardLog" /SD IDOK
    Abort
  ${EndIf}
  StrCpy $StewardMaintenance "1"
  !insertmacro STEWARD_LOG "maintenance.service_stopped"
!macroend

; 替换文件之前。标记还在说明上次维护或回滚没有完成（安装中断、断电、进程被结束，或旧助手没能复原服务）：
; 副本还在就整份换回，已经换回就只重做旧助手那一段；恢复不成就中止，不开新维护、不覆盖原来的状态备份。
; 已装过本产品就进入维护阶段；同版本是修复，不同版本是升级。
!macro NSIS_HOOK_PREINSTALL
  Call StewardOpenLog
  StrCpy $StewardUninstKey "${UNINSTKEY}"
  StrCpy $StewardMaintenance "0"
  StrCpy $StewardMode "install"
  StrCpy $StewardBackup "$INSTDIR.rollback"
  StrCpy $StewardMarker "$INSTDIR.rollback.ini"
  ${If} ${FileExists} "$StewardMarker"
  ${OrIf} ${FileExists} "$INSTDIR\service\ai-environmental-steward-service-install.exe"
    !insertmacro STEWARD_CLOSE_RUNNING_APP
  ${EndIf}
  ${If} ${FileExists} "$StewardMarker"
    ReadINIStr $StewardInstalled "$StewardMarker" "maintenance" "version"
    !insertmacro STEWARD_LOG "maintenance.unfinished_found version=$StewardInstalled"
    StrCpy $StewardRollbackContext "recover"
    Call StewardRollback
    ${If} $StewardRestored != "1"
      Abort "上一次安装没有完成，原来的版本 $StewardInstalled 还没有完全恢复；标记与副本都保留，下次运行本安装包会继续恢复。"
    ${EndIf}
  ${EndIf}
  ${If} ${FileExists} "$INSTDIR\service\ai-environmental-steward-service-install.exe"
    ReadRegStr $StewardInstalled SHCTX "${UNINSTKEY}" "DisplayVersion"
    !insertmacro STEWARD_MAINTENANCE_BEGIN
    ${If} $StewardInstalled == "${VERSION}"
      StrCpy $StewardMode "repair"
    ${Else}
      StrCpy $StewardMode "upgrade"
    ${EndIf}
  ${EndIf}
  ; 回滚为了改名会把输出目录切到 $TEMP；模板接下来的 File 解压到当前输出目录，这里切回安装目录。
  SetOutPath "$INSTDIR"
  !insertmacro STEWARD_LOG "install.mode $StewardMode installed=$StewardInstalled new=${VERSION}"
!macroend

; 替换文件之后：新装、同版本修复与升级分别调用安装助手；批准用户由助手取本会话的桌面用户。
; 成功时先删标记（提交），再删副本；修复与升级失败时回到完整旧版本并以失败结束；新装失败时如实提示。
; 用户在应用里确认「启用监测与保护」之前，服务不应用代理、TUN 或 WFP。
!macro NSIS_HOOK_POSTINSTALL
  !insertmacro STEWARD_LOG "service.setup mode=$StewardMode"
  StrCpy $StewardExit "-1"
  ${If} $StewardMode == "upgrade"
    ExecWait '"$INSTDIR\service\ai-environmental-steward-service-install.exe" --action complete-upgrade --user-from-session --host-exe "$INSTDIR\${MAINBINARYNAME}.exe"' $StewardExit
  ${ElseIf} $StewardMode == "repair"
    ExecWait '"$INSTDIR\service\ai-environmental-steward-service-install.exe" --action repair --user-from-session --host-exe "$INSTDIR\${MAINBINARYNAME}.exe"' $StewardExit
  ${Else}
    ExecWait '"$INSTDIR\service\ai-environmental-steward-service-install.exe" --action install --user-from-session --host-exe "$INSTDIR\${MAINBINARYNAME}.exe"' $StewardExit
  ${EndIf}
  !insertmacro STEWARD_LOG "service.setup_done mode=$StewardMode exit=$StewardExit"
  ${If} $StewardExit == "0"
    ${If} $StewardMaintenance == "1"
      StrCpy $StewardMaintenance "0"
      Delete "$StewardMarker"
      RMDir /r "$StewardBackup"
      !insertmacro STEWARD_LOG "maintenance.committed"
    ${EndIf}
  ${ElseIf} $StewardMode == "install"
    MessageBox MB_OK|MB_ICONSTOP "产品网络服务没有安装或启动成功，网络功能暂不可用。请用 support\collect-logs.cmd -Export -CaseId install 导出日志后联系支持。$\r$\n日志：$StewardLog" /SD IDOK
    Abort
  ${Else}
    StrCpy $StewardRollbackContext "failed"
    Call StewardRollback
    Abort
  ${EndIf}
!macroend

; 卸载开始。必须明确选择停止管理并恢复原网络；选「否」取消卸载，保护与服务保持不变。
; 确认之后先关掉正在运行的桌面程序（模板的应用检查排在本钩子之后，在那里取消会留下一个没有服务的安装），再撤保护、删服务。
; 勾了删除应用数据才删服务状态。
!macro NSIS_HOOK_PREUNINSTALL
  Call un.StewardOpenLog
  MessageBox MB_YESNO|MB_ICONEXCLAMATION|MB_DEFBUTTON2 "卸载会停止管理并恢复原网络：撤除本应用对受保护程序的阻断，停止并删除产品网络服务。$\r$\n本应用的报告、恢复材料与日志默认保留（除非勾选删除应用数据），项目资料不动。$\r$\n$\r$\n继续卸载请选「是」；要保留保护请选「否」，卸载将取消。" /SD IDYES IDYES steward_uninstall_confirmed
  !insertmacro STEWARD_LOG "uninstall.cancelled_by_user"
  Abort "已取消卸载：本应用的保护与服务保持不变。"
  steward_uninstall_confirmed:
  !insertmacro STEWARD_CLOSE_RUNNING_APP
  ${If} $DeleteAppDataCheckboxState = 1
    StrCpy $StewardFlags "--release-protection --delete-state"
  ${Else}
    StrCpy $StewardFlags "--release-protection"
  ${EndIf}
  !insertmacro STEWARD_LOG "uninstall.release flags=$StewardFlags"
  StrCpy $StewardExit "-1"
  ExecWait '"$INSTDIR\service\ai-environmental-steward-service-uninstall.exe" $StewardFlags' $StewardExit
  ${If} $StewardExit != "0"
    !insertmacro STEWARD_LOG "uninstall.refused exit=$StewardExit"
    MessageBox MB_OK|MB_ICONSTOP "没能证明产品网络服务已停止、本应用的网络保护已撤净，卸载已中止；服务已重新启动并保持管理，不会留下无人处理的阻断。$\r$\n可以重试卸载；仍失败时请用 support\collect-logs.cmd -Export -CaseId uninstall 导出日志后联系支持。$\r$\n日志：$StewardLog" /SD IDOK
    Abort
  ${EndIf}
!macroend

; 卸载结束：删掉可能残留的回滚标记、副本与换下来的目录；数据按勾选保留或已由卸载助手删除。
!macro NSIS_HOOK_POSTUNINSTALL
  Delete "$INSTDIR.rollback.ini"
  RMDir /r "$INSTDIR.rollback"
  RMDir /r "$INSTDIR.failed"
  ${If} $DeleteAppDataCheckboxState <> 1
    !insertmacro STEWARD_LOG "uninstall.done data_kept"
  ${EndIf}
!macroend
