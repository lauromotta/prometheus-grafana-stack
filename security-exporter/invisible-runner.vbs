' invisible-runner.vbs
' Roda o coletor de seguranca SEM janela de console (invisivel).
' Chamado pelo Agendador de Tarefas (CanarioSegurancaPrometheus) a cada 60s.
Option Explicit
Dim sh
Set sh = CreateObject("WScript.Shell")
sh.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -File ""D:\monitoring\security-exporter\collect-security-metrics.ps1""", 0, False
