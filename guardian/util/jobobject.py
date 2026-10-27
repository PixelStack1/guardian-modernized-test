"""Job Object « tuer à la fermeture » (lot 8).

À l'init, Guardian se place lui-même (PAS le bootloader onefile, qui est son parent)
dans un Job Object marqué ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE``. Les processus
enfants (workers de capture, serveurs Manager…) héritent du job. Le seul handle
du job est détenu par ce processus et n'est pas héritable : quand Guardian meurt,
même par ``taskkill /F``, Windows ferme le handle et termine tous les enfants.
Les jobs imbriqués sont pris en charge depuis Windows 8 (si un job parent existe,
par ex. sur un runner CI, l'assignation reste possible).

Fail-open : toute erreur est journalisée et Guardian continue sans job (les chiens
de garde parentwatch restent en place).
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any

logger = logging.getLogger(__name__)

JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
JobObjectExtendedLimitInformation = 9

_job_handle: Any = None  # gardé ouvert pendant toute la vie du processus
_held: Any = None  # dans un worker : handle sur le job du GUI (retarde le kill)
JOB_NAME_ENV = "GUARDIAN_JOB_NAME"  # hérité par les enfants lancés ensuite
JOB_OBJECT_QUERY = 0x0004


def _structs() -> tuple[Any, Any]:
    import ctypes
    from ctypes import wintypes

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            (n, ctypes.c_ulonglong)
            for n in (
                "ReadOperationCount",
                "WriteOperationCount",
                "OtherOperationCount",
                "ReadTransferCount",
                "WriteTransferCount",
                "OtherTransferCount",
            )
        ]

    class BASIC(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
            ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class EXTENDED(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BASIC),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    return EXTENDED, wintypes


def kill_children_with_me(kernel32: Any = None) -> bool:
    """Place le processus courant dans un job kill-on-close. True si actif."""
    global _job_handle
    if _job_handle is not None:
        return True
    try:
        import ctypes

        extended, wt = _structs()
        if kernel32 is None:
            if sys.platform != "win32":
                return False
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateJobObjectW.restype = wt.HANDLE
            kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wt.LPCWSTR]
            kernel32.SetInformationJobObject.argtypes = [
                wt.HANDLE,
                ctypes.c_int,
                ctypes.c_void_p,
                wt.DWORD,
            ]
            kernel32.GetCurrentProcess.restype = wt.HANDLE
            kernel32.AssignProcessToJobObject.argtypes = [wt.HANDLE, wt.HANDLE]
            kernel32.CloseHandle.argtypes = [wt.HANDLE]
        name = f"Local\\GuardianKillJob-{os.getpid()}"
        job = kernel32.CreateJobObjectW(None, name)  # handle non héritable
        if not job:
            raise OSError(f"CreateJobObjectW failed ({ctypes.get_last_error()})")
        info = extended()
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            kernel32.CloseHandle(job)
            raise OSError(f"SetInformationJobObject failed ({ctypes.get_last_error()})")
        if not kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess()):
            kernel32.CloseHandle(job)
            raise OSError(
                f"AssignProcessToJobObject failed ({ctypes.get_last_error()})"
            )
        _job_handle = job
        os.environ[JOB_NAME_ENV] = name
        logger.info("Kill-on-close job active: children die with Guardian")
        return True
    except Exception as e:
        logger.warning("Kill-on-close job unavailable (continuing): %s", e)
        return False


def log_spawn(purpose: str, pid: Any) -> None:
    """Trace PID + rôle de chaque processus lancé (diagnostic des orphelins)."""
    logger.info("spawned child pid=%s purpose=%s", pid, purpose)


def hold_job(kernel32: Any = None) -> bool:
    """Dans un worker qui tient WinDivert : ouvrir un handle sur le job du GUI.
    Si le GUI est tué, le job n'est fermé (donc les autres enfants tués) qu'à la
    sortie de ce worker, APRÈS son nettoyage (fermeture du handle WinDivert puis
    désenregistrement du pilote). Fail-open."""
    global _held
    name = os.environ.get(JOB_NAME_ENV)
    if _held is not None or not name:
        return False
    try:
        if kernel32 is None:
            if sys.platform != "win32":
                return False
            import ctypes
            from ctypes import wintypes as wt

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenJobObjectW.restype = wt.HANDLE
            kernel32.OpenJobObjectW.argtypes = [wt.DWORD, wt.BOOL, wt.LPCWSTR]
        h = kernel32.OpenJobObjectW(JOB_OBJECT_QUERY, False, name)
        if not h:
            return False
        _held = h
        return True
    except Exception as e:
        logger.warning("hold_job failed (continuing): %s", e)
        return False
