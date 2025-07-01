#include "textflag.h"

TEXT libc_os_sync_wait_on_address_trampoline<>(SB),NOSPLIT,$0-0
    JMP libc_os_sync_wait_on_address(SB)
GLOBL ·libc_os_sync_wait_on_address_trampoline_addr(SB), RODATA, $8
DATA ·libc_os_sync_wait_on_address_trampoline_addr(SB)/8, $libc_os_sync_wait_on_address_trampoline<>(SB)

TEXT libc_os_sync_wait_on_address_with_timeout_trampoline<>(SB),NOSPLIT,$0-0
    JMP libc_os_sync_wait_on_address_with_timeout(SB)
GLOBL ·libc_os_sync_wait_on_address_with_timeout_trampoline_addr(SB), RODATA, $8
DATA ·libc_os_sync_wait_on_address_with_timeout_trampoline_addr(SB)/8, $libc_os_sync_wait_on_address_with_timeout_trampoline<>(SB)

TEXT libc_os_sync_wake_by_address_any_trampoline<>(SB),NOSPLIT,$0-0
    JMP libc_os_sync_wake_by_address_any(SB)
GLOBL ·libc_os_sync_wake_by_address_any_trampoline_addr(SB), RODATA, $8
DATA ·libc_os_sync_wake_by_address_any_trampoline_addr(SB)/8, $libc_os_sync_wake_by_address_any_trampoline<>(SB)

TEXT libc_os_sync_wake_by_address_all_trampoline<>(SB),NOSPLIT,$0-0
    JMP libc_os_sync_wake_by_address_all(SB)
GLOBL ·libc_os_sync_wake_by_address_all_trampoline_addr(SB), RODATA, $8
DATA ·libc_os_sync_wake_by_address_all_trampoline_addr(SB)/8, $libc_os_sync_wake_by_address_all_trampoline<>(SB)
