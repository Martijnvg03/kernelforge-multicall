---
layout: default
---

# Chained Kernel Function Calls Through Pure ROP

**Extending Cr4sh's KernelForge from single-shot kernel calls to multi-function ROP chains with local variables, return value passing, and persistent thread reuse — all from dynamically discovered ntoskrnl gadgets. HVCI remains fully bypassed.**

---

## TL;DR

- [KernelForge](https://github.com/Cr4sh/KernelForge) by Dmytro Oleksiuk
  (Cr4sh) proved that given kernel R/W, you can call any kernel function from
  user mode on HVCI-enabled systems via ROP — no injected code required.
- The original had one deliberate limitation: **one kernel function call per
  thread.** Each invocation created a thread, called one function, and
  terminated. Multi-step operations were out of scope.
- **DynGadgets removes that limitation.** It chains an arbitrary number of
  kernel calls into a single ROP payload with full data flow between them.
- Gadgets are discovered dynamically by scanning ntoskrnl's executable
  sections and classifying them by semantic effect — no hardcoded byte
  patterns, no per-build updates.
- Return values flow between calls as local variables on the kernel stack.
  One call's output becomes the next call's input through existing gadget
  sequences.
- Persistent threads survive across multiple chain dispatches via event
  ping-pong — a single kernel thread stays alive for an arbitrary number of
  operations.
- HVCI cannot detect this. The attack writes only to the kernel stack
  (writable, non-executable). Every execution address points to ntoskrnl's
  `.text` section (executable, non-writable). From HVCI's perspective,
  legitimate signed code is running from legitimate signed pages.
- No countermeasure deployed today fully prevents this.

---

## 1. KernelForge: the foundation

[KernelForge](https://github.com/Cr4sh/KernelForge), written by Dmytro
Oleksiuk (Cr4sh), proved a simple and devastating concept: given an arbitrary
kernel read/write primitive, you can call any kernel function from user mode
on HVCI-enabled systems without executing a single byte of injected code.

The technique hijacks a dummy thread's kernel stack while it sits in a wait
state. When the thread resumes, the processor's own `ret` instruction
sequences through a ROP chain written to the stack, dispatching the target
function via a retpoline gadget already present in `ntoskrnl.exe`. HVCI
enforces that no new executable kernel pages can be created — but every
address in the chain already belongs to a signed Microsoft binary. There is
nothing for HVCI to flag.

The original KernelForge had one deliberate limitation, noted in its own
README as future work: **it could only call one kernel function per thread.**
Each invocation created a thread, called one function, saved the return
value, and terminated. Multi-step operations — anything requiring paired
calls, intermediate allocations, or passing one function's output to the
next — were out of scope.

## 2. The extension: from single shots to campaigns

DynGadgets removes that limitation. Where the original executed one kernel
function and exited, this extension chains an arbitrary number of kernel
calls into a single ROP payload, with full data flow between them. The
difference is the gap between firing one round and executing an entire
operation.

**Original KernelForge:**
- One function call per dummy thread
- Five hardcoded gadgets found by byte pattern
- Return value saved, thread terminated
- No data flow between calls
- Single driver backend (WinIo.sys)

**DynGadgets extension:**
- Unlimited chained calls per thread
- Gadgets discovered dynamically via abstract interpretation
- Return values flow between calls as local variables
- Persistent threads survive across multiple chain dispatches
- Pluggable driver backends

The practical consequence: operations that previously required multiple
thread create/hijack/terminate cycles — each one a detection opportunity —
now execute as a single atomic chain on one thread. More critically,
operations that were previously *impossible* because they required
intermediate state (allocate memory, write to it, pass the pointer forward)
now work naturally.

## 3. How chaining works

Three capabilities make multi-call chains possible:

**Dynamic gadget resolution.** Instead of matching five hardcoded byte
sequences, DynGadgets scans all executable sections of ntoskrnl and
classifies the gadgets it finds by their semantic effects — which registers
they pop, what memory they access, how they adjust the stack. This produces a
rich enough gadget vocabulary to compose chains of arbitrary length, and
makes the tool resilient across Windows builds without manual updates.

**Chain-local variables.** The chain builder allocates slots on the kernel
stack that act as local variables across calls. When a function returns a
value in RAX, a `mov [rcx], rax` gadget captures it into a local slot. Later
calls can load that slot's address into a register and pass it as an
argument. This is how one call's output becomes the next call's input —
entirely through stack data and existing gadget sequences, no custom code.

**Persistent threads.** Instead of terminating the hijacked thread after each
chain, the chain can end with `KeWaitForSingleObject`, parking the thread on
a new event. The next chain is written to the same thread's stack and
dispatched by signaling that event. A ping-pong between two events keeps a
single kernel thread alive across an arbitrary number of dispatches, with the
framework caching the stack layout so subsequent invocations skip the scan
entirely.

## 4. What this enables

A single chain can now express complete kernel-level operations that
previously required a loaded driver. A representative example — DLL
injection into a target process entirely from user mode via ROP:

```
Chain: 7 kernel calls, 1 thread, 0 bytes of injected code

  1. KeStackAttachProcess(TargetEPROCESS, &ApcState)
  2. ZwAllocateVirtualMemory(target, &base, size, MEM_COMMIT, PAGE_RW)
  3. ZwWriteVirtualMemory(target, base, dllPath, pathLen)
  4. RtlCreateUserThread(target, ..., LdrLoadDll, base)
  5. ZwFreeVirtualMemory(target, &base)
  6. KeUnstackDetachProcess(&ApcState)
  7. ZwTerminateThread(self, 0x1337)
```

Every pointer passed between these calls — the APC state, the allocated base
address, the thread handle — lives as a local variable on the kernel stack.
No kernel pool allocation is visible. No handle is opened through user-mode
APIs that EDR hooks. The entire sequence runs in one thread wake-up.

Other demonstrated operations:

- **Cross-process memory reads** — `KeStackAttachProcess` +
  `MmCopyMemory` + detach, reading arbitrary process memory without a handle
- **Kernel pool operations** — `ExAllocatePool2` / `ExFreePool` with
  results flowing to subsequent calls
- **File I/O at kernel privilege** — `ZwCreateFile` with all 11 arguments
  (4 register + 7 stack), followed by further file operations
- **Persistent monitoring** — thread stays alive across multiple dispatches,
  each executing a different chain

## 5. Why HVCI does not help

HVCI enforces one invariant: kernel pages cannot be both writable and
executable. This prevents shellcode injection, pool spraying into executable
regions, and modified driver code. It is a meaningful defense against an
entire class of attacks.

It is also completely irrelevant here. The attack writes only to the kernel
stack — writable, non-executable memory. The execution addresses in the chain
all point to ntoskrnl's `.text` section — executable, non-writable memory
that HVCI itself protects. From HVCI's perspective, the processor is
executing legitimate signed code from legitimate signed pages. There is no
violation to detect.

> **The gap is structural:** HVCI answers "is this page allowed to execute?"
> It cannot answer "is this sequence of legitimate execution addresses a
> sequence the kernel actually intended?" ROP chains are data, not code.
> They are the kernel's own instructions, sequenced by an attacker.

The chaining extension makes this worse. A single-call KernelForge invocation
was a sharp tool — useful, but limited in scope. Multi-call chains with local
variables and persistent threads turn it into a general-purpose kernel
programming environment. The attacker is no longer calling a function; they
are writing programs that execute at ring 0, composed entirely from the OS's
own binary.

## 6. Red team impact

For offensive engagements where a kernel read/write primitive is obtainable —
and the loldriver ecosystem makes this broadly feasible — chained KernelForge
invocations change the operational calculus:

- **No custom driver required.** The vulnerable signed driver provides
  read/write only. All kernel logic runs through ntoskrnl's own code.
  Driver signature enforcement and HVCI are not bypassed — they are made
  irrelevant.
- **No EDR-visible handle operations.** Process injection, memory reads,
  and file I/O happen through kernel-internal APIs, not the user-mode
  syscall boundary that EDR instruments.
- **No anomalous thread creation.** The attack thread is a legitimate
  user-mode thread. Its kernel stack contents are unusual, but no current
  detection technology inspects kernel stacks of waiting threads.
- **Atomic operations.** A 7-call injection chain runs in a single thread
  wake-up cycle. There is no window between calls where partial state is
  observable.
- **Version resilience.** Dynamic gadget scanning adapts to whatever
  ntoskrnl build is running. No per-build offset tables to maintain.

## 7. Countermeasures and their gaps

**Shadow Stacks (Intel CET).** The strongest deployed countermeasure. A
hardware shadow stack records return addresses in a separate, non-writable
memory region. When `ret` fires, the processor compares the popped address
against the shadow copy. A mismatch raises a `#CP` exception. This directly
detects the core KernelForge mechanism — overwritten return addresses on the
kernel stack.

Shadow stacks significantly raise the bar. But they do not close the door:

- Kernel shadow stacks require Intel 11th gen+ or AMD Zen 3+ hardware and
  explicit OS enablement. The installed base is a fraction of the Windows
  fleet.
- Shadow stacks protect `ret` but not indirect `jmp` or `call`. JOP and COP
  variants are harder to construct but not impossible, especially given a
  dynamic gadget engine that can classify arbitrary instruction sequences.
- Shadow stack management across context switches, exceptions, and APC
  delivery is complex. Complexity is attack surface.
- Data-only attacks that corrupt function pointers, callback tables, or
  dispatch routines instead of return addresses are unaffected.

**kCFI / kCFG.** Validates indirect call targets against a bitmap of valid
entry points. Constrains JOP/COP variants but does not affect ROP, which
uses `ret` not `call`.

**KASLR.** Hides kernel addresses — but the read primitive that enables
KernelForge inherently provides address resolution. KASLR is a speed bump,
not a wall.

**VBS / Credential Guard.** Isolates specific secrets in a secure enclave.
Cannot prevent kernel function invocation through legitimate calling
conventions. Protects the crown jewels, not the kingdom.

No deployed combination of these technologies fully prevents arbitrary kernel
function execution given read/write. Each covers one axis. The attack surface
is the kernel's own instruction stream — you cannot remove the gadgets
without removing the kernel.

## 8. No final countermeasure exists

This needs to be stated plainly: there is no technology, deployed or
proposed, that fully prevents data-only kernel exploitation given arbitrary
kernel memory access. The problem is not a missing feature. It is a
fundamental consequence of running a monolithic kernel where every
instruction is reachable and every data structure is writable from within
the same address space.

Every countermeasure constrains a technique, not the capability. Remove ROP
with shadow stacks, and the attacker chains through indirect jumps. Constrain
indirect jumps with CFI, and the attacker corrupts dispatch tables. Protect
dispatch tables, and the attacker modifies scheduling metadata. Each fix
narrows the path. None of them closes it. The kernel is too large and too
internally trusted.

What the defensive community can do is **make the path expensive enough to
matter.** That requires layering — and it requires at least one layer that
operates outside the kernel's own trust domain.

## 9. Proposed: hypervisor thread verification

The specific vulnerability KernelForge exploits is that the kernel trusts a
thread's kernel stack contents at resumption time. A thread enters a wait
state with a legitimate return chain. It resumes — potentially seconds or
minutes later — and the kernel never verifies that the return chain is the
same one. Nothing checks. The thread just returns through whatever is there.

A hypervisor-level mechanism could close this specific gap: **hash the return
chain when a thread enters a wait state, re-hash it before the thread
resumes, fail on mismatch.**

Operating at the scheduler boundary:

1. **Wait entry.** When a thread transitions to a kernel wait, the
   hypervisor snapshots a cryptographic hash of the thread's return chain —
   every return address from RSP to the trap frame. The hash is stored in
   hypervisor memory, inaccessible from ring 0.
2. **Resumption check.** Before the scheduler dispatches the thread, a VM
   exit triggers re-verification. The hypervisor re-hashes and compares.
   This is the exact moment KernelForge's payload takes effect — making the
   check precise rather than statistical.
3. **Mismatch response.** Stack tampering detected. Bugcheck, quarantine the
   thread, or log and alert depending on deployment posture.

The critical property: the verification state lives in hypervisor memory. An
attacker with arbitrary kernel read/write — the prerequisite for KernelForge
— cannot reach it. This is the only kind of countermeasure that holds against
the threat model: one enforced from outside the compromised domain.

**Limitations are real but tractable.** Performance cost at every context
switch (mitigable via hardware acceleration, VMFUNC fast paths, or
probabilistic sampling). Legitimate stack modifications (exception unwinding,
APC delivery, longjmp) need allowlisting. Attacks that trigger immediate
execution without a wait/resume cycle are unaffected. These are engineering
constraints, not fundamental barriers.

Combined with shadow stacks, kCFI, and HVCI, hypervisor thread verification
would close the exact class of attack demonstrated here: kernel stack
manipulation during thread quiescence. It would not be a final
countermeasure. No such thing exists. But it would eliminate the current
reality where a thread's kernel execution context is trusted implicitly after
arbitrarily long idle periods, without any verification from any layer.

## 10. Conclusion

KernelForge, as originally published by Cr4sh, proved that HVCI does not
prevent kernel code execution. The DynGadgets extension turns that proof of
concept into something operationally complete: chained multi-function calls
with data flow, dynamic gadget resolution across OS builds, and persistent
thread reuse that minimizes the attack's footprint.

Shadow stacks are the strongest countermeasure available today and should be
deployed everywhere hardware supports them. But they are not universal, not
final, and not sufficient alone. The defensive community should push for
verification at the hypervisor level — the only trust boundary an attacker
with kernel read/write cannot cross.

Until then, any system with a kernel read/write vulnerability is fully
exploitable regardless of HVCI, VBS, or Secure Boot. The gadgets are already
loaded. They shipped with the OS.

---

Original KernelForge by [Dmytro Oleksiuk (Cr4sh)](https://github.com/Cr4sh/KernelForge) — DynGadgets extension, 2026
