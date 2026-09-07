---
layout: default
---

# Chaining Arbitrary Kernel Function Calls Through Pure ROP

**Extending Cr4sh's KernelForge from single-shot kernel invocations to multi-function ROP chains with stack-local variables, return-value forwarding, and persistent thread reuse — all resolved dynamically from ntoskrnl gadgets. HVCI remains fully bypassed.**

---

## Summary

- [KernelForge](https://github.com/Cr4sh/KernelForge) by Dmytro Oleksiuk (Cr4sh) demonstrated that, given kernel read/write, any kernel function can be called from user mode on HVCI-enabled systems via ROP — without injecting a single byte of executable code.
- The original design imposed one deliberate constraint: **one kernel function call per thread**. Each invocation spawned a thread, dispatched one call, and terminated. Multi-step operations were explicitly out of scope.
- **This extension removes that constraint.** It chains an arbitrary number of kernel calls into a single ROP payload, with full data flow between them.
- Gadgets are discovered at runtime by scanning ntoskrnl's executable sections and classifying each by its semantic effect — no hardcoded byte patterns, no per-build maintenance.
- Return values propagate between calls as stack-local variables. One call's output becomes the next call's input through existing gadget sequences.
- Persistent threads survive across multiple chain dispatches via event-based synchronization, eliminating repeated thread creation.
- HVCI cannot detect this. The payload writes only to the kernel stack (writable, non-executable). Every execution target points into ntoskrnl's `.text` section (executable, non-writable). From HVCI's perspective, legitimate signed code is running from legitimate signed pages.
- No currently deployed countermeasure fully prevents this.

---

## 1. Foundation: How KernelForge Works

[KernelForge](https://github.com/Cr4sh/KernelForge), written by Dmytro Oleksiuk (Cr4sh), proved a straightforward but consequential concept: given an arbitrary kernel read/write primitive, you can invoke any kernel function from user mode on HVCI-enabled systems without executing injected code.

The technique hijacks a suspended thread's kernel stack while it sits in a wait state. When the thread resumes, the processor's own `ret` instruction sequences through a ROP chain that has been written to the stack, dispatching the target function via a retpoline gadget present in `ntoskrnl.exe`. HVCI enforces that no new executable kernel pages can be allocated, but every address in the chain already belongs to a signed Microsoft binary. There is nothing for HVCI to flag.

The original KernelForge imposed one deliberate constraint, noted in its README as future work: **it supported only a single kernel function call per thread**. Each invocation created a thread, dispatched one call, captured the return value, and terminated. Multi-step operations — anything requiring paired calls, intermediate allocations, or passing one function's output to the next — were left unaddressed.

## 2. From Single Invocations to Multi-Call Chains

This extension removes that constraint. Where the original executed one kernel function and exited, the extended version chains an arbitrary number of kernel calls into a single ROP payload with full inter-call data flow. The difference is the gap between firing a single round and executing an entire operation.

**Original KernelForge:**
- One function call per thread
- Five hardcoded gadgets matched by byte pattern
- Return value saved, thread terminated
- No data flow between calls
- Single driver backend (WinIo.sys)

**Extended design:**
- Unlimited chained calls per thread
- Gadgets discovered dynamically via abstract interpretation
- Return values flow between calls as stack-local variables
- Persistent threads survive across multiple chain dispatches
- Pluggable driver backends

The practical consequence: operations that previously required multiple thread-create/hijack/terminate cycles — each a potential detection event — now execute as a single atomic chain on one thread. More importantly, operations that were previously *impossible* because they required intermediate state (allocate memory, write to it, forward the pointer) now work naturally.

## 3. Chain Mechanics

Three capabilities enable multi-call chains:

### Dynamic Gadget Discovery

Instead of matching five hardcoded byte sequences, the scanner traverses all executable sections of ntoskrnl and classifies discovered gadgets by their semantic effects: which registers they pop, what memory they access, how they adjust the stack pointer. This produces a sufficiently rich gadget vocabulary to compose chains of arbitrary length, and makes the tool resilient across Windows builds without manual offset updates.

### Stack-Local Variables

The chain builder allocates slots on the kernel stack that serve as local variables across calls. When a function returns a value in RAX, a `mov [rcx], rax` gadget captures it into a designated slot. Subsequent calls can load that slot's address into a register and pass it as an argument. This is how one call's output feeds into the next call's input — entirely through stack data and existing gadget sequences, without any custom code.

### Persistent Thread Reuse

Instead of terminating the hijacked thread after each chain, the chain concludes with a call to `KeWaitForSingleObject`, parking the thread on a new event object. The next chain is written to the same thread's stack and dispatched by signaling that event. Alternating between two events keeps a single kernel thread alive across an arbitrary number of dispatches. The framework caches the stack layout, so subsequent invocations skip the initial scan entirely.

## 4. Demonstrated Operations

A single chain can now express complete kernel-level operations that previously required a loaded driver. A representative example — DLL injection into a target process, performed entirely from user mode via ROP:

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

Every pointer passed between these calls — the APC state, the allocated base address, the thread handle — lives as a stack-local variable on the kernel stack. No kernel pool allocation is visible. No handle is opened through user-mode APIs that EDR instruments. The entire sequence runs in one thread wake-up.

Other demonstrated operations:

- **Cross-process memory access** — `KeStackAttachProcess` + `MmCopyMemory` + detach, reading arbitrary process memory without an observable handle
- **Kernel pool management** — `ExAllocatePool2` / `ExFreePool` with results forwarded to subsequent calls
- **Kernel-level file I/O** — `ZwCreateFile` with all 11 arguments (4 register + 7 stack), followed by further file operations
- **Persistent monitoring** — thread remains alive across multiple dispatches, each executing a different chain

## 5. Why HVCI Does Not Apply

HVCI enforces one invariant: kernel pages cannot be simultaneously writable and executable. This prevents shellcode injection, pool spraying into executable regions, and modification of driver code. It is a meaningful defense against an entire class of attacks.

It is also entirely irrelevant here. The payload writes only to the kernel stack — writable, non-executable memory. The execution targets in the chain all point into ntoskrnl's `.text` section — executable, non-writable memory that HVCI itself protects. From HVCI's perspective, the processor is executing legitimate signed code from legitimate signed pages. There is no violation to detect.

> **The gap is structural.** HVCI answers "is this page allowed to execute?" It cannot answer "is this sequence of legitimate execution addresses a sequence the kernel actually intended?" ROP chains are data, not code. They are the kernel's own instructions, sequenced by an attacker.

The chaining extension amplifies this gap. A single-call KernelForge invocation was a precise tool — useful, but narrow. Multi-call chains with stack-local variables and persistent threads transform it into a general-purpose kernel programming environment. The attacker is no longer calling a function; they are composing programs that execute at ring 0, built entirely from the operating system's own binary.

## 6. Offensive Implications

For engagements where a kernel read/write primitive is available — and the loldriver ecosystem makes this broadly feasible — chained KernelForge invocations shift the operational calculus:

- **No custom driver required.** The vulnerable signed driver provides read/write only. All kernel logic executes through ntoskrnl's own code. Driver signature enforcement and HVCI are not bypassed — they are rendered irrelevant.
- **No EDR-visible handle operations.** Process injection, memory reads, and file I/O occur through kernel-internal APIs, not the user-mode syscall boundary that EDR instruments.
- **No anomalous thread creation.** The attack thread is a legitimate user-mode thread. Its kernel stack contents are atypical, but no current detection technology inspects kernel stacks of waiting threads.
- **Atomic execution.** A 7-call injection chain runs in a single thread wake-up cycle. There is no window between calls where partial state is externally observable.
- **Build resilience.** Dynamic gadget scanning adapts to whatever ntoskrnl build is present. No per-build offset tables to maintain.

## 7. Countermeasures and Their Gaps

### Shadow Stacks (Intel CET)

The strongest deployed countermeasure. A hardware shadow stack records return addresses in a separate, non-writable memory region. When `ret` executes, the processor compares the popped address against the shadow copy. A mismatch raises a `#CP` exception. This directly targets the core KernelForge mechanism: overwritten return addresses on the kernel stack.

Shadow stacks significantly raise the bar, but they do not close the door:

- Kernel shadow stacks require Intel 11th-generation or AMD Zen 3+ hardware and explicit OS enablement. The installed base remains a fraction of the Windows fleet.
- Shadow stacks protect `ret` but not indirect `jmp` or `call`. JOP and COP variants are harder to construct but not infeasible, especially given a dynamic gadget engine that classifies arbitrary instruction sequences.
- Shadow stack management across context switches, exceptions, and APC delivery is inherently complex. Complexity introduces attack surface.
- Data-only attacks that corrupt function pointers, callback tables, or dispatch routines instead of return addresses are entirely unaffected.

### kCFI / kCFG

Validates indirect call targets against a bitmap of valid entry points. Constrains JOP/COP variants but does not affect ROP, which relies on `ret` rather than `call`.

### KASLR

Randomizes kernel base addresses, but the read primitive that enables KernelForge inherently provides address resolution. KASLR is a speed bump, not a barrier.

### VBS / Credential Guard

Isolates specific secrets within a secure enclave. Cannot prevent kernel function invocation through legitimate calling conventions. Protects specific assets, not the broader execution environment.

No deployed combination of these technologies fully prevents arbitrary kernel function execution given read/write access. Each addresses one axis. The attack surface is the kernel's own instruction stream — you cannot remove the gadgets without removing the kernel.

## 8. The Fundamental Limitation

This needs to be stated plainly: no technology, deployed or proposed, fully prevents data-only kernel exploitation given arbitrary kernel memory access. The problem is not a missing feature. It is a fundamental consequence of running a monolithic kernel where every instruction is reachable and every data structure is writable from within the same address space.

Every countermeasure constrains a technique, not the underlying capability. Eliminate ROP with shadow stacks, and the attacker chains through indirect jumps. Constrain indirect jumps with CFI, and the attacker corrupts dispatch tables. Protect dispatch tables, and the attacker modifies scheduling metadata. Each mitigation narrows the path. None of them closes it. The kernel is too large and too internally trusted.

What the defensive community can do is **make the path expensive enough to matter** — and that requires layering, with at least one layer operating outside the kernel's own trust domain.

## 9. Proposed Mitigation: Hypervisor-Level Thread Verification

The specific weakness KernelForge exploits is that the kernel trusts a thread's kernel stack contents at resumption time. A thread enters a wait state with a legitimate return chain. It resumes — potentially seconds or minutes later — and the kernel never verifies that the return chain is unchanged. Nothing checks. The thread simply returns through whatever is present on its stack.

A hypervisor-level mechanism could close this specific gap: **hash the return chain when a thread enters a wait state, re-hash before resumption, and fault on mismatch.**

The mechanism operates at the scheduler boundary:

1. **Wait entry.** When a thread transitions to a kernel wait, the hypervisor computes a cryptographic hash of the thread's return chain — every return address from RSP to the trap frame. The hash is stored in hypervisor memory, inaccessible from ring 0.
2. **Resumption verification.** Before the scheduler dispatches the thread, a VM exit triggers re-verification. The hypervisor recomputes and compares. This targets the exact moment KernelForge's payload takes effect, making the check precise rather than probabilistic.
3. **Mismatch response.** Stack tampering detected. The system can bugcheck, quarantine the thread, or log and alert depending on deployment posture.

The critical property: the verification state resides in hypervisor memory. An attacker with arbitrary kernel read/write — the prerequisite for KernelForge — cannot reach it. This is the only class of countermeasure that holds against the threat model: one enforced from outside the compromised domain.

**Practical constraints are real but tractable.** Performance cost at every context switch (mitigable via hardware acceleration, VMFUNC fast paths, or probabilistic sampling). Legitimate stack modifications (exception unwinding, APC delivery, longjmp) require allowlisting. Attacks that trigger immediate execution without a wait/resume cycle are unaffected. These are engineering challenges, not fundamental barriers.

Combined with shadow stacks, kCFI, and HVCI, hypervisor-level thread verification would close the exact class of attack demonstrated here: kernel stack manipulation during thread quiescence. It would not be a final countermeasure — no such thing exists. But it would eliminate the current reality where a thread's kernel execution context is trusted implicitly after arbitrarily long idle periods, without verification from any layer.

## 10. Conclusion

KernelForge, as originally published by Cr4sh, proved that HVCI does not prevent kernel code execution given read/write access. This extension turns that proof of concept into something operationally complete: chained multi-function calls with inter-call data flow, dynamic gadget resolution across OS builds, and persistent thread reuse that minimizes the attack's observable footprint.

Shadow stacks are the strongest countermeasure available today and should be deployed wherever hardware supports them. But they are neither universal nor sufficient on their own. The defensive community should pursue verification at the hypervisor level — the only trust boundary an attacker with kernel read/write cannot cross.

Until then, any system with a kernel read/write vulnerability is fully exploitable regardless of HVCI, VBS, or Secure Boot. The gadgets are already loaded. They shipped with the operating system.

---

Original KernelForge by [Dmytro Oleksiuk (Cr4sh)](https://github.com/Cr4sh/KernelForge) — Multi-call chain extension, 2026
