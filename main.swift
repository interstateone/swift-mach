import Darwin.Mach
import Security.Authorization

func acquireTaskportRight() -> OSStatus {
    var authorization: AuthorizationRef?
    let flags: AuthorizationFlags = [AuthorizationFlags.extendRights, .preAuthorize, .interactionAllowed]
    let createStatus = AuthorizationCreate(nil, nil, flags, &authorization)
    guard createStatus == errAuthorizationSuccess else { return createStatus }

    let items = [AuthorizationItem(name: "system.privilege.taskport", valueLength: 0, value: nil, flags: 0)]
    var taskportRights = AuthorizationRights(count: 1, items: UnsafeMutablePointer(mutating: items))
    let copyStatus = AuthorizationCopyRights(authorization!, &taskportRights, nil, flags, nil)
    guard copyStatus == errAuthorizationSuccess else { return copyStatus }

    return errAuthorizationSuccess
}

print("Enter pid:")
guard
    let pidString = readLine(),
    let pid = Int32(pidString)
else { exit(1) }

let rightStatus = acquireTaskportRight()
guard rightStatus == errAuthorizationSuccess else {
    print(SecCopyErrorMessageString(rightStatus, nil) ?? "")
    exit(1)
}

var task = mach_port_t()
let taskForPidResult = task_for_pid(task_self_trap(), pid, &task)
guard taskForPidResult == KERN_SUCCESS else {
    print(mach_error_string(taskForPidResult))
    exit(1)
}
print("Task: \(task)")

var threadList: thread_act_array_t?
var threadCount: mach_msg_type_number_t = 0
let threadsResult = task_threads(task, &threadList, &threadCount)
guard
    threadsResult == KERN_SUCCESS,
    let threadList = threadList
else {
    print(mach_error_string(threadsResult))
    exit(1)
}
print("Thread count: \(threadCount)")

let x86_THREAD_STATE64_COUNT = mach_msg_type_number_t(MemoryLayout<x86_thread_state64_t>.size / MemoryLayout<Int8>.size)
var state = thread_state_t.allocate(capacity: 1)
for threadIndex in 0..<threadCount {
    var stateCount: mach_msg_type_number_t = x86_THREAD_STATE64_COUNT
    let stateResult = thread_get_state(threadList[Int(threadIndex)], x86_THREAD_STATE64, state, &stateCount)
    guard stateResult == KERN_SUCCESS else {
        print(stateResult, mach_error_string(stateResult))
        exit(1)
    }

    let archState = state.withMemoryRebound(to: x86_thread_state64_t.self, capacity: 1) { return $0.pointee }
    print("""

          Thread \(threadIndex) state:
          RAX: \(archState.__rax)
          RBX: \(archState.__rbx)
          RCX: \(archState.__rcx)
          RDX: \(archState.__rdx)
          RBP: \(archState.__rbp)
          RSP: \(archState.__rsp)
          RSI: \(archState.__rsi)
          RDI: \(archState.__rdi)
          """)
}
