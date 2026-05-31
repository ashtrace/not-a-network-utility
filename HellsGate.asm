.data
  wSystemCall       DWORD	0h	    ; syscall number
  qSyscallInsAdress QWORD	0h	    ; memory address of the `syscall` instruction

.code 
	HellsGate PROC
      mov wSystemCall, 0h
      mov qSyscallInsAdress, 0h
      mov wSystemCall, ecx		    ; saving the ssn value to wSystemCall
      mov qSyscallInsAdress, rdx	; saving the syscall instruction address to qSyscallInsAdress	
      ret
	HellsGate ENDP

	HellDescent PROC
      mov r10, rcx
      mov eax, wSystemCall		
      jmp qword ptr [qSyscallInsAdress]	; jumping to qSyscallInsAdress instead of calling 'syscall'
      ret
	HellDescent ENDP
end