sort: # void sort(long* numbers, int n)
        lea     edx, [rsi-1]    # lastIndex = n - 1
        xor     esi, esi        # firstIndex = 0\
        # jmp     QuickSort
QuickSort: # void QuickSort(long* array, int firstIndex, int lastIndex)\
        # rdi -> array, esi -> firstIndex, rdx -> lastIndex
        cmp     rsi, rdx        # if (firstIndex < lastIndex)
        jge     .endfunction
        push    rbx
        mov     rbx, rsi        # pivot = firstIndex   
        push    rax
        mov     rax, rsi        # for( int j = firstIndex,
        push    r8
        push    r9
        push    r12
        mov     r12, [rdi+rdx*8] # array[lastIndex]
.loop:
        cmp     rax, rdx        # firstIndex < lastIndex
        jge     .endloop
        mov     r8, [rdi+rax*8]        # array[j]
        cmp     r8, r12        # if (array[j] < array[lastIndex])
        jge     .endif
        mov     r9, [rdi+rbx*8] # array[pivot]
        mov     QWORD PTR[rdi+rbx*8], r8       # array[pivot] = array[j]
        mov     QWORD PTR[rdi+rax*8], r9       # array[j] = array[pivot]
        inc     rbx             # pivot++
.endif:
        inc     rax             # j++
        jmp     .loop   
.endloop:
        mov     r8, [rdi+rbx*8]        # array[pivot]
        mov     QWORD PTR[rdi+rdx*8], r8       # array[lastIndex] = array[pivot]
        mov     QWORD PTR[rdi+rbx*8], r12       # array[pivot] = array[lastIndex]

        mov     r8, rdx         # r8 = lastIndex
        mov     rdx, rbx        # $3 = pivot
        dec     rdx             # pivot - 1
        call    QuickSort       # QuickSort(array, firstIndex, pivot-1)
        mov     rsi, rbx        # $2 = pivot
        inc     rsi             # pivot +1
        mov     rdx, r8         # $3 = lastIndex
        
        pop     r12
        pop     r9
        pop     r8
        pop     rax
        pop     rbx
        jmp    QuickSort       # QuickSort(array, pivot+1, lastIndex)
.endfunction:
        ret
