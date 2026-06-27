#include "crypto_asm_hidden.h"
// linker define ge25519_p1p1_9l_dense_to_p2_9l_dense

	.p2align 4
	ASM_HIDDEN _CRYPTO_SHARED_NAMESPACE(ge25519_p1p1_9l_dense_to_p2_9l_dense)
	.globl _CRYPTO_SHARED_NAMESPACE(ge25519_p1p1_9l_dense_to_p2_9l_dense)
	ASM_HIDDEN CRYPTO_SHARED_NAMESPACE(ge25519_p1p1_9l_dense_to_p2_9l_dense)
	.globl CRYPTO_SHARED_NAMESPACE(ge25519_p1p1_9l_dense_to_p2_9l_dense)

_CRYPTO_SHARED_NAMESPACE(ge25519_p1p1_9l_dense_to_p2_9l_dense):
CRYPTO_SHARED_NAMESPACE(ge25519_p1p1_9l_dense_to_p2_9l_dense):

	sub	sp, sp, #112
	stp	x19, x20, [sp, #0]
	stp	x21, x22, [sp, #16]
	stp	x23, x24, [sp, #32]
	stp	x25, x26, [sp, #48]
	stp	x27, x28, [sp, #64]
	stp	x29, x30, [sp, #80]
	stp	x0, x1, [sp, #96]
	
	mov	w30, #1216
	
        // inputs <104,40> and <120,80>>
        ldr	x11, [sp, #104]
        add	x12, x11, #40      
	ld2	{v10.s, v11.s}[0], [x11], #8
	ld2	{v10.s, v11.s}[1], [x12], #8		
	ld2	{v12.s, v13.s}[0], [x11], #8	
	ld2	{v12.s, v13.s}[1], [x12], #8		
	ld2	{v14.s, v15.s}[0], [x11], #8
	ld2	{v14.s, v15.s}[1], [x12], #8		
	ld2	{v16.s, v17.s}[0], [x11], #8	
	ld2	{v16.s, v17.s}[1], [x12], #8		
	ld2	{v18.s, v19.s}[0], [x11], #8
	ld2	{v18.s, v19.s}[1], [x12], #8
	
        ldr	x10, [sp, #104]
        add	x11, x10, #120
        add	x12, x10, #80
	ld2	{v20.s, v21.s}[0], [x11], #8
	ld2	{v20.s, v21.s}[1], [x12], #8		
	ld2	{v22.s, v23.s}[0], [x11], #8	
	ld2	{v22.s, v23.s}[1], [x12], #8		
	ld2	{v24.s, v25.s}[0], [x11], #8
	ld2	{v24.s, v25.s}[1], [x12], #8		
	ld2	{v26.s, v27.s}[0], [x11], #8	
	ld2	{v26.s, v27.s}[1], [x12], #8		
	ld2	{v28.s, v29.s}[0], [x11], #8	        
	ld2	{v28.s, v29.s}[1], [x12], #8	
	
	// <96,40> ← Mul(<104,40>,<120,80>)
	mov 	x29, #0x1fffffff
	dup 	v29.2d, x29
	dup 	v30.2s, w30
	        
        umull	v5.2d, v15.2s, v25.2s
        umull	v7.2d, v15.2s, v27.2s
        umull	v8.2d, v15.2s, v28.2s
        umull	v0.2d, v15.2s, v20.2s
        umull	v2.2d, v15.2s, v22.2s
        umull	v4.2d, v15.2s, v24.2s
        umull	v6.2d, v15.2s, v26.2s
        umull	v1.2d, v15.2s, v21.2s 
        umull	v3.2d, v15.2s, v23.2s
        
        umlal	v7.2d, v17.2s, v25.2s
        umlal	v8.2d, v17.2s, v27.2s
        umlal	v0.2d, v17.2s, v28.2s
        umlal	v2.2d, v17.2s, v20.2s
        umlal	v4.2d, v17.2s, v22.2s
        umlal	v6.2d, v17.2s, v24.2s
        umlal	v1.2d, v17.2s, v26.2s
        umlal	v3.2d, v17.2s, v21.2s
        umull	v9.2d, v17.2s, v23.2s
        
        umlal	v8.2d, v18.2s, v25.2s
        umlal	v0.2d, v18.2s, v27.2s
        umlal	v2.2d, v18.2s, v28.2s
        umlal	v4.2d, v18.2s, v20.2s
        umlal	v6.2d, v18.2s, v22.2s
        umlal	v1.2d, v18.2s, v24.2s
        umlal	v3.2d, v18.2s, v26.2s
        umlal	v9.2d, v18.2s, v21.2s
        umull	v15.2d, v18.2s, v23.2s
        
        umlal	v0.2d, v10.2s, v25.2s
        umlal	v2.2d, v10.2s, v27.2s
        umlal	v4.2d, v10.2s, v28.2s
        umlal	v6.2d, v10.2s, v20.2s
        umlal	v1.2d, v10.2s, v22.2s
        umlal	v3.2d, v10.2s, v24.2s
        umlal	v9.2d, v10.2s, v26.2s
        umlal	v15.2d, v10.2s, v21.2s
        umull	v17.2d, v10.2s, v23.2s
        
        umlal	v2.2d, v12.2s, v25.2s
        umlal	v4.2d, v12.2s, v27.2s
        umlal	v6.2d, v12.2s, v28.2s
        umlal	v1.2d, v12.2s, v20.2s
        umlal	v3.2d, v12.2s, v22.2s
        umlal	v9.2d, v12.2s, v24.2s
        umlal	v15.2d, v12.2s, v26.2s
        umlal	v17.2d, v12.2s, v21.2s
        umull	v18.2d, v12.2s, v23.2s
        
        umlal	v4.2d, v14.2s, v25.2s
        umlal	v6.2d, v14.2s, v27.2s
        umlal	v1.2d, v14.2s, v28.2s
        umlal	v3.2d, v14.2s, v20.2s
        umlal	v9.2d, v14.2s, v22.2s
        umlal	v15.2d, v14.2s, v24.2s
        umlal	v17.2d, v14.2s, v26.2s
        umlal	v18.2d, v14.2s, v21.2s
        umull	v10.2d, v14.2s, v23.2s
        
        umlal	v6.2d, v16.2s, v25.2s
        umlal	v1.2d, v16.2s, v27.2s
        umlal	v3.2d, v16.2s, v28.2s
        umlal	v9.2d, v16.2s, v20.2s
        umlal	v15.2d, v16.2s, v22.2s
        umlal	v17.2d, v16.2s, v24.2s
        umlal	v18.2d, v16.2s, v26.2s
        umlal	v10.2d, v16.2s, v21.2s
        umull	v12.2d, v16.2s, v23.2s                    
        
        umlal	v1.2d, v11.2s, v25.2s
        umlal	v3.2d, v11.2s, v27.2s
        umlal	v9.2d, v11.2s, v28.2s
        umlal	v15.2d, v11.2s, v20.2s
        umlal	v17.2d, v11.2s, v22.2s
        umlal	v18.2d, v11.2s, v24.2s
        umlal	v10.2d, v11.2s, v26.2s
        umlal	v12.2d, v11.2s, v21.2s
        umull	v14.2d, v11.2s, v23.2s
        
        umlal	v3.2d, v13.2s, v25.2s
        umlal	v9.2d, v13.2s, v27.2s
        umlal	v15.2d, v13.2s, v28.2s
        umlal	v17.2d, v13.2s, v20.2s
        umlal	v18.2d, v13.2s, v22.2s
        umlal	v10.2d, v13.2s, v24.2s
        umlal	v12.2d, v13.2s, v26.2s
        umlal	v14.2d, v13.2s, v21.2s
        umull	v16.2d, v13.2s, v23.2s
        
        usra	v15.2d, v9.2d, #29
        and	v9.16b, v9.16b, v29.16b
        xtn	v9.2s, v9.2d
        umull	v9.2d, v9.2s, v30.2s
        add	v5.2d, v5.2d, v9.2d        
                      
        usra	v17.2d, v15.2d, #29
        and	v15.16b, v15.16b, v29.16b
        xtn	v15.2s, v15.2d
        umull	v15.2d, v15.2s, v30.2s
        add	v7.2d, v7.2d, v15.2d
        
        usra	v18.2d, v17.2d, #29
        and	v17.16b, v17.16b, v29.16b
        xtn	v17.2s, v17.2d
        umull	v17.2d, v17.2s, v30.2s
        add	v8.2d, v8.2d, v17.2d
              
        usra	v10.2d, v18.2d, #29
        and	v18.16b, v18.16b, v29.16b
        xtn	v18.2s, v18.2d
        umull	v18.2d, v18.2s, v30.2s
        add	v0.2d, v0.2d, v18.2d
              
        usra	v12.2d, v10.2d, #29
        and	v10.16b, v10.16b, v29.16b
        xtn	v10.2s, v10.2d
        umull	v10.2d, v10.2s, v30.2s
        add	v2.2d, v2.2d, v10.2d
                        
        usra	v14.2d, v12.2d, #29
        and	v12.16b, v12.16b, v29.16b
        xtn	v12.2s, v12.2d
        umull	v12.2d, v12.2s, v30.2s
        add	v4.2d, v4.2d, v12.2d
        
        usra	v16.2d, v14.2d, #29
        and	v14.16b, v14.16b, v29.16b
        xtn	v14.2s, v14.2d
        umull	v14.2d, v14.2s, v30.2s
        add	v6.2d, v6.2d, v14.2d
        
        ushr	v9.2d, v16.2d, #29
        and	v16.16b, v16.16b, v29.16b
        xtn	v16.2s, v16.2d
        umull	v16.2d, v16.2s, v30.2s
        add	v1.2d, v1.2d, v16.2d

        xtn	v9.2s, v9.2d                              
        umull	v9.2d, v9.2s, v30.2s
        add	v3.2d, v3.2d, v9.2d
        
        lsr	x29, x29, #6
        dup	v30.2d, x29

        usra	v4.2d, v2.2d, #29
        and	v2.16b, v2.16b, v29.16b	
	        
        usra	v7.2d, v5.2d, #29
        and	v5.16b, v5.16b, v29.16b
        
        usra	v6.2d, v4.2d, #29
        and	v4.16b, v4.16b, v29.16b
        
        usra	v8.2d, v7.2d, #29
        and	v7.16b, v7.16b, v29.16b        

        usra	v1.2d, v6.2d, #29
        and	v6.16b, v6.16b, v29.16b

        usra	v0.2d, v8.2d, #29
        and	v8.16b, v8.16b, v29.16b
        
        usra	v3.2d, v1.2d, #29
        and	v1.16b, v1.16b, v29.16b

        usra	v2.2d, v0.2d, #29
        and	v0.16b, v0.16b, v29.16b
        
        bic	v15.16b, v3.16b, v30.16b
        usra	v5.2d, v15.2d, #23
        usra	v5.2d, v15.2d, #22
        usra	v5.2d, v15.2d, #19                
        and	v3.16b, v3.16b, v30.16b        
        
        usra	v4.2d, v2.2d, #29
        and	v2.16b, v2.16b, v29.16b
        
        usra	v7.2d, v5.2d, #29
        and	v5.16b, v5.16b, v29.16b
        
        ldr	x11, [sp, #96]        
        add	x12, x11, #40
	st2	{v0.s, v1.s}[0], [x11], #8
	st2	{v0.s, v1.s}[2], [x12], #8		
	st2	{v2.s, v3.s}[0], [x11], #8	
	st2	{v2.s, v3.s}[2], [x12], #8
	st2	{v4.s, v5.s}[0], [x11], #8
	st2	{v4.s, v5.s}[2], [x12], #8		
	st2	{v6.s, v7.s}[0], [x11], #8	
	st2	{v6.s, v7.s}[2], [x12], #8
	st1	{v8.2s}, [x11], #8	
	mov	x19, v8.d[1]	
	str	x19, [x12], #8
	
	// mul
	ldr	x1, [sp, #104]		
	ldp	w13, w17, [x1, #40]
	ldp	w14, w18, [x1, #48]
	ldp	w15, w10, [x1, #56]
	ldp	w16, w11, [x1, #64]
	ldr	w12, [x1, #72]

	ldp	w23, w27, [x1, #120]
	ldp	w24, w28, [x1, #128]
	ldp	w25, w20, [x1, #136]
	ldp	w26, w21, [x1, #144]
	ldr	w22, [x1, #152]         	
	
        umull	x0, w10, w20
        umull	x1, w10, w21        
        umull	x2, w10, w22        
        umull	x3, w10, w23        
        umull	x4, w10, w24        
        umull	x5, w10, w25
        umull	x6, w10, w26 
        umull	x7, w10, w27
        umull	x8, w10, w28                       
        
        umaddl	x1, w11, w20, x1  
        umaddl	x2, w11, w21, x2 
        umaddl	x3, w11, w22, x3        
        umaddl	x4, w11, w23, x4
        umaddl	x5, w11, w24, x5
        umaddl	x6, w11, w25, x6
        umaddl	x7, w11, w26, x7        
        umaddl	x8, w11, w27, x8
        umull	x9, w11, w28        
        
        umaddl	x2, w12, w20, x2 
        umaddl	x3, w12, w21, x3
        umaddl	x4, w12, w22, x4
        umaddl	x5, w12, w23, x5
        umaddl	x6, w12, w24, x6
        umaddl	x7, w12, w25, x7
        umaddl	x8, w12, w26, x8
        umaddl	x9, w12, w27, x9
        umull	x10, w12, w28
        
        umaddl	x3, w13, w20, x3    
        umaddl	x4, w13, w21, x4    
        umaddl	x5, w13, w22, x5 
        umaddl	x6, w13, w23, x6 
        umaddl	x7, w13, w24, x7
        umaddl	x8, w13, w25, x8
        umaddl	x9, w13, w26, x9
        umaddl	x10, w13, w27, x10 
        umull	x11, w13, w28               
        
        umaddl	x4, w14, w20, x4 
        umaddl	x5, w14, w21, x5 
        umaddl	x6, w14, w22, x6 
        umaddl	x7, w14, w23, x7 
        umaddl	x8, w14, w24, x8
        umaddl	x9, w14, w25, x9 
        umaddl	x10, w14, w26, x10
        umaddl	x11, w14, w27, x11
        umull	x12, w14, w28        
        
        umaddl	x5, w15, w20, x5 
        umaddl	x6, w15, w21, x6 
        umaddl	x7, w15, w22, x7 
        umaddl	x8, w15, w23, x8
        umaddl	x9, w15, w24, x9
        umaddl	x10, w15, w25, x10 
        umaddl	x11, w15, w26, x11
        umaddl	x12, w15, w27, x12 
        umull	x13, w15, w28
        
        umaddl	x6, w16, w20, x6
        umaddl	x7, w16, w21, x7
        umaddl	x8, w16, w22, x8
        umaddl	x9, w16, w23, x9  
        umaddl	x10, w16, w24, x10
        umaddl	x11, w16, w25, x11
        umaddl	x12, w16, w26, x12   
        umaddl	x13, w16, w27, x13 
        umull	x14, w16, w28                    
        
        umaddl	x7, w17, w20, x7
        umaddl	x8, w17, w21, x8
        umaddl	x9, w17, w22, x9
        umaddl	x10, w17, w23, x10
        umaddl	x11, w17, w24, x11
        umaddl	x12, w17, w25, x12  
        umaddl	x13, w17, w26, x13
        umaddl	x14, w17, w27, x14 
        umull	x15, w17, w28
        
        umaddl	x8, w18, w20, x8
        umaddl	x9, w18, w21, x9
        umaddl	x10, w18, w22, x10
        umaddl	x11, w18, w23, x11
        umaddl	x12, w18, w24, x12 
        umaddl	x13, w18, w25, x13
        umaddl	x14, w18, w26, x14
        umaddl	x15, w18, w27, x15
        umull	x16, w18, w28
              
        add	x10, x10, x9, lsr #29
        and	x9, x9, #0x1fffffff
        umull	x9, w9, w30
        add	x0, x0, x9
        
        add	x11, x11, x10, lsr #29
        and	x10, x10, #0x1fffffff
        umull	x10, w10, w30
        add	x1, x1, x10
        
        add	x12, x12, x11, lsr #29
        and	x11, x11, #0x1fffffff
        umull	x11, w11, w30
        add	x2, x2, x11
        
        add	x13, x13, x12, lsr #29
        and	x12, x12, #0x1fffffff
        umull	x12, w12, w30
        add	x3, x3, x12
        
        add	x14, x14, x13, lsr #29
        and	x13, x13, #0x1fffffff
        umull	x13, w13, w30
        add	x4, x4, x13
                
        add	x15, x15, x14, lsr #29
        and	x14, x14, #0x1fffffff
        umull	x14, w14, w30
        add	x5, x5, x14
        
        add	x16, x16, x15, lsr #29
        and	x15, x15, #0x1fffffff
        umull	x15, w15, w30
        add	x6, x6, x15           
               
        lsr	x9, x16, #29
        and	x16, x16, #0x1fffffff
        umull	x16, w16, w30
        add	x7, x7, x16
                       
        umull	x9, w9, w30
        add	x8, x8, x9
        
        add	x5, x5, x4, lsr #29
        and	x4, x4, 0x1fffffff
	        
        add	x1, x1, x0, lsr #29
        and	x0, x0, 0x1fffffff
        
        add	x6, x6, x5, lsr #29
        and	x5, x5, 0x1fffffff
        
        add	x2, x2, x1, lsr #29
        and	x1, x1, 0x1fffffff        

        add	x7, x7, x6, lsr #29
        and	x6, x6, 0x1fffffff

        add	x3, x3, x2, lsr #29
        and	x2, x2, 0x1fffffff
        
        add	x8, x8, x7, lsr #29
        and	x7, x7, 0x1fffffff

        add	x4, x4, x3, lsr #29
        and	x3, x3, 0x1fffffff
        bfi	x3, x7, #32, #29
        
        bic	x10, x8, #0x7fffff
        add	x0, x0, x10, lsr #23
        add	x0, x0, x10, lsr #22
        add	x0, x0, x10, lsr #19
        and	x8, x8, #0x7fffff
        
        add	x5, x5, x4, lsr #29
        and	x4, x4, 0x1fffffff
        bfi	x4, x8, #32, #23
        
        add	x1, x1, x0, lsr #29
        bfi	x6, x1, #32, #30
        and	x0, x0, 0x1fffffff        
        bfi	x5, x0, #32, #29
	
	ldr	x10, [sp, #96]	
	stp	x3, x4, [x10, #80]
	stp	x5, x6, [x10, #96]
	str	x2, [x10, #112]
	
	ldp	x29, x30, [sp, #80]
	ldp	x27, x28, [sp, #64]	
	ldp	x25, x26, [sp, #48]	
	ldp	x23, x24, [sp, #32]
	ldp	x21, x22, [sp, #16]	
	ldp	x19, x20, [sp, #0]
	add	sp, sp, #112
	
	ret
.section	.note.GNU-stack,"",@progbits
