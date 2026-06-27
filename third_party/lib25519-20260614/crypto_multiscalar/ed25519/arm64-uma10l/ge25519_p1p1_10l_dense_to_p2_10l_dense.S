#include "crypto_asm_hidden.h"
// linker define ge25519_p1p1_10l_dense_to_p2_10l_dense

	.p2align 4
	ASM_HIDDEN _CRYPTO_SHARED_NAMESPACE(ge25519_p1p1_10l_dense_to_p2_10l_dense)
	.globl _CRYPTO_SHARED_NAMESPACE(ge25519_p1p1_10l_dense_to_p2_10l_dense)
	ASM_HIDDEN CRYPTO_SHARED_NAMESPACE(ge25519_p1p1_10l_dense_to_p2_10l_dense)
	.globl CRYPTO_SHARED_NAMESPACE(ge25519_p1p1_10l_dense_to_p2_10l_dense)

_CRYPTO_SHARED_NAMESPACE(ge25519_p1p1_10l_dense_to_p2_10l_dense):
CRYPTO_SHARED_NAMESPACE(ge25519_p1p1_10l_dense_to_p2_10l_dense):

	sub	sp, sp, #112
	stp	x19, x20, [sp, #0]
	stp	x21, x22, [sp, #16]
	stp	x23, x24, [sp, #32]
	stp	x25, x26, [sp, #48]
	stp	x27, x28, [sp, #64]
	stp	x29, x30, [sp, #80]
	stp	x0, x1, [sp, #96]
	
	mov	w30, #19
	
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
        umull	v0.2d, v10.2s, v20.2s
        umull	v0.2d, v10.2s, v20.2s
        
        umull	v1.2d, v10.2s, v21.2s        
        umlal	v1.2d, v11.2s, v20.2s
        
        umull	v2.2d, v10.2s, v22.2s        
        umlal	v2.2d, v12.2s, v20.2s

        umull	v3.2d, v10.2s, v23.2s        
        umlal	v3.2d, v11.2s, v22.2s
        umlal	v3.2d, v12.2s, v21.2s
        umlal	v3.2d, v13.2s, v20.2s
        
        umull	v4.2d, v10.2s, v24.2s        
        umlal	v4.2d, v12.2s, v22.2s
        umlal	v4.2d, v14.2s, v20.2s

        umull	v5.2d, v10.2s, v25.2s
        umlal	v5.2d, v11.2s, v24.2s
        umlal	v5.2d, v12.2s, v23.2s
        umlal	v5.2d, v13.2s, v22.2s
        umlal	v5.2d, v14.2s, v21.2s
        umlal	v5.2d, v15.2s, v20.2s

        umull	v6.2d, v10.2s, v26.2s        
        umlal	v6.2d, v12.2s, v24.2s
        umlal	v6.2d, v14.2s, v22.2s 
        umlal	v6.2d, v16.2s, v20.2s
        
        umull	v7.2d, v10.2s, v27.2s
        umlal	v7.2d, v11.2s, v26.2s
        umlal	v7.2d, v12.2s, v25.2s
        umlal	v7.2d, v13.2s, v24.2s
        umlal	v7.2d, v14.2s, v23.2s
        umlal	v7.2d, v15.2s, v22.2s
        umlal	v7.2d, v16.2s, v21.2s
        umlal	v7.2d, v17.2s, v20.2s
        
        umull	v8.2d, v10.2s, v28.2s
        umlal	v8.2d, v12.2s, v26.2s
        umlal	v8.2d, v14.2s, v24.2s
        umlal	v8.2d, v16.2s, v22.2s
        umlal	v8.2d, v18.2s, v20.2s

        umull	v9.2d, v10.2s, v29.2s
        umlal	v9.2d, v11.2s, v28.2s
        umlal	v9.2d, v12.2s, v27.2s
        umlal	v9.2d, v13.2s, v26.2s
        umlal	v9.2d, v14.2s, v25.2s
        umlal	v9.2d, v15.2s, v24.2s
        umlal	v9.2d, v16.2s, v23.2s
        umlal	v9.2d, v17.2s, v22.2s
        umlal	v9.2d, v18.2s, v21.2s
        umlal	v9.2d, v19.2s, v20.2s
        
	dup	v31.2s, w30                         
           
        mul	v22.2s, v22.2s, v31.2s
        mul	v24.2s, v24.2s, v31.2s
        mul	v26.2s, v26.2s, v31.2s
        mul	v28.2s, v28.2s, v31.2s
                     
        umlal	v0.2d, v12.2s, v28.2s
        umlal	v0.2d, v14.2s, v26.2s
        umlal	v0.2d, v16.2s, v24.2s
        umlal	v0.2d, v18.2s, v22.2s       
        
        umlal	v1.2d, v13.2s, v28.2s
        umlal	v1.2d, v15.2s, v26.2s
        umlal	v1.2d, v17.2s, v24.2s
        umlal	v1.2d, v19.2s, v22.2s
        
        umlal	v2.2d, v14.2s, v28.2s
        umlal	v2.2d, v16.2s, v26.2s
        umlal	v2.2d, v18.2s, v24.2s
        
        umlal	v3.2d, v15.2s, v28.2s
        umlal	v3.2d, v17.2s, v26.2s
        umlal	v3.2d, v19.2s, v24.2s
        
        umlal	v4.2d, v16.2s, v28.2s
        umlal	v4.2d, v18.2s, v26.2s      

        umlal	v5.2d, v17.2s, v28.2s
        umlal	v5.2d, v19.2s, v26.2s
        
        umlal	v6.2d, v18.2s, v28.2s
        
        umlal	v7.2d, v19.2s, v28.2s         
        
        shl	v11.2s, v11.2s, #1
        shl	v13.2s, v13.2s, #1
        shl	v15.2s, v15.2s, #1
        shl	v17.2s, v17.2s, #1
        shl	v19.2s, v19.2s, #1
             
        umlal	v2.2d, v11.2s, v21.2s
                
        umlal	v4.2d, v11.2s, v23.2s
        umlal	v4.2d, v13.2s, v21.2s
        
        umlal	v6.2d, v11.2s, v25.2s
        umlal	v6.2d, v13.2s, v23.2s
        umlal	v6.2d, v15.2s, v21.2s       
        
        umlal	v8.2d, v11.2s, v27.2s
        umlal	v8.2d, v13.2s, v25.2s
        umlal	v8.2d, v15.2s, v23.2s        
        umlal	v8.2d, v17.2s, v21.2s
                
        mul	v21.2s, v21.2s, v31.2s       
        mul	v23.2s, v23.2s, v31.2s
        mul	v25.2s, v25.2s, v31.2s
        mul	v27.2s, v27.2s, v31.2s
        mul	v29.2s, v29.2s, v31.2s
                   
        umlal	v0.2d, v11.2s, v29.2s
        umlal	v0.2d, v13.2s, v27.2s
        umlal	v0.2d, v15.2s, v25.2s
        umlal	v0.2d, v17.2s, v23.2s
        umlal	v0.2d, v19.2s, v21.2s        
        
        umlal	v1.2d, v12.2s, v29.2s
        umlal	v1.2d, v14.2s, v27.2s
        umlal	v1.2d, v16.2s, v25.2s
        umlal	v1.2d, v18.2s, v23.2s
        
        umlal	v2.2d, v13.2s, v29.2s
        umlal	v2.2d, v15.2s, v27.2s
        umlal	v2.2d, v17.2s, v25.2s
        umlal	v2.2d, v19.2s, v23.2s
        
        umlal	v3.2d, v14.2s, v29.2s
        umlal	v3.2d, v16.2s, v27.2s
        umlal	v3.2d, v18.2s, v25.2s
        
        umlal	v4.2d, v15.2s, v29.2s
        umlal	v4.2d, v17.2s, v27.2s
        umlal	v4.2d, v19.2s, v25.2s        

        umlal	v5.2d, v16.2s, v29.2s
        umlal	v5.2d, v18.2s, v27.2s
        
        umlal	v6.2d, v17.2s, v29.2s
        umlal	v6.2d, v19.2s, v27.2s

        umlal	v7.2d, v18.2s, v29.2s
        
        umlal	v8.2d, v19.2s, v29.2s

        mov	w29, #0x03ffffff
        dup	v30.2d, x29	
        ushr	v25.2d, v30.2d, #1	
	
        usra	v6.2d, v5.2d, #25
        and	v5.16b, v5.16b, v25.16b
        
        usra	v1.2d, v0.2d, #26
        and	v0.16b, v0.16b, v30.16b

        usra	v7.2d, v6.2d, #26
        and	v6.16b, v6.16b, v30.16b
        
        usra	v2.2d, v1.2d, #25
        and	v1.16b, v1.16b, v25.16b
        
        usra	v8.2d, v7.2d, #25
        and	v7.16b, v7.16b, v25.16b
        
        usra	v3.2d, v2.2d, #26
        and	v2.16b, v2.16b, v30.16b
        
        usra	v9.2d, v8.2d, #26
        and	v8.16b, v8.16b, v30.16b
        
        usra	v4.2d, v3.2d, #25
        and	v3.16b, v3.16b, v25.16b
               
        bic	v10.16b, v9.16b, v25.16b
        usra	v0.2d, v10.2d, #25        
        usra	v0.2d, v10.2d, #24
        usra	v0.2d, v10.2d, #21                
        and	v9.16b, v9.16b, v25.16b        
        
        usra	v5.2d, v4.2d, #26
        and	v4.16b, v4.16b, v30.16b
        
        usra	v1.2d, v0.2d, #26
        and	v0.16b, v0.16b, v30.16b
        
        usra	v6.2d, v5.2d, #25
        and	v5.16b, v5.16b, v25.16b
        
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
	st2	{v8.s, v9.s}[0], [x11], #8	        
	st2	{v8.s, v9.s}[2], [x12], #8
	
	// mul
	ldr	x1, [sp, #104]		
	ldp	w10, w11, [x1, #40]
	ldp	w12, w13, [x1, #48]
	ldp	w14, w15, [x1, #56]
	ldp	w16, w17, [x1, #64]
	ldp	w18, w19, [x1, #72]
	
	ldp	w20, w21, [x1, #120]
	ldp	w22, w23, [x1, #128]
	ldp	w24, w25, [x1, #136]
	ldp	w26, w27, [x1, #144]
	ldp	w28, w29, [x1, #152]
	
        umull	x0, w10, w20
        umull	x1, w10, w21        
        umull	x2, w10, w22
        umull	x3, w10, w23
        umull	x4, w10, w24        
        umull	x5, w10, w25
        umull	x6, w10, w26        
        umull	x7, w10, w27
        umull	x8, w10, w28
        umull	x9, w10, w29               
                
        umaddl	x1, w11, w20, x1
        umaddl	x3, w11, w22, x3
        umaddl	x5, w11, w24, x5
        umaddl	x7, w11, w26, x7
        umaddl	x9, w11, w28, x9             

        umaddl	x2, w12, w20, x2        
        umaddl	x3, w12, w21, x3
        umaddl	x4, w12, w22, x4
        umaddl	x5, w12, w23, x5
        umaddl	x6, w12, w24, x6
        umaddl	x7, w12, w25, x7
        umaddl	x8, w12, w26, x8
        umaddl	x9, w12, w27, x9                
        
        umaddl	x3, w13, w20, x3
        umaddl	x5, w13, w22, x5
        umaddl	x7, w13, w24, x7  
        umaddl	x9, w13, w26, x9              
        
        umaddl	x4, w14, w20, x4
        umaddl	x5, w14, w21, x5
        umaddl	x6, w14, w22, x6
        umaddl	x7, w14, w23, x7
        umaddl	x8, w14, w24, x8
        umaddl	x9, w14, w25, x9                
        
        umaddl	x5, w15, w20, x5
        umaddl	x7, w15, w22, x7
        umaddl	x9, w15, w24, x9        
                
        umaddl	x6, w16, w20, x6
        umaddl	x7, w16, w21, x7
        umaddl	x8, w16, w22, x8 
	umaddl	x9, w16, w23, x9               
        
        umaddl	x7, w17, w20, x7
        umaddl	x9, w17, w22, x9        

        umaddl	x8, w18, w20, x8
        umaddl	x9, w18, w21, x9
        
        umaddl	x9, w19, w20, x9
                    
        mul	w22, w22, w30
        mul	w24, w24, w30
        mul	w26, w26, w30
        mul	w28, w28, w30
                     
        umaddl	x0, w12, w28, x0
        
        umaddl	x1, w13, w28, x1        
        
        umaddl	x0, w14, w26, x0
        umaddl	x2, w14, w28, x2
        
        umaddl	x1, w15, w26, x1
        umaddl	x3, w15, w28, x3        
                
        umaddl	x0, w16, w24, x0
        umaddl	x2, w16, w26, x2
        umaddl	x4, w16, w28, x4
        
        umaddl	x1, w17, w24, x1
        umaddl	x3, w17, w26, x3
        umaddl	x5, w17, w28, x5        
        
        umaddl	x0, w18, w22, x0   
        umaddl	x2, w18, w24, x2
        umaddl	x6, w18, w28, x6
        umaddl	x4, w18, w26, x4    
        
        umaddl	x1, w19, w22, x1        
        umaddl	x3, w19, w24, x3        
        umaddl	x5, w19, w26, x5        
        umaddl	x7, w19, w28, x7     
               
        add	w11, w11, w11             
        umaddl	x2, w11, w21, x2                
        umaddl	x4, w11, w23, x4
        umaddl	x6, w11, w25, x6
        umaddl	x8, w11, w27, x8        

        add	w13, w13, w13        
        umaddl	x4, w13, w21, x4       
        umaddl	x6, w13, w23, x6
        umaddl	x8, w13, w25, x8        

        add	w15, w15, w15        
        umaddl	x6, w15, w21, x6
        umaddl	x8, w15, w23, x8

        add	w17, w17, w17            
        umaddl	x8, w17, w21, x8
                
        mul	w21, w21, w30    
        mul	w23, w23, w30
        mul	w25, w25, w30
        mul	w27, w27, w30
        mul	w29, w29, w30
                   
        umaddl	x0, w11, w29, x0
        
        umaddl	x1, w12, w29, x1
        
        umaddl	x0, w13, w27, x0
        umaddl	x2, w13, w29, x2
        
        umaddl	x1, w14, w27, x1        
        umaddl	x3, w14, w29, x3        
                
        umaddl	x0, w15, w25, x0
        umaddl	x2, w15, w27, x2
        umaddl	x4, w15, w29, x4        
        
        umaddl	x1, w16, w25, x1
        umaddl	x3, w16, w27, x3
        umaddl	x5, w16, w29, x5
                
        umaddl	x0, w17, w23, x0
        umaddl	x2, w17, w25, x2
        umaddl	x4, w17, w27, x4        
        umaddl	x6, w17, w29, x6
        
        umaddl	x1, w18, w23, x1
        umaddl	x3, w18, w25, x3
        umaddl	x5, w18, w27, x5
        umaddl	x7, w18, w29, x7        
                
        add	w19, w19, w19                
        umaddl	x0, w19, w21, x0
        umaddl	x2, w19, w23, x2
        umaddl	x4, w19, w25, x4      
        umaddl	x6, w19, w27, x6	
        umaddl	x8, w19, w29, x8            

	add	x6, x6, x5, lsr #25
	and	x5, x5, #0x1ffffff
	
	add	x1, x1, x0, lsr #26
	and	x0, x0, #0x3ffffff
	
	add	x7, x7, x6, lsr #26
	and	x6, x6, #0x3ffffff
	
	add	x2, x2, x1, lsr #25
	and	x1, x1, #0x1ffffff
	
	add	x8, x8, x7, lsr #25
	and	x7, x7, #0x1ffffff

	add	x3, x3, x2, lsr #26
	and	x2, x2, #0x3ffffff
	
	add	x9, x9, x8, lsr #26
	and	x8, x8, #0x3ffffff
	
	add	x4, x4, x3, lsr #25
	and	x3, x3, #0x1ffffff
	bfi	x2, x3, #32, #25	
	
	bic	x10, x9, #0x1ffffff
	add	x0, x0, x10, lsr #25
	add	x0, x0, x10, lsr #24
	add	x0, x0, x10, lsr #21		
	and	x9, x9, #0x1ffffff
	bfi	x8, x9, #32, #25	
	
	add	x5, x5, x4, lsr #26
	and	x4, x4, #0x3ffffff
	
	add	x1, x1, x0, lsr #26
	and	x0, x0, #0x3ffffff	
	bfi	x0, x1, #32, #26	
	
	add	x6, x6, x5, lsr #25
	bfi	x6, x7, #32, #25	
	and	x5, x5, #0x1ffffff
	bfi	x4, x5, #32, #25
	
	ldr	x10, [sp, #96]
	stp	x0, x2, [x10, #80]
	stp	x4, x6, [x10, #96]
	str	x8, [x10, #112]	
	
	ldp	x29, x30, [sp, #80]
	ldp	x27, x28, [sp, #64]	
	ldp	x25, x26, [sp, #48]	
	ldp	x23, x24, [sp, #32]
	ldp	x21, x22, [sp, #16]	
	ldp	x19, x20, [sp, #0]
	add	sp, sp, #112
	
	ret
.section	.note.GNU-stack,"",@progbits
