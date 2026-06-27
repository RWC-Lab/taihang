#include "crypto_asm_hidden.h"
// linker define ge25519_multi_scalarmult_process

/* Assembly for multi scalar multiplication */

	.p2align 4
	ASM_HIDDEN _CRYPTO_SHARED_NAMESPACE(ge25519_multi_scalarmult_process)
	.globl _CRYPTO_SHARED_NAMESPACE(ge25519_multi_scalarmult_process)
	ASM_HIDDEN CRYPTO_SHARED_NAMESPACE(ge25519_multi_scalarmult_process)
	.globl CRYPTO_SHARED_NAMESPACE(ge25519_multi_scalarmult_process)
	
_CRYPTO_SHARED_NAMESPACE(ge25519_multi_scalarmult_process):
CRYPTO_SHARED_NAMESPACE(ge25519_multi_scalarmult_process):

	sub	sp, sp, #816
	stp	x19, x20, [sp, #0]
	stp	x21, x22, [sp, #16]
	stp	x23, x24, [sp, #32]
	stp	x25, x26, [sp, #48]
	stp	x27, x28, [sp, #64]
	stp	x29, x30, [sp, #80]
	
	movz	x21, #0xffda 
	movk	x21, #0x07ff, lsl 16
	movk	x21, #0xfffe, lsl 32
	movk	x21, #0x03ff, lsl 48
	
	movz	x22, #0xfffe 
	movk	x22, #0x07ff, lsl 16
	movk	x22, #0xfffe, lsl 32
	movk	x22, #0x03ff, lsl 48	

	stp	x21, x22, [sp, #192]
	
	movz	x21, #0xf159
	movk	x21, #0x02b2, lsl 16
	movk	x21, #0xe509, lsl 32
	movk	x21, #0x01a6, lsl 48
	
	movz	x22, #0xdd7a
	movk	x22, #0x022a, lsl 16
	movk	x22, #0x141d, lsl 32
	movk	x22, #0x00d4, lsl 48
	
	movz	x23, #0x8052
	movk	x23, #0x0003, lsl 16
	movk	x23, #0xd130, lsl 32
	movk	x23, #0x00f3, lsl 48
	
	movz	x24, #0x7977
	movk	x24, #0x0340, lsl 16
	movk	x24, #0xe331, lsl 32
	movk	x24, #0x019c, lsl 48
	
	movz	x25, #0x6dff
	movk	x25, #0x01c5, lsl 16
	movk	x25, #0x1b67, lsl 32
	movk	x25, #0x0090, lsl 48
	
	stp	x21, x22, [sp, #208]
	stp	x23, x24, [sp, #224]
	str	x25, [sp, #240]	
	
	mov	x27, #1
	stp	xzr, xzr, [sp, #248] 
	stp	xzr, xzr, [sp, #264]
	str	xzr, [sp, #280]
	
	stp	x27, xzr, [sp, #288]
	stp	xzr, xzr, [sp, #304]
	str	xzr, [sp, #320]	
	
	stp	x27, xzr, [sp, #328]
	stp	xzr, xzr, [sp, #344]
	str	xzr, [sp, #360]	
	
	stp	x27, xzr, [sp, #368]
	stp	xzr, xzr, [sp, #384]
	str	xzr, [sp, #400]
	
	str	x0, [sp, #96]
	str	x1, [sp, #104]
	str	x2, [sp, #112]
	str	x3, [sp, #120]

	mov	x25, xzr
	
	mov	x26, #160
	mul	x26, x26, x4

	mov	x29, #255
	
	add	x28, x1, x29
	
	stp	x25, x26, [sp, #160]
	stp	x28, x29, [sp, #176]
	
	mov	w30, #19
		
.L1:
	ldr	x25, [sp, #160]
	cmp	x25, xzr
	beq	.L2
	
	/* p1p1 to p2 */
	
	// mul
	add	x29, sp, #248
	ldp	w10, w11, [x29, #0]
	ldp	w12, w13, [x29, #8]
	ldp	w14, w15, [x29, #16]
	ldp	w16, w17, [x29, #24]
	ldp	w18, w19, [x29, #32]
	
	ldp	w20, w21, [x29, #120]
	ldp	w22, w23, [x29, #128]
	ldp	w24, w25, [x29, #136]
	ldp	w26, w27, [x29, #144]
	ldp	w28, w29, [x29, #152]
	
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
        
	stp	x0, x2, [sp, #408]
	stp	x4, x6, [sp, #424]
	str	x8, [sp, #440]
     
	// mul
	add	x29, sp, #288
	ldp	w10, w11, [x29, #0]
	ldp	w12, w13, [x29, #8]
	ldp	w14, w15, [x29, #16]
	ldp	w16, w17, [x29, #24]
	ldp	w18, w19, [x29, #32]
	
	ldp	w20, w21, [x29, #40]
	ldp	w22, w23, [x29, #48]
	ldp	w24, w25, [x29, #56]
	ldp	w26, w27, [x29, #64]
	ldp	w28, w29, [x29, #72]
	
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
        
	stp	x0, x2, [sp, #448]
	stp	x4, x6, [sp, #464]
	str	x8, [sp, #480]

	// mul
	add	x29, sp, #288
	ldp	w10, w11, [x29, #0]
	ldp	w12, w13, [x29, #8]
	ldp	w14, w15, [x29, #16]
	ldp	w16, w17, [x29, #24]
	ldp	w18, w19, [x29, #32]
	
	ldp	w20, w21, [x29, #80]
	ldp	w22, w23, [x29, #88]
	ldp	w24, w25, [x29, #96]
	ldp	w26, w27, [x29, #104]
	ldp	w28, w29, [x29, #112]
	
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
	and	x17, x7, #0x1ffffff

	add	x3, x3, x2, lsr #26
	and	x12, x2, #0x3ffffff
	
	add	x9, x9, x8, lsr #26
	and	x18, x8, #0x3ffffff
	
	add	x4, x4, x3, lsr #25
	and	x13, x3, #0x1ffffff
	
	bic	x10, x9, #0x1ffffff
	add	x0, x0, x10, lsr #25
	add	x0, x0, x10, lsr #24
	add	x0, x0, x10, lsr #21		
	and	x19, x9, #0x1ffffff
	
	add	x5, x5, x4, lsr #26
	and	x14, x4, #0x3ffffff
	
	add	x11, x1, x0, lsr #26
	and	x10, x0, #0x3ffffff	
	
	add	x16, x6, x5, lsr #25
	and	x15, x5, #0x1ffffff
	
	/* dbl p1p1 */
	
	// square		   	
        mul	w20, w16, w30
        mul	w21, w18, w30

        add	w25, w30, w30
        mul	w22, w15, w25
        mul	w23, w17, w25
        mul	w24, w19, w25

        umull	x0, w10, w10

        add	w25, w10, w10        
        umull	x1, w25, w11
        umull	x2, w25, w12
        umull	x3, w25, w13
        umull	x4, w25, w14
        umull	x5, w25, w15
        umull	x6, w25, w16
        umull	x7, w25, w17        
        umull	x8, w25, w18
        
        umaddl	x4, w12, w12, x4
        umaddl	x8, w14, w14, x8        
        
        add	w10, w15, w15        
        umaddl	x1, w20, w10, x1	
        umaddl	x2, w20, w16, x2

        add	 w9, w17, w17
        umaddl	x3, w21, w10, x3
        umaddl	x5, w21,  w9, x5        
        umaddl	x6, w21, w18, x6 
        
        umaddl	x0, w22, w15, x0       
       
        umaddl	x1, w23, w14, x1
        umaddl	x2, w23, w10, x2        
        umaddl	x3, w23, w16, x3
        umaddl	x4, w23, w17, x4

        umaddl	x1, w24, w12, x1
        umaddl	x3, w24, w14, x3
        umaddl	x4, w24, w10, x4
        umaddl	x5, w24, w16, x5
        umaddl	x6, w24,  w9, x6
        umaddl	x7, w24, w18, x7
        umaddl	x8, w24, w19, x8

        add	w26, w11, w11        
        umaddl	x0, w26, w24, x0
        umaddl	x2, w26, w11, x2
        umaddl	x3, w26, w12, x3
        umaddl	x5, w26, w14, x5
        umaddl	x6, w26, w10, x6
        umaddl	x7, w26, w16, x7
        umaddl	x8, w26,  w9, x8
        
        umull	x9, w25, w19
        umaddl	x9, w26, w18, x9
        
        add	w27, w12, w12        
        umaddl	x0, w27, w21, x0
        umaddl	x5, w27, w13, x5
        umaddl	x8, w27, w16, x8
        umaddl	x6, w27, w14, x6
        umaddl	x7, w27, w15, x7
        umaddl	x9, w27, w17, x9

        add	w28, w13, w13
        umaddl	x4, w26, w28, x4        
        umaddl	x0, w28, w23, x0
        umaddl	x1, w28, w21, x1
        umaddl	x2, w28, w24, x2
        umaddl	x8, w28, w10, x8
        umaddl	x6, w28, w13, x6
        umaddl	x7, w28, w14, x7
        umaddl	x9, w28, w16, x9
                
        add	w29, w14, w14                
        umaddl	x0, w29, w20, x0        
        umaddl	x2, w29, w21, x2
        umaddl	x9, w29, w15, x9
        
        add	w18, w16, w16        
        umaddl	x4, w18, w21, x4 
        
	// double
        add	x0, x0, x0
        add	x1, x1, x1
        add	x2, x2, x2
        add	x3, x3, x3
        add	x4, x4, x4
        add	x5, x5, x5
        add	x6, x6, x6
        add	x7, x7, x7
        add	x8, x8, x8
        add	x9, x9, x9                      
	
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
	
	add	x29, sp, #568
	stp	x0, x2, [x29, #0]
	stp	x4, x6, [x29, #16]
	str	x8, [x29, #32]
	
	// square
	add	x29, sp, #448	
	ldp	w10, w11, [x29, #0]
	ldp	w12, w13, [x29, #8]
	ldp	w14, w15, [x29, #16]
	ldp	w16, w17, [x29, #24]
	ldp	w18, w19, [x29, #32]	
        	
        mul	w20, w16, w30
        mul	w21, w18, w30

        add	w25, w30, w30
        mul	w22, w15, w25
        mul	w23, w17, w25
        mul	w24, w19, w25

        umull	x0, w10, w10

        add	w25, w10, w10        
        umull	x1, w25, w11
        umull	x2, w25, w12
        umull	x3, w25, w13
        umull	x4, w25, w14
        umull	x5, w25, w15
        umull	x6, w25, w16
        umull	x7, w25, w17        
        umull	x8, w25, w18
        
        umaddl	x4, w12, w12, x4
        umaddl	x8, w14, w14, x8        
        
        add	w10, w15, w15        
        umaddl	x1, w20, w10, x1	
        umaddl	x2, w20, w16, x2

        add	 w9, w17, w17
        umaddl	x3, w21, w10, x3
        umaddl	x5, w21,  w9, x5        
        umaddl	x6, w21, w18, x6 
        
        umaddl	x0, w22, w15, x0       
       
        umaddl	x1, w23, w14, x1
        umaddl	x2, w23, w10, x2        
        umaddl	x3, w23, w16, x3
        umaddl	x4, w23, w17, x4

        umaddl	x1, w24, w12, x1
        umaddl	x3, w24, w14, x3
        umaddl	x4, w24, w10, x4
        umaddl	x5, w24, w16, x5
        umaddl	x6, w24,  w9, x6
        umaddl	x7, w24, w18, x7
        umaddl	x8, w24, w19, x8

        add	w26, w11, w11        
        umaddl	x0, w26, w24, x0
        umaddl	x2, w26, w11, x2
        umaddl	x3, w26, w12, x3
        umaddl	x5, w26, w14, x5
        umaddl	x6, w26, w10, x6
        umaddl	x7, w26, w16, x7
        umaddl	x8, w26,  w9, x8
        
        umull	x9, w25, w19
        umaddl	x9, w26, w18, x9
        
        add	w27, w12, w12        
        umaddl	x0, w27, w21, x0
        umaddl	x5, w27, w13, x5
        umaddl	x8, w27, w16, x8
        umaddl	x6, w27, w14, x6
        umaddl	x7, w27, w15, x7
        umaddl	x9, w27, w17, x9

        add	w28, w13, w13
        umaddl	x4, w26, w28, x4        
        umaddl	x0, w28, w23, x0
        umaddl	x1, w28, w21, x1
        umaddl	x2, w28, w24, x2
        umaddl	x8, w28, w10, x8
        umaddl	x6, w28, w13, x6
        umaddl	x7, w28, w14, x7
        umaddl	x9, w28, w16, x9
                
        add	w29, w14, w14                
        umaddl	x0, w29, w20, x0        
        umaddl	x2, w29, w21, x2
        umaddl	x9, w29, w15, x9
        
        add	w18, w16, w16        
        umaddl	x4, w18, w21, x4       
	
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
	
	add	x29, sp, #528
	stp	x0, x2, [x29, #0]
	stp	x4, x6, [x29, #16]
	str	x8, [x29, #32]

 	// square
	add	x29, sp, #408
	ldp	w10, w11, [x29, #0]
	ldp	w12, w13, [x29, #8]
	ldp	w14, w15, [x29, #16]
	ldp	w16, w17, [x29, #24]
	ldp	w18, w19, [x29, #32]	
        	
        mul	w20, w16, w30
        mul	w21, w18, w30

        add	w25, w30, w30
        mul	w22, w15, w25
        mul	w23, w17, w25
        mul	w24, w19, w25

        umull	x0, w10, w10

        add	w25, w10, w10        
        umull	x1, w25, w11
        umull	x2, w25, w12
        umull	x3, w25, w13
        umull	x4, w25, w14
        umull	x5, w25, w15
        umull	x6, w25, w16
        umull	x7, w25, w17        
        umull	x8, w25, w18
        
        umaddl	x4, w12, w12, x4
        umaddl	x8, w14, w14, x8        
        
        add	w10, w15, w15        
        umaddl	x1, w20, w10, x1	
        umaddl	x2, w20, w16, x2

        add	 w9, w17, w17
        umaddl	x3, w21, w10, x3
        umaddl	x5, w21,  w9, x5        
        umaddl	x6, w21, w18, x6 
        
        umaddl	x0, w22, w15, x0       
       
        umaddl	x1, w23, w14, x1
        umaddl	x2, w23, w10, x2        
        umaddl	x3, w23, w16, x3
        umaddl	x4, w23, w17, x4

        umaddl	x1, w24, w12, x1
        umaddl	x3, w24, w14, x3
        umaddl	x4, w24, w10, x4
        umaddl	x5, w24, w16, x5
        umaddl	x6, w24,  w9, x6
        umaddl	x7, w24, w18, x7
        umaddl	x8, w24, w19, x8

        add	w26, w11, w11        
        umaddl	x0, w26, w24, x0
        umaddl	x2, w26, w11, x2
        umaddl	x3, w26, w12, x3
        umaddl	x5, w26, w14, x5
        umaddl	x6, w26, w10, x6
        umaddl	x7, w26, w16, x7
        umaddl	x8, w26,  w9, x8
        
        umull	x9, w25, w19
        umaddl	x9, w26, w18, x9
        
        add	w27, w12, w12        
        umaddl	x0, w27, w21, x0
        umaddl	x5, w27, w13, x5
        umaddl	x8, w27, w16, x8
        umaddl	x6, w27, w14, x6
        umaddl	x7, w27, w15, x7
        umaddl	x9, w27, w17, x9

        add	w28, w13, w13
        umaddl	x4, w26, w28, x4        
        umaddl	x0, w28, w23, x0
        umaddl	x1, w28, w21, x1
        umaddl	x2, w28, w24, x2
        umaddl	x8, w28, w10, x8
        umaddl	x6, w28, w13, x6
        umaddl	x7, w28, w14, x7
        umaddl	x9, w28, w16, x9
                
        add	w29, w14, w14                
        umaddl	x0, w29, w20, x0        
        umaddl	x2, w29, w21, x2
        umaddl	x9, w29, w15, x9
        
        add	w18, w16, w16        
        umaddl	x4, w18, w21, x4       
	
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

	// neg	 
	ldp	x21, x23, [sp, #192]	  
        sub	x11, x21, x0
        sub	x12, x23, x2
        sub	x18, x23, x4
        sub	x19, x23, x6
        sub	x20, x23, x8

	// add	
	add	x29, sp, #528
	ldp	x13, x14, [x29, #0]
	ldp	x15, x16, [x29, #16]
	ldr	x17, [x29, #32]
	
        add	x0, x11, x13
        add	x2, x12, x14
        add	x4, x18, x15
        add	x6, x19, x16
        add	x8, x20, x17
        
	stp	x0, x2, [sp, #288]
	stp	x4, x6, [sp, #304]
	str	x8, [sp, #320]

	// sub
	add	x29, sp, #568
	ldp	x13, x14, [x29, #0]
	ldp	x15, x16, [x29, #16]
	ldr	x17, [x29, #32]
		
        sub	x0, x0, x13
        sub	x2, x2, x14
        sub	x4, x4, x15
        sub	x6, x6, x16
        sub	x8, x8, x17
 
	stp	x0, x2, [sp, #368]
	stp	x4, x6, [sp, #384]
	str	x8, [sp, #400]

	// sub	
	add	x29, sp, #528
	ldp	x13, x14, [x29, #0]
	ldp	x15, x16, [x29, #16]
	ldr	x17, [x29, #32]
	
	movz	x21, #0xffb4 
	movk	x21, #0x0fff, lsl 16
	movk	x21, #0xfffc, lsl 32
	movk	x21, #0x07ff, lsl 48
	
	movz	x23, #0xfffc 
	movk	x23, #0x0fff, lsl 16
	movk	x23, #0xfffc, lsl 32
	movk	x23, #0x07ff, lsl 48	

        add	x11, x11, x21
        add	x12, x12, x23
        add	x18, x18, x23
        add	x19, x19, x23
        add	x20, x20, x23	
        		
        sub	x0, x11, x13
        sub	x2, x12, x14
        sub	x4, x18, x15
        sub	x6, x19, x16
        sub	x8, x20, x17
        
        lsr	x1, x0, #32
        mov	w0, w0	
        lsr	x3, x2, #32
        mov	w2, w2	
        lsr	x5, x4, #32
        mov	w4, w4	
        lsr	x7, x6, #32
        mov	w6, w6	
        lsr	x9, x8, #32
        mov	w8, w8	                                        
        
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
        
	stp	x0, x2, [sp, #328]
	stp	x4, x6, [sp, #344]
	str	x8, [sp, #360]

	// add
	ldp	x10, x12, [sp, #408]
	ldp	x14, x16, [sp, #424]
	ldr	x18, [sp, #440]
		
	ldp	x20, x22, [sp, #448]
	ldp	x24, x26, [sp, #464]
	ldr	x28, [sp, #480]	
	    
        add	x10, x10, x20
        add	x12, x12, x22
        add	x14, x14, x24
        add	x16, x16, x26
        add	x18, x18, x28
        
	// square	
	lsr	x11, x10, #32
	lsr	x13, x12, #32	
	lsr	x15, x14, #32	
	lsr	x17, x16, #32
	lsr	x19, x18, #32	
        	
        mul	w20, w16, w30
        mul	w21, w18, w30

        add	w25, w30, w30
        mul	w22, w15, w25
        mul	w23, w17, w25
        mul	w24, w19, w25

        umull	x0, w10, w10

        add	w25, w10, w10        
        umull	x1, w25, w11
        umull	x2, w25, w12
        umull	x3, w25, w13
        umull	x4, w25, w14
        umull	x5, w25, w15
        umull	x6, w25, w16
        umull	x7, w25, w17        
        umull	x8, w25, w18
        
        umaddl	x4, w12, w12, x4
        umaddl	x8, w14, w14, x8        
        
        add	w10, w15, w15        
        umaddl	x1, w20, w10, x1	
        umaddl	x2, w20, w16, x2

        add	 w9, w17, w17
        umaddl	x3, w21, w10, x3
        umaddl	x5, w21,  w9, x5        
        umaddl	x6, w21, w18, x6 
        
        umaddl	x0, w22, w15, x0       
       
        umaddl	x1, w23, w14, x1
        umaddl	x2, w23, w10, x2        
        umaddl	x3, w23, w16, x3
        umaddl	x4, w23, w17, x4

        umaddl	x1, w24, w12, x1
        umaddl	x3, w24, w14, x3
        umaddl	x4, w24, w10, x4
        umaddl	x5, w24, w16, x5
        umaddl	x6, w24,  w9, x6
        umaddl	x7, w24, w18, x7
        umaddl	x8, w24, w19, x8

        add	w26, w11, w11        
        umaddl	x0, w26, w24, x0
        umaddl	x2, w26, w11, x2
        umaddl	x3, w26, w12, x3
        umaddl	x5, w26, w14, x5
        umaddl	x6, w26, w10, x6
        umaddl	x7, w26, w16, x7
        umaddl	x8, w26,  w9, x8
        
        umull	x9, w25, w19
        umaddl	x9, w26, w18, x9
        
        add	w27, w12, w12        
        umaddl	x0, w27, w21, x0
        umaddl	x5, w27, w13, x5
        umaddl	x8, w27, w16, x8
        umaddl	x6, w27, w14, x6
        umaddl	x7, w27, w15, x7
        umaddl	x9, w27, w17, x9

        add	w28, w13, w13
        umaddl	x4, w26, w28, x4        
        umaddl	x0, w28, w23, x0
        umaddl	x1, w28, w21, x1
        umaddl	x2, w28, w24, x2
        umaddl	x8, w28, w10, x8
        umaddl	x6, w28, w13, x6
        umaddl	x7, w28, w14, x7
        umaddl	x9, w28, w16, x9
                
        add	w29, w14, w14                
        umaddl	x0, w29, w20, x0        
        umaddl	x2, w29, w21, x2
        umaddl	x9, w29, w15, x9
        
        add	w18, w16, w16        
        umaddl	x4, w18, w21, x4       
	
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
        
        // add
	ldp	x13, x14, [sp, #328]
	ldp	x15, x16, [sp, #344]
	ldr	x17, [sp, #360]
	
        add	x0, x0, x13
        add	x2, x2, x14
        add	x4, x4, x15
        add	x6, x6, x16
        add	x8, x8, x17
	
	stp	x0, x2, [sp, #248]
	stp	x4, x6, [sp, #264]
	str	x8, [sp, #280]
	
.L2:		
	str	xzr, [sp, #128]
	ldr	x1, [sp, #176]
	str	x1, [sp, #136]
	
.L3:	
	ldrsb	w14, [x1, #0]
	
	cmp	w14, wzr
	bne	.L4
	
	add	x1, x1, #256
	str	x1, [sp, #136]
	ldr	x3, [sp, #128]
	add	x3, x3, #1
	str	x3, [sp, #128]
	ldr	x4, [sp, #120]	
	cmp	x3, x4
	blt	.L3
	
	ldp	x28, x29, [sp, #176]
	sub	x28, x28, #1
	sub	x29, x29, #1
	stp	x28, x29, [sp, #176]	
	cmp	x29, xzr
	bge	.L1	
	
	b	.L8
		
.L4:	
	mov	x25, #1
	str	x25, [sp, #160]
	str	w14, [sp, #144]
		
	/* p1p1 to p3 */
	
	// mul
	add	x29, sp, #248
	ldp	w10, w11, [x29, #0]
	ldp	w12, w13, [x29, #8]
	ldp	w14, w15, [x29, #16]
	ldp	w16, w17, [x29, #24]
	ldp	w18, w19, [x29, #32]
	
	ldp	w20, w21, [x29, #120]
	ldp	w22, w23, [x29, #128]
	ldp	w24, w25, [x29, #136]
	ldp	w26, w27, [x29, #144]
	ldp	w28, w29, [x29, #152]
	
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

	stp	x0, x2, [sp, #408]
	stp	x4, x6, [sp, #424]
	str	x8, [sp, #440]
   
	// mul
	add	x29, sp, #288
	ldp	w10, w11, [x29, #0]
	ldp	w12, w13, [x29, #8]
	ldp	w14, w15, [x29, #16]
	ldp	w16, w17, [x29, #24]
	ldp	w18, w19, [x29, #32]
	
	ldp	w20, w21, [x29, #40]
	ldp	w22, w23, [x29, #48]
	ldp	w24, w25, [x29, #56]
	ldp	w26, w27, [x29, #64]
	ldp	w28, w29, [x29, #72]
	
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

	stp	x0, x2, [sp, #448]
	stp	x4, x6, [sp, #464]
	str	x8, [sp, #480]	

	// mul
	add	x29, sp, #288
	ldp	w10, w11, [x29, #0]
	ldp	w12, w13, [x29, #8]
	ldp	w14, w15, [x29, #16]
	ldp	w16, w17, [x29, #24]
	ldp	w18, w19, [x29, #32]
	
	ldp	w20, w21, [x29, #80]
	ldp	w22, w23, [x29, #88]
	ldp	w24, w25, [x29, #96]
	ldp	w26, w27, [x29, #104]
	ldp	w28, w29, [x29, #112]
	
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

	add	x29, sp, #488
	stp	x0, x2, [x29, #0]
	stp	x4, x6, [x29, #16]
	str	x8, [x29, #32]	
		
	// mul
	add	x29, sp, #248
	ldp	w10, w11, [x29, #0]
	ldp	w12, w13, [x29, #8]
	ldp	w14, w15, [x29, #16]
	ldp	w16, w17, [x29, #24]
	ldp	w18, w19, [x29, #32]
	
	ldp	w20, w21, [x29, #80]
	ldp	w22, w23, [x29, #88]
	ldp	w24, w25, [x29, #96]
	ldp	w26, w27, [x29, #104]
	ldp	w28, w29, [x29, #112]
	
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

	add	x29, sp, #528
	stp	x0, x2, [x29, #0]
	stp	x4, x6, [x29, #16]
	str	x8, [x29, #32]		
	
	ldr	x0, [sp, #112]
	ldr	x9, [sp, #128]
	ldr	x26, [sp, #168]	
		
	mul	x8, x26, x9
	add	x0, x0, x8
	str	x0, [sp, #152]
	
	ldrsb	w14, [sp, #144]
	cmp	w14, wzr
	blt	.L5
	
	lsr	w14, w14, #1
	mov	x9, #160
	mul	x14, x14, x9
	add	x0, x0, x14
	str	x0, [sp, #152]	
	
	/* pnielsadd p1p1 */
	
	// add
	ldp	x10, x12, [sp, #448]
	ldp	x14, x16, [sp, #464]	
	ldr	x18, [sp, #480]
	
	ldp	x11, x13, [sp, #408]
	ldp	x15, x17, [sp, #424]	
	ldr	x19, [sp, #440]	
	
        add	x0, x10, x11
        add	x2, x12, x13
        add	x4, x14, x15
        add	x6, x16, x17
        add	x8, x18, x19

	add	x29, sp, #608
	stp	x0, x2, [x29, #0]
	stp	x4, x6, [x29, #16]
	str	x8, [x29, #32]	

	// sub	
	ldp	x21, x22, [sp, #192]	
        add	x10, x10, x21
        add	x12, x12, x22
        add	x14, x14, x22
        add	x16, x16, x22
        add	x18, x18, x22
        
        sub	x10, x10, x11
        sub	x12, x12, x13
        sub	x14, x14, x15
        sub	x16, x16, x17
        sub	x18, x18, x19
	
	// mul
	ldr	x0, [sp, #152]
	ldp	w20, w21, [x0, #0]
	ldp	w22, w23, [x0, #8]
	ldp	w24, w25, [x0, #16]
	ldp	w26, w27, [x0, #24]
	ldp	w28, w29, [x0, #32]
	
	lsr	x11, x10, #32
	lsr	x13, x12, #32	
	lsr	x15, x14, #32	
	lsr	x17, x16, #32
	lsr	x19, x18, #32
	
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

	add	x29, sp, #568
	stp	x0, x2, [x29, #0]
	stp	x4, x6, [x29, #16]
	str	x8, [x29, #32]		
        
	// mul
	ldr	x0, [sp, #152]	
	ldp	w10, w11, [x0, #40]
	ldp	w12, w13, [x0, #48]
	ldp	w14, w15, [x0, #56]
	ldp	w16, w17, [x0, #64]
	ldp	w18, w19, [x0, #72]
		
	ldp	w20, w21, [x29, #40]
	ldp	w22, w23, [x29, #48]
	ldp	w24, w25, [x29, #56]
	ldp	w26, w27, [x29, #64]
	ldp	w28, w29, [x29, #72]

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

	// add
	add	x29, sp, #528
	ldp	x13, x14, [x29, #40]
	ldp	x15, x16, [x29, #56]
	ldr	x17, [x29, #72]
		
        add	x1, x0, x13
        add	x3, x2, x14
        add	x5, x4, x15
        add	x7, x6, x16
        add	x9, x8, x17
        	
	stp	x1, x3, [sp, #328]
	stp	x5, x7, [sp, #344]
	str	x9, [sp, #360]
        
	// sub
	ldp	x21, x22, [sp, #192]	
        add	x0, x0, x21
        add	x2, x2, x22
        add	x4, x4, x22
        add	x6, x6, x22
        add	x8, x8, x22
        
        sub	x0, x0, x13
        sub	x2, x2, x14
        sub	x4, x4, x15
        sub	x6, x6, x16
        sub	x8, x8, x17
	
	stp	x0, x2, [sp, #248]
	stp	x4, x6, [sp, #264]
	str	x8, [sp, #280]

	// mul
	ldr	x0, [sp, #152]	
	ldp	w10, w11, [x0, #120]
	ldp	w12, w13, [x0, #128]
	ldp	w14, w15, [x0, #136]
	ldp	w16, w17, [x0, #144]
	ldp	w18, w19, [x0, #152]
	
	ldp	w20, w21, [x29, #0]
	ldp	w22, w23, [x29, #8]
	ldp	w24, w25, [x29, #16]
	ldp	w26, w27, [x29, #24]
	ldp	w28, w29, [x29, #32]
	
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

	add	x29, sp, #488
	stp	x0, x2, [x29, #80]
	stp	x4, x6, [x29, #96]
	str	x8, [x29, #112]	

	// mul
	ldr	x0, [sp, #152]	
	ldp	w10, w11, [x0, #80]
	ldp	w12, w13, [x0, #88]
	ldp	w14, w15, [x0, #96]
	ldp	w16, w17, [x0, #104]
	ldp	w18, w19, [x0, #112]
		
	ldp	w20, w21, [x29, #0]
	ldp	w22, w23, [x29, #8]
	ldp	w24, w25, [x29, #16]
	ldp	w26, w27, [x29, #24]
	ldp	w28, w29, [x29, #32]
	
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
        
        // double and then reduce
        add	x0, x0, x0
        add	x1, x1, x1
        add	x2, x2, x2
        add	x3, x3, x3
        add	x4, x4, x4
        add	x5, x5, x5
        add	x6, x6, x6
        add	x7, x7, x7
        add	x8, x8, x8
        add	x9, x9, x9        

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

	// add
	add	x29, sp, #568
	ldp	x13, x14, [x29, #0]
	ldp	x15, x16, [x29, #16]
	ldr	x17, [x29, #32]
		
        add	x1, x0, x13
        add	x3, x2, x14
        add	x5, x4, x15
        add	x7, x6, x16
        add	x9, x8, x17
	
	stp	x1, x3, [sp, #288]
	stp	x5, x7, [sp, #304] 
	str	x9, [sp, #320]

	// sub
	ldp	x21, x22, [sp, #192]	
        add	x0, x0, x21
        add	x2, x2, x22
        add	x4, x4, x22
        add	x6, x6, x22
        add	x8, x8, x22
        
        sub	x0, x0, x13
        sub	x2, x2, x14
        sub	x4, x4, x15
        sub	x6, x6, x16
        sub	x8, x8, x17
	
	stp	x0, x2, [sp, #368]
	stp	x4, x6, [sp, #384]
	str	x8, [sp, #400]

	b	.L6		
		
.L5:		
	mov	w15, wzr
	sub	w15, w15, w14
	lsr	w15, w15, #1
	mov	x9, #160
	mul	x15, x15, x9
	add	x0, x0, x15
	str	x0, [sp, #152]	
	
	/* pnielssub p1p1 */
               
	// neg
	ldr	x0, [sp, #152]		
	ldp	x7, x8, [x0, #120]
	ldp	x9, x10, [x0, #136]
	ldr	x11, [x0, #152]	
	    
	ldp	x21, x22, [sp, #192]	    
        sub	x7, x21, x7
        sub	x8, x22, x8
        sub	x9, x22, x9
        sub	x10, x22, x10
        sub	x11, x22, x11
	
	add	x29, sp, #648
	stp	x7, x8, [x29, #0]
	stp	x9, x10, [x29, #16]
	str	x11, [x29, #32]

	// add
	ldp	x10, x12, [sp, #448]
	ldp	x14, x16, [sp, #464]	
	ldr	x18, [sp, #480]
	
	ldp	x11, x13, [sp, #408]
	ldp	x15, x17, [sp, #424]	
	ldr	x19, [sp, #440]	
	
        add	x0, x10, x11
        add	x2, x12, x13
        add	x4, x14, x15
        add	x6, x16, x17
        add	x8, x18, x19

	add	x29, sp, #608
	stp	x0, x2, [x29, #0]
	stp	x4, x6, [x29, #16]
	str	x8, [x29, #32]

	// sub	
	ldp	x21, x22, [sp, #192]	
        add	x10, x10, x21
        add	x12, x12, x22
        add	x14, x14, x22
        add	x16, x16, x22
        add	x18, x18, x22
        
        sub	x10, x10, x11
        sub	x12, x12, x13
        sub	x14, x14, x15
        sub	x16, x16, x17
        sub	x18, x18, x19
	
	// mul
	ldr	x0, [sp, #152]	
	ldp	w20, w21, [x0, #40]
	ldp	w22, w23, [x0, #48]
	ldp	w24, w25, [x0, #56]
	ldp	w26, w27, [x0, #64]
	ldp	w28, w29, [x0, #72]
	
	lsr	x11, x10, #32
	lsr	x13, x12, #32	
	lsr	x15, x14, #32	
	lsr	x17, x16, #32
	lsr	x19, x18, #32
	
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

	add	x29, sp, #568
	stp	x0, x2, [x29, #0]
	stp	x4, x6, [x29, #16]
	str	x8, [x29, #32]	

	// mul
	ldr	x0, [sp, #152]	
	ldp	w10, w11, [x0, #0]
	ldp	w12, w13, [x0, #8]
	ldp	w14, w15, [x0, #16]
	ldp	w16, w17, [x0, #24]
	ldp	w18, w19, [x0, #32]		
	
	ldp	w20, w21, [x29, #40]
	ldp	w22, w23, [x29, #48]
	ldp	w24, w25, [x29, #56]
	ldp	w26, w27, [x29, #64]
	ldp	w28, w29, [x29, #72]
		
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

	// add
	add	x29, sp, #568
	ldp	x13, x14, [x29, #0]
	ldp	x15, x16, [x29, #16]
	ldr	x17, [x29, #32]
		
        add	x1, x0, x13
        add	x3, x2, x14
        add	x5, x4, x15
        add	x7, x6, x16
        add	x9, x8, x17
	
	stp	x1, x3, [sp, #328]
	stp	x5, x7, [sp, #344]
	str	x9, [sp, #360]

	// sub
	ldp	x21, x22, [sp, #192]	
        add	x0, x0, x21
        add	x2, x2, x22
        add	x4, x4, x22
        add	x6, x6, x22
        add	x8, x8, x22
        
        sub	x0, x0, x13
        sub	x2, x2, x14
        sub	x4, x4, x15
        sub	x6, x6, x16
        sub	x8, x8, x17
	
	stp	x0, x2, [sp, #248]
	stp	x4, x6, [sp, #264]
	str	x8, [sp, #280]

	// mul
	add	x29, sp, #528	
	ldp	w10, w11, [x29, #0]
	ldp	w12, w13, [x29, #8]
	ldp	w14, w15, [x29, #16]
	ldp	w16, w17, [x29, #24]
	ldp	w18, w19, [x29, #32]
	
	ldp	w20, w21, [x29, #120]
	ldp	w22, w23, [x29, #128]
	ldp	w24, w25, [x29, #136]
	ldp	w26, w27, [x29, #144]
	ldp	w28, w29, [x29, #152]
	
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

	add	x29, sp, #488
	stp	x0, x2, [x29, #80]
	stp	x4, x6, [x29, #96]
	str	x8, [x29, #112]
        
	// mul
	ldr	x0, [sp, #152]	
	ldp	w10, w11, [x0, #80]
	ldp	w12, w13, [x0, #88]
	ldp	w14, w15, [x0, #96]
	ldp	w16, w17, [x0, #104]
	ldp	w18, w19, [x0, #112]	
	
	ldp	w20, w21, [x29, #0]
	ldp	w22, w23, [x29, #8]
	ldp	w24, w25, [x29, #16]
	ldp	w26, w27, [x29, #24]
	ldp	w28, w29, [x29, #32]
	
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
        
        // double and then reduce
        add	x0, x0, x0
        add	x1, x1, x1
        add	x2, x2, x2
        add	x3, x3, x3
        add	x4, x4, x4
        add	x5, x5, x5
        add	x6, x6, x6
        add	x7, x7, x7
        add	x8, x8, x8
        add	x9, x9, x9                             

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
	
	// add
	add	x29, sp, #568
	ldp	x13, x14, [x29, #0]
	ldp	x15, x16, [x29, #16]
	ldr	x17, [x29, #32]
		
        add	x1, x0, x13
        add	x3, x2, x14
        add	x5, x4, x15
        add	x7, x6, x16
        add	x9, x8, x17
	
	stp	x1, x3, [sp, #288]
	stp	x5, x7, [sp, #304]
	str	x9, [sp, #320]

	// sub
	ldp	x21, x22, [sp, #192]	
        add	x0, x0, x21
        add	x2, x2, x22
        add	x4, x4, x22
        add	x6, x6, x22
        add	x8, x8, x22
        
        sub	x0, x0, x13
        sub	x2, x2, x14
        sub	x4, x4, x15
        sub	x6, x6, x16
        sub	x8, x8, x17
	
	stp	x0, x2, [sp, #368]
	stp	x4, x6, [sp, #384]
	str	x8, [sp, #400]	
	
.L6:	
	ldr	x1, [sp, #136]
	add	x1, x1, #256
	str	x1, [sp, #136]
	ldr	x3, [sp, #128]
	add	x3, x3, #1
	str	x3, [sp, #128]
	ldr	x4, [sp, #120]
	cmp	x3, x4
	blt	.L3

.L7:
	ldp	x28, x29, [sp, #176]
	sub	x28, x28, #1
	sub	x29, x29, #1
	stp	x28, x29, [sp, #176]	
	cmp	x29, xzr
	bge	.L1
	
.L8:	
	/* p1p1 to p3 */
	
	// mul
	add	x29, sp, #248
	ldp	w10, w11, [x29, #0]
	ldp	w12, w13, [x29, #8]
	ldp	w14, w15, [x29, #16]
	ldp	w16, w17, [x29, #24]
	ldp	w18, w19, [x29, #32]
	
	ldp	w20, w21, [x29, #120]
	ldp	w22, w23, [x29, #128]
	ldp	w24, w25, [x29, #136]
	ldp	w26, w27, [x29, #144]
	ldp	w28, w29, [x29, #152]
	
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
        
	stp	x0, x2, [sp, #408]
	stp	x4, x6, [sp, #424]
	str	x8, [sp, #440]
      
	// mul
	add	x29, sp, #288
	ldp	w10, w11, [x29, #0]
	ldp	w12, w13, [x29, #8]
	ldp	w14, w15, [x29, #16]
	ldp	w16, w17, [x29, #24]
	ldp	w18, w19, [x29, #32]
	
	ldp	w20, w21, [x29, #40]
	ldp	w22, w23, [x29, #48]
	ldp	w24, w25, [x29, #56]
	ldp	w26, w27, [x29, #64]
	ldp	w28, w29, [x29, #72]
	
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

	stp	x0, x2, [sp, #448]
	stp	x4, x6, [sp, #464]
	str	x8, [sp, #480]

	/* p3 to cached add/sub */	
	
	// add
	ldp	x13, x14, [sp, #408]
	ldp	x15, x16, [sp, #424]	
	ldr	x17, [sp, #440]
		
        add	x1, x0, x13
        add	x3, x2, x14
        add	x5, x4, x15
        add	x7, x6, x16
        add	x9, x8, x17
	
	add	x29, sp, #688	
	stp	x1, x3, [x29, #0]
	stp	x5, x7, [x29, #16]
	str	x9, [x29, #32]

	// sub
	ldp	x21, x22, [sp, #192]	
        add	x0, x0, x21
        add	x2, x2, x22
        add	x4, x4, x22
        add	x6, x6, x22
        add	x8, x8, x22
        
        sub	x0, x0, x13
        sub	x2, x2, x14
        sub	x4, x4, x15
        sub	x6, x6, x16
        sub	x8, x8, x17
	
	add	x29, sp, #648	
	stp	x0, x2, [x29, #0]
	stp	x4, x6, [x29, #16]
	str	x8, [x29, #32]

	// mul
	add	x29, sp, #288
	ldp	w10, w11, [x29, #0]
	ldp	w12, w13, [x29, #8]
	ldp	w14, w15, [x29, #16]
	ldp	w16, w17, [x29, #24]
	ldp	w18, w19, [x29, #32]
	
	ldp	w20, w21, [x29, #80]
	ldp	w22, w23, [x29, #88]
	ldp	w24, w25, [x29, #96]
	ldp	w26, w27, [x29, #104]
	ldp	w28, w29, [x29, #112]
	
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

	/* p3 to cached: assign to third fe */
	
	add	x29, sp, #728	
	stp	x0, x2, [x29, #0]
	stp	x4, x6, [x29, #16]
	str	x8, [x29, #32]
	
	// mul
	add	x29, sp, #248
	ldp	w10, w11, [x29, #0]
	ldp	w12, w13, [x29, #8]
	ldp	w14, w15, [x29, #16]
	ldp	w16, w17, [x29, #24]
	ldp	w18, w19, [x29, #32]
	
	ldp	w20, w21, [x29, #80]
	ldp	w22, w23, [x29, #88]
	ldp	w24, w25, [x29, #96]
	ldp	w26, w27, [x29, #104]
	ldp	w28, w29, [x29, #112]
	
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
	and	x17, x7, #0x1ffffff

	add	x3, x3, x2, lsr #26
	and	x12, x2, #0x3ffffff
	
	add	x9, x9, x8, lsr #26
	and	x18, x8, #0x3ffffff
	
	add	x4, x4, x3, lsr #25
	and	x13, x3, #0x1ffffff
	
	bic	x10, x9, #0x1ffffff
	add	x0, x0, x10, lsr #25
	add	x0, x0, x10, lsr #24
	add	x0, x0, x10, lsr #21		
	and	x19, x9, #0x1ffffff
	
	add	x5, x5, x4, lsr #26
	and	x14, x4, #0x3ffffff
	
	add	x11, x1, x0, lsr #26
	and	x10, x0, #0x3ffffff	
	
	add	x16, x6, x5, lsr #25
	and	x15, x5, #0x1ffffff
	
	/* p3 to cached: multiply the fourth fe  */
	
	// mul
	add	x29, sp, #208
	ldp	w20, w21, [x29, #0]
	ldp	w22, w23, [x29, #8]
	ldp	w24, w25, [x29, #16]
	ldp	w26, w27, [x29, #24]
	ldp	w28, w29, [x29, #32]
	
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
	
	add	x29, sp, #768	
	stp	x0, x2, [x29, #0]
	stp	x4, x6, [x29, #16]
	str	x8, [x29, #32]	

	/* p1p1 to p3 */
		
	// mul
	ldr	x0, [sp, #96]	
	ldp	w10, w11, [x0, #0]
	ldp	w12, w13, [x0, #8]
	ldp	w14, w15, [x0, #16]
	ldp	w16, w17, [x0, #24]
	ldp	w18, w19, [x0, #32]
	
	ldp	w20, w21, [x0, #120]
	ldp	w22, w23, [x0, #128]
	ldp	w24, w25, [x0, #136]
	ldp	w26, w27, [x0, #144]
	ldp	w28, w29, [x0, #152]
	
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
        
	stp	x0, x2, [sp, #408]
	stp	x4, x6, [sp, #424]
	str	x8, [sp, #440]
     
	// mul
	ldr	x0, [sp, #96]	
	ldp	w10, w11, [x0, #40]
	ldp	w12, w13, [x0, #48]
	ldp	w14, w15, [x0, #56]
	ldp	w16, w17, [x0, #64]
	ldp	w18, w19, [x0, #72]
	
	ldp	w20, w21, [x0, #80]
	ldp	w22, w23, [x0, #88]
	ldp	w24, w25, [x0, #96]
	ldp	w26, w27, [x0, #104]
	ldp	w28, w29, [x0, #112]
	
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

	stp	x0, x2, [sp, #448]
	stp	x4, x6, [sp, #464]
	str	x8, [sp, #480]

	// mul
	ldr	x0, [sp, #96]	
	ldp	w10, w11, [x0, #40]
	ldp	w12, w13, [x0, #48]
	ldp	w14, w15, [x0, #56]
	ldp	w16, w17, [x0, #64]
	ldp	w18, w19, [x0, #72]
	
	ldp	w20, w21, [x0, #120]
	ldp	w22, w23, [x0, #128]
	ldp	w24, w25, [x0, #136]
	ldp	w26, w27, [x0, #144]
	ldp	w28, w29, [x0, #152]
	
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

	add	x29, sp, #488
	stp	x0, x2, [x29, #0]
	stp	x4, x6, [x29, #16]
	str	x8, [x29, #32]
	
	// mul
	ldr	x0, [sp, #96]	
	ldp	w10, w11, [x0, #0]
	ldp	w12, w13, [x0, #8]
	ldp	w14, w15, [x0, #16]
	ldp	w16, w17, [x0, #24]
	ldp	w18, w19, [x0, #32]
	
	ldp	w20, w21, [x0, #80]
	ldp	w22, w23, [x0, #88]
	ldp	w24, w25, [x0, #96]
	ldp	w26, w27, [x0, #104]
	ldp	w28, w29, [x0, #112]
	
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

	add	x29, sp, #528
	stp	x0, x2, [x29, #0]
	stp	x4, x6, [x29, #16]
	str	x8, [x29, #32]

	/* pnielsadd p1p1 */

	// add
	ldp	x10, x12, [sp, #448]
	ldp	x14, x16, [sp, #464]	
	ldr	x18, [sp, #480]
	
	ldp	x11, x13, [sp, #408]
	ldp	x15, x17, [sp, #424]	
	ldr	x19, [sp, #440]	
	
        add	x0, x10, x11
        add	x2, x12, x13
        add	x4, x14, x15
        add	x6, x16, x17
        add	x8, x18, x19

	add	x29, sp, #608
	stp	x0, x2, [x29, #0]
	stp	x4, x6, [x29, #16]
	str	x8, [x29, #32]

	// sub
	ldp	x21, x22, [sp, #192]		
        add	x10, x10, x21
        add	x12, x12, x22
        add	x14, x14, x22
        add	x16, x16, x22
        add	x18, x18, x22
        
        sub	x10, x10, x11
        sub	x12, x12, x13
        sub	x14, x14, x15
        sub	x16, x16, x17
        sub	x18, x18, x19

	// mul
	add	x29, sp, #648	
	ldp	w20, w21, [x29, #0]
	ldp	w22, w23, [x29, #8]
	ldp	w24, w25, [x29, #16]
	ldp	w26, w27, [x29, #24]
	ldp	w28, w29, [x29, #32]
		
	lsr	x11, x10, #32
	lsr	x13, x12, #32	
	lsr	x15, x14, #32	
	lsr	x17, x16, #32
	lsr	x19, x18, #32
	
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

	add	x29, sp, #568
	stp	x0, x2, [x29, #0]
	stp	x4, x6, [x29, #16]
	str	x8, [x29, #32]	

	// mul
	add	x29, sp, #608
	ldp	w10, w11, [x29, #0]
	ldp	w12, w13, [x29, #8]
	ldp	w14, w15, [x29, #16]
	ldp	w16, w17, [x29, #24]
	ldp	w18, w19, [x29, #32]
	
	ldp	w20, w21, [x29, #80]
	ldp	w22, w23, [x29, #88]
	ldp	w24, w25, [x29, #96]
	ldp	w26, w27, [x29, #104]
	ldp	w28, w29, [x29, #112]
	
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

	// add
	add	x29, sp, #568
	ldp	x13, x14, [x29, #0]
	ldp	x15, x16, [x29, #16]
	ldr	x17, [x29, #32]
	
        add	x1, x0, x13
        add	x3, x2, x14
        add	x5, x4, x15
        add	x7, x6, x16
        add	x9, x8, x17		
	
	ldr	x10, [sp, #96]	
	stp	x1, x3, [x10, #80]
	stp	x5, x7, [x10, #96]
	str	x9, [x10, #112]

	// sub
	ldp	x21, x22, [sp, #192]	
        add	x0, x0, x21
        add	x2, x2, x22
        add	x4, x4, x22
        add	x6, x6, x22
        add	x8, x8, x22
        
        sub	x0, x0, x13
        sub	x2, x2, x14
        sub	x4, x4, x15
        sub	x6, x6, x16
        sub	x8, x8, x17        
	
	ldr	x10, [sp, #96]	
	stp	x0, x2, [x10, #0]
	stp	x4, x6, [x10, #16]
	str	x8, [x10, #32]

	// mul
	add	x29, sp, #528
	ldp	w10, w11, [x29, #0]
	ldp	w12, w13, [x29, #8]
	ldp	w14, w15, [x29, #16]
	ldp	w16, w17, [x29, #24]
	ldp	w18, w19, [x29, #32]
	
	add	x29, sp, #768	
	ldp	w20, w21, [x29, #0]
	ldp	w22, w23, [x29, #8]
	ldp	w24, w25, [x29, #16]
	ldp	w26, w27, [x29, #24]
	ldp	w28, w29, [x29, #32]
	
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

	add	x29, sp, #568
	stp	x0, x2, [x29, #0]
	stp	x4, x6, [x29, #16]
	str	x8, [x29, #32]	

	// mul
	add	x29, sp, #488
	ldp	w10, w11, [x29, #0]
	ldp	w12, w13, [x29, #8]
	ldp	w14, w15, [x29, #16]
	ldp	w16, w17, [x29, #24]
	ldp	w18, w19, [x29, #32]
	
	add	x29, sp, #728	
	ldp	w20, w21, [x29, #0]
	ldp	w22, w23, [x29, #8]
	ldp	w24, w25, [x29, #16]
	ldp	w26, w27, [x29, #24]
	ldp	w28, w29, [x29, #32]
	
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
        
        // double and then reduce
        add	x0, x0, x0
        add	x1, x1, x1
        add	x2, x2, x2
        add	x3, x3, x3
        add	x4, x4, x4
        add	x5, x5, x5
        add	x6, x6, x6
        add	x7, x7, x7
        add	x8, x8, x8
        add	x9, x9, x9        

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
	
	// add
	add	x29, sp, #568
	ldp	x13, x14, [x29, #0]
	ldp	x15, x16, [x29, #16]
	ldr	x17, [x29, #32]
		
        add	x1, x0, x13
        add	x3, x2, x14
        add	x5, x4, x15
        add	x7, x6, x16
        add	x9, x8, x17
	
	ldr	x10, [sp, #96]	
	stp	x1, x3, [x10, #40]
	stp	x5, x7, [x10, #56]
	str	x9, [x10, #72]

	// sub
	ldp	x21, x22, [sp, #192]
        add	x0, x0, x21
        add	x2, x2, x22
        add	x4, x4, x22
        add	x6, x6, x22
        add	x8, x8, x22
        
        sub	x0, x0, x13
        sub	x2, x2, x14
        sub	x4, x4, x15
        sub	x6, x6, x16
        sub	x8, x8, x17       
        
	ldr	x10, [sp, #96]	
	stp	x0, x2, [x10, #120]
	stp	x4, x6, [x10, #136]
	str	x8, [x10, #152]	
		
	ldp	x29, x30, [sp, #80]
	ldp	x27, x28, [sp, #64]	
	ldp	x25, x26, [sp, #48]	
	ldp	x23, x24, [sp, #32]
	ldp	x21, x22, [sp, #16]	
	ldp	x19, x20, [sp, #0]
	add	sp, sp, #816

	ret
.section	.note.GNU-stack,"",@progbits
