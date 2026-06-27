#include "crypto_asm_hidden.h"

// 2-way Montgomery ladder, 10-limb implementation

	.p2align 4
	ASM_HIDDEN _CRYPTO_SHARED_NAMESPACE(mladder_2x1)
	.globl _CRYPTO_SHARED_NAMESPACE(mladder_2x1)
	ASM_HIDDEN CRYPTO_SHARED_NAMESPACE(mladder_2x1)
	.globl CRYPTO_SHARED_NAMESPACE(mladder_2x1)
	
_CRYPTO_SHARED_NAMESPACE(mladder_2x1):
CRYPTO_SHARED_NAMESPACE(mladder_2x1):

	sub	sp, sp, #1632
	stp	x19, x20, [sp, #0]
	stp	x21, x22, [sp, #16]
	stp	x23, x24, [sp, #32]
	stp	x25, x26, [sp, #48]
	stp	x27, x28, [sp, #64]
	stp	x29, x30, [sp, #80]
	stp	d8,  d9,  [sp, #96]
	stp	d10, d11, [sp, #112]
	stp	d12, d13, [sp, #128]
	stp	d14, d15, [sp, #144]
		
	mov	x4, #1		
	mov	w30, #19
	mov	w29, #0x03ffffff
	
	movz	x12, #0xdb42
	movk	x12, #0x0001, lsl 16
	movk	x12, #0xdb42, lsl 32
	movk	x12, #0x0001, lsl 48
	
	movz	x21, #0xffda
	movk	x21, #0x07ff, lsl 16
	movk	x21, #0xffda, lsl 32
	movk	x21, #0x07ff, lsl 48
	
	movz	x22, #0xfffe
	movk	x22, #0x03ff, lsl 16
	movk	x22, #0xfffe, lsl 32
	movk	x22, #0x03ff, lsl 48
	
	movz	x23, #0xfffe
	movk	x23, #0x07ff, lsl 16
	movk	x23, #0xfffe, lsl 32
	movk	x23, #0x07ff, lsl 48	

	// X1 ← XP,X3 ← XP
	
	add	x20, sp, #192
	
	ldr	q20, [x1, #0]
	str	q20, [x20, #0]
	str	q20, [x20, #480]
	
	ldr	q20, [x1, #16]
	str	q20, [x20, #16]
	str	q20, [x20, #496]
	
	ldr	q20, [x1, #32]
	str	q20, [x20, #32]
	str	q20, [x20, #512]
	
	ldr	q20, [x1, #48]
	str	q20, [x20, #48]
	str	q20, [x20, #528]
	
	ldr	q20, [x1, #64]
	str	q20, [x20, #64]
	str	q20, [x20, #544]
	
	ldr	q20, [x1, #80]
	str	q20, [x20, #80]
	str	q20, [x20, #560]
	
	ldr	q20, [x1, #96]
	str	q20, [x20, #96]
	str	q20, [x20, #576]
	
	ldr	q20, [x1, #112]
	str	q20, [x20, #112]
	str	q20, [x20, #592]
	
	ldr	q20, [x1, #128]
	str	q20, [x20, #128]
	str	q20, [x20, #608]
	
	ldr	q20, [x1, #144]
	str	q20, [x20, #144]
	str	q20, [x20, #624]
	
	dup 	v20.2s, w4
	dup 	v21.2s, wzr

	// X2 ← 1
	str	q20, [x20, #160]
	str	q21, [x20, #176]
	str	q21, [x20, #192]
	str	q21, [x20, #208]
	str	q21, [x20, #224]
	str	q21, [x20, #240]
	str	q21, [x20, #256]
	str	q21, [x20, #272]
	str	q21, [x20, #288]
	str	q21, [x20, #304]

	// Z2 ← 0
	str	q21, [x20, #320]
	str	q21, [x20, #336]
	str	q21, [x20, #352]
	str	q21, [x20, #368]
	str	q21, [x20, #384]
	str	q21, [x20, #400]
	str	q21, [x20, #416]
	str	q21, [x20, #432]
	str	q21, [x20, #448]
	str	q21, [x20, #464]

	// Z3 ← 1
	str	q20, [x20, #640]
	str	q21, [x20, #656]
	str	q21, [x20, #672]
	str	q21, [x20, #688]
	str	q21, [x20, #704]
	str	q21, [x20, #720]
	str	q21, [x20, #736]
	str	q21, [x20, #752]
	str	q21, [x20, #768]
	str	q21, [x20, #784]

	mov	x5, #48
	mov	x6, #62
	mov	x15, x6	
	stp	xzr, xzr, [sp, #160]	
	mov	x3, x2
	
	// Montgomery ladder loop
.L1:
	add	x3, x3, x5	
	ldr	q30, [x3, #0]
	str	q30, [sp, #176]	
	mov	x3, x2
.L2:

	/* 
	 * Montgomery ladder step
	 *
	 * T1 ← X2 + Z2
	 * T2 ← X2 - Z2
	 * T3 ← X3 + Z3
	 * T4 ← X3 - Z3
	 * Z3 ← T2 · T3
	 * X3 ← T1 · T4
	 *
	 * bit ← n[i]
	 * select ← bit ⊕ prevbit
	 * prevbit ← bit
	 * CSelect(T1,T3,select): if (select == 1) {T1 = T3}
	 * CSelect(T2,T4,select): if (select == 1) {T2 = T4}
	 *
	 * T2 ← T2^2
	 * T1 ← T1^2
	 * T3 ← X3 + Z3
	 * Z3 ← X3 - Z3
	 * Z3 ← Z3^2
	 * X3 ← T3^2
	 * T3 ← T1 - T2
	 * T4 ← ((A + 2)/4) · T3
	 * T4 ← T4 + T2
	 * X2 ← T1 · T2
	 * Z2 ← T3 · T4
	 * Z3 ← Z3 · X1
	 *
	 */

	// X2
	ldr	q10, [x20, #160]
	ldr	q11, [x20, #176]
	ldr	q12, [x20, #192]
	ldr	q13, [x20, #208]
	ldr	q14, [x20, #224]
	ldr	q15, [x20, #240]
	ldr	q16, [x20, #256]
	ldr	q17, [x20, #272]
	ldr	q18, [x20, #288]
	ldr	q19, [x20, #304]	
	
	// Z2
	ldr	q0, [x20, #320]
	ldr	q1, [x20, #336]
	ldr	q2, [x20, #352]
	ldr	q3, [x20, #368]
	ldr	q4, [x20, #384]
	ldr	q5, [x20, #400]
	ldr	q6, [x20, #416]
	ldr	q7, [x20, #432]
	ldr	q8, [x20, #448]
	ldr	q9, [x20, #464]

	// T1 ← X2 + Z2	
	add	v20.2s, v0.2s, v10.2s
	add	v21.2s, v1.2s, v11.2s
	add	v22.2s, v2.2s, v12.2s
	add	v23.2s, v3.2s, v13.2s
	add	v24.2s, v4.2s, v14.2s
	add	v25.2s, v5.2s, v15.2s
	add	v26.2s, v6.2s, v16.2s
	add	v27.2s, v7.2s, v17.2s
	add	v28.2s, v8.2s, v18.2s
	add	v29.2s, v9.2s, v19.2s
	
	str	q20, [x20, #800]
	str	q21, [x20, #816]
	str	q22, [x20, #832]
	str	q23, [x20, #848]
	str	q24, [x20, #864]
	str	q25, [x20, #880]
	str	q26, [x20, #896]
	str	q27, [x20, #912]
	str	q28, [x20, #928]
	str	q29, [x20, #944]	

	// T2 ← X2 - Z2	
	mov	v30.d[0], x21
	add	v10.2s, v30.2s, v10.2s
	mov	v30.d[0], x22
	mov	v31.d[0], x23	
	add	v11.2s, v30.2s, v11.2s
	add	v12.2s, v31.2s, v12.2s
	add	v13.2s, v30.2s, v13.2s
	add	v14.2s, v31.2s, v14.2s
	add	v15.2s, v30.2s, v15.2s
	add	v16.2s, v31.2s, v16.2s
	add	v17.2s, v30.2s, v17.2s
	add	v18.2s, v31.2s, v18.2s
	add	v19.2s, v30.2s, v19.2s
	
	sub	v20.2s, v10.2s, v0.2s
	sub	v21.2s, v11.2s, v1.2s
	sub	v22.2s, v12.2s, v2.2s
	sub	v23.2s, v13.2s, v3.2s
	sub	v24.2s, v14.2s, v4.2s
	sub	v25.2s, v15.2s, v5.2s
	sub	v26.2s, v16.2s, v6.2s
	sub	v27.2s, v17.2s, v7.2s
	sub	v28.2s, v18.2s, v8.2s
	sub	v29.2s, v19.2s, v9.2s
	
	str	q20, [x20, #960]
	str	q21, [x20, #976]
	str	q22, [x20, #992]
	str	q23, [x20, #1008]
	str	q24, [x20, #1024]
	str	q25, [x20, #1040]
	str	q26, [x20, #1056]
	str	q27, [x20, #1072]
	str	q28, [x20, #1088]
	str	q29, [x20, #1104]
	
	// X3
	ldr	q10, [x20, #480]
	ldr	q11, [x20, #496]
	ldr	q12, [x20, #512]
	ldr	q13, [x20, #528]
	ldr	q14, [x20, #544]
	ldr	q15, [x20, #560]
	ldr	q16, [x20, #576]
	ldr	q17, [x20, #592]
	ldr	q18, [x20, #608]
	ldr	q19, [x20, #624]	
	
	// Z3
	ldr	q0, [x20, #640]
	ldr	q1, [x20, #656]
	ldr	q2, [x20, #672]
	ldr	q3, [x20, #688]
	ldr	q4, [x20, #704]
	ldr	q5, [x20, #720]
	ldr	q6, [x20, #736]
	ldr	q7, [x20, #752]
	ldr	q8, [x20, #768]
	ldr	q9, [x20, #784]

	// T3 ← X3 + Z3	
	add	v20.2s, v0.2s, v10.2s
	add	v21.2s, v1.2s, v11.2s
	add	v22.2s, v2.2s, v12.2s
	add	v23.2s, v3.2s, v13.2s
	add	v24.2s, v4.2s, v14.2s
	add	v25.2s, v5.2s, v15.2s
	add	v26.2s, v6.2s, v16.2s
	add	v27.2s, v7.2s, v17.2s
	add	v28.2s, v8.2s, v18.2s
	add	v29.2s, v9.2s, v19.2s
	
	str	q20, [x20, #1120]
	str	q21, [x20, #1136]
	str	q22, [x20, #1152]
	str	q23, [x20, #1168]
	str	q24, [x20, #1184]
	str	q25, [x20, #1200]
	str	q26, [x20, #1216]
	str	q27, [x20, #1232]
	str	q28, [x20, #1248]
	str	q29, [x20, #1264]	

	// T4 ← X3 - Z3	
	mov	v30.d[0], x21
	add	v10.2s, v30.2s, v10.2s
	mov	v30.d[0], x22
	mov	v31.d[0], x23	
	add	v11.2s, v30.2s, v11.2s
	add	v12.2s, v31.2s, v12.2s
	add	v13.2s, v30.2s, v13.2s
	add	v14.2s, v31.2s, v14.2s
	add	v15.2s, v30.2s, v15.2s
	add	v16.2s, v31.2s, v16.2s
	add	v17.2s, v30.2s, v17.2s
	add	v18.2s, v31.2s, v18.2s
	add	v19.2s, v30.2s, v19.2s	
	
	sub	v20.2s, v10.2s, v0.2s
	sub	v21.2s, v11.2s, v1.2s
	sub	v22.2s, v12.2s, v2.2s
	sub	v23.2s, v13.2s, v3.2s
	sub	v24.2s, v14.2s, v4.2s
	sub	v25.2s, v15.2s, v5.2s
	sub	v26.2s, v16.2s, v6.2s
	sub	v27.2s, v17.2s, v7.2s
	sub	v28.2s, v18.2s, v8.2s
	sub	v29.2s, v19.2s, v9.2s
	
	str	q20, [x20, #1280]
	str	q21, [x20, #1296]
	str	q22, [x20, #1312]
	str	q23, [x20, #1328]
	str	q24, [x20, #1344]
	str	q25, [x20, #1360]
	str	q26, [x20, #1376]
	str	q27, [x20, #1392]
	str	q28, [x20, #1408]
	str	q29, [x20, #1424]

	// X3 ← T1 · T4
	ldr	q10, [x20, #800]
	ldr	q11, [x20, #816]
	ldr	q12, [x20, #832]
	ldr	q13, [x20, #848]
	ldr	q14, [x20, #864]
	ldr	q15, [x20, #880]
	ldr	q16, [x20, #896]
	ldr	q17, [x20, #912]
	ldr	q18, [x20, #928]
	ldr	q19, [x20, #944]
		
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
        
	xtn	v10.2s, v0.2d
	xtn	v11.2s, v1.2d
	xtn	v12.2s, v2.2d
	xtn	v13.2s, v3.2d
	xtn	v14.2s, v4.2d
	xtn	v15.2s, v5.2d
	xtn	v16.2s, v6.2d
	xtn	v17.2s, v7.2d
	xtn	v18.2s, v8.2d
	xtn	v19.2s, v9.2d        
        
	str	q10, [x20, #480]
	str	q11, [x20, #496]
	str	q12, [x20, #512]
	str	q13, [x20, #528]
	str	q14, [x20, #544]
	str	q15, [x20, #560]
	str	q16, [x20, #576]
	str	q17, [x20, #592]
	str	q18, [x20, #608]
	str	q19, [x20, #624]

	// Z3 ← T2 · T3
	ldr	q10, [x20, #960]
	ldr	q11, [x20, #976]
	ldr	q12, [x20, #992]
	ldr	q13, [x20, #1008]
	ldr	q14, [x20, #1024]
	ldr	q15, [x20, #1040]
	ldr	q16, [x20, #1056]
	ldr	q17, [x20, #1072]
	ldr	q18, [x20, #1088]
	ldr	q19, [x20, #1104]
	
	ldr	q20, [x20, #1120]
	ldr	q21, [x20, #1136]
	ldr	q22, [x20, #1152]
	ldr	q23, [x20, #1168]
	ldr	q24, [x20, #1184]
	ldr	q25, [x20, #1200]
	ldr	q26, [x20, #1216]
	ldr	q27, [x20, #1232]
	ldr	q28, [x20, #1248]
	ldr	q29, [x20, #1264]

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
        
	xtn	v10.2s, v0.2d
	xtn	v11.2s, v1.2d
	xtn	v12.2s, v2.2d
	xtn	v13.2s, v3.2d
	xtn	v14.2s, v4.2d
	xtn	v15.2s, v5.2d
	xtn	v16.2s, v6.2d
	xtn	v17.2s, v7.2d
	xtn	v18.2s, v8.2d
	xtn	v19.2s, v9.2d
        
	str	q10, [x20, #640]
	str	q11, [x20, #656]
	str	q12, [x20, #672]
	str	q13, [x20, #688]
	str	q14, [x20, #704]
	str	q15, [x20, #720]
	str	q16, [x20, #736]
	str	q17, [x20, #752]
	str	q18, [x20, #768]
	str	q19, [x20, #784]
	
	// conditional select 
	ldp	x8, x9, [sp, #176]
	
	lsr	x8, x8, x15
	lsr	x9, x9, x15	
	
	mov	v31.d[0], x8
	mov	v31.d[1], x9
	
	xtn	v31.2s, v31.2d	
	
	dup	v30.2s, w4
	
	and	v29.16b, v31.16b, v30.16b
        
	ldr	q28, [sp, #160]
	eor	v31.16b, v29.16b, v28.16b
	str	q29, [sp, #160]	
	
	sub	x15, x15, #1
	
	dup	v30.2s, wzr
	sub	v30.2s, v30.2s, v31.2s
	
	// T1 = CSelect(T1,T3)
	ldr	q10, [x20, #800]
	ldr	q11, [x20, #816]
	ldr	q12, [x20, #832]
	ldr	q13, [x20, #848]
	ldr	q14, [x20, #864]
	ldr	q15, [x20, #880]
	ldr	q16, [x20, #896]
	ldr	q17, [x20, #912]
	ldr	q18, [x20, #928]
	ldr	q19, [x20, #944]
	
	ldr	q20, [x20, #1120]
	ldr	q21, [x20, #1136]
	ldr	q22, [x20, #1152]
	ldr	q23, [x20, #1168]
	ldr	q24, [x20, #1184]
	ldr	q25, [x20, #1200]
	ldr	q26, [x20, #1216]
	ldr	q27, [x20, #1232]
	ldr	q28, [x20, #1248]
	ldr	q29, [x20, #1264]
	
	eor	v0.16b, v10.16b, v20.16b
	eor	v1.16b, v11.16b, v21.16b
	eor	v2.16b, v12.16b, v22.16b
	eor	v3.16b, v13.16b, v23.16b
	eor	v4.16b, v14.16b, v24.16b
	eor	v5.16b, v15.16b, v25.16b
	eor	v6.16b, v16.16b, v26.16b
	eor	v7.16b, v17.16b, v27.16b
	eor	v8.16b, v18.16b, v28.16b
	eor	v9.16b, v19.16b, v29.16b
	
        and	v0.16b, v0.16b, v30.16b
        and	v1.16b, v1.16b, v30.16b
        and	v2.16b, v2.16b, v30.16b
        and	v3.16b, v3.16b, v30.16b
        and	v4.16b, v4.16b, v30.16b
        and	v5.16b, v5.16b, v30.16b
        and	v6.16b, v6.16b, v30.16b
        and	v7.16b, v7.16b, v30.16b
        and	v8.16b, v8.16b, v30.16b
        and	v9.16b, v9.16b, v30.16b
        
	eor	v0.16b, v0.16b, v10.16b
	eor	v1.16b, v1.16b, v11.16b
	eor	v2.16b, v2.16b, v12.16b
	eor	v3.16b, v3.16b, v13.16b
	eor	v4.16b, v4.16b, v14.16b
	eor	v5.16b, v5.16b, v15.16b
	eor	v6.16b, v6.16b, v16.16b
	eor	v7.16b, v7.16b, v17.16b
	eor	v8.16b, v8.16b, v18.16b
	eor	v9.16b, v9.16b, v19.16b
	
	str	q0, [x20, #800]
	str	q1, [x20, #816]
	str	q2, [x20, #832]
	str	q3, [x20, #848]
	str	q4, [x20, #864]
	str	q5, [x20, #880]
	str	q6, [x20, #896]
	str	q7, [x20, #912]
	str	q8, [x20, #928]
	str	q9, [x20, #944]

	// T2 = CSelect(T2,T4)
	ldr	q10, [x20, #960]
	ldr	q11, [x20, #976]
	ldr	q12, [x20, #992]
	ldr	q13, [x20, #1008]
	ldr	q14, [x20, #1024]
	ldr	q15, [x20, #1040]
	ldr	q16, [x20, #1056]
	ldr	q17, [x20, #1072]
	ldr	q18, [x20, #1088]
	ldr	q19, [x20, #1104]
	
	ldr	q20, [x20, #1280]
	ldr	q21, [x20, #1296]
	ldr	q22, [x20, #1312]
	ldr	q23, [x20, #1328]
	ldr	q24, [x20, #1344]
	ldr	q25, [x20, #1360]
	ldr	q26, [x20, #1376]
	ldr	q27, [x20, #1392]
	ldr	q28, [x20, #1408]
	ldr	q29, [x20, #1424]
	
	eor	v0.16b, v10.16b, v20.16b
	eor	v1.16b, v11.16b, v21.16b
	eor	v2.16b, v12.16b, v22.16b
	eor	v3.16b, v13.16b, v23.16b
	eor	v4.16b, v14.16b, v24.16b
	eor	v5.16b, v15.16b, v25.16b
	eor	v6.16b, v16.16b, v26.16b
	eor	v7.16b, v17.16b, v27.16b
	eor	v8.16b, v18.16b, v28.16b
	eor	v9.16b, v19.16b, v29.16b
	
        and	v0.16b, v0.16b, v30.16b
        and	v1.16b, v1.16b, v30.16b
        and	v2.16b, v2.16b, v30.16b
        and	v3.16b, v3.16b, v30.16b
        and	v4.16b, v4.16b, v30.16b
        and	v5.16b, v5.16b, v30.16b
        and	v6.16b, v6.16b, v30.16b
        and	v7.16b, v7.16b, v30.16b
        and	v8.16b, v8.16b, v30.16b
        and	v9.16b, v9.16b, v30.16b
        
	eor	v10.16b, v0.16b, v10.16b
	eor	v11.16b, v1.16b, v11.16b
	eor	v12.16b, v2.16b, v12.16b
	eor	v13.16b, v3.16b, v13.16b
	eor	v14.16b, v4.16b, v14.16b
	eor	v15.16b, v5.16b, v15.16b
	eor	v16.16b, v6.16b, v16.16b
	eor	v17.16b, v7.16b, v17.16b
	eor	v18.16b, v8.16b, v18.16b
	eor	v19.16b, v9.16b, v19.16b

	// T2 ← T2^2
        dup	v31.2s, w30	
        shl	v0.2d, v31.2d, #1
	
        mul	v20.2s, v16.2s, v31.2s
        mul	v21.2s, v18.2s, v31.2s
        mul	v22.2s, v15.2s, v0.2s
        mul	v23.2s, v17.2s, v0.2s
        mul	v24.2s, v19.2s, v0.2s
        
        shl	v25.2s, v10.2s, #1
        shl	v26.2s, v11.2s, #1
        shl	v27.2s, v12.2s, #1
        shl	v28.2s, v13.2s, #1
        shl	v29.2s, v14.2s, #1
        shl	 v7.2s, v15.2s, #1
        shl	 v8.2s, v16.2s, #1
        shl	 v9.2s, v17.2s, #1
      
        umull	v0.2d, v10.2s, v10.2s
        umlal	v0.2d, v26.2s, v24.2s
        umlal	v0.2d, v27.2s, v21.2s
        umlal	v0.2d, v28.2s, v23.2s
        umlal	v0.2d, v29.2s, v20.2s
        umlal	v0.2d, v22.2s, v15.2s        
        
        umull	v1.2d, v25.2s, v11.2s
        umlal	v1.2d, v24.2s, v12.2s
        umlal	v1.2d, v28.2s, v21.2s
        umlal	v1.2d, v23.2s, v14.2s
        umlal	v1.2d, v20.2s, v7.2s
        
        umull	v2.2d, v25.2s, v12.2s
        umlal	v2.2d, v26.2s, v11.2s
        umlal	v2.2d, v28.2s, v24.2s
        umlal	v2.2d, v29.2s, v21.2s
        umlal	v2.2d, v23.2s, v7.2s
        umlal	v2.2d, v20.2s, v16.2s

        umull	v3.2d, v25.2s, v13.2s
        umlal	v3.2d, v26.2s, v12.2s
        umlal	v3.2d, v24.2s, v14.2s
        umlal	v3.2d, v21.2s, v7.2s
        umlal	v3.2d, v23.2s, v16.2s
        
        umull	v4.2d, v25.2s, v14.2s
        umlal	v4.2d, v26.2s, v28.2s
        umlal	v4.2d, v12.2s, v12.2s
        umlal	v4.2d, v24.2s, v7.2s
        umlal	v4.2d, v8.2s, v21.2s
        umlal	v4.2d, v23.2s, v17.2s       

        umull	v5.2d, v25.2s, v15.2s
        umlal	v5.2d, v26.2s, v14.2s
        umlal	v5.2d, v27.2s, v13.2s
        umlal	v5.2d, v24.2s, v16.2s
        umlal	v5.2d, v21.2s, v9.2s

        umull	v6.2d, v25.2s, v16.2s        
        umlal	v6.2d, v26.2s, v7.2s
        umlal	v6.2d, v27.2s, v14.2s
        umlal	v6.2d, v28.2s, v13.2s
        umlal	v6.2d, v24.2s, v9.2s
        umlal	v6.2d, v21.2s, v18.2s
             
        umull	v8.2d, v25.2s, v18.2s
        umlal	v8.2d, v26.2s, v9.2s
        umlal	v8.2d, v27.2s, v16.2s
        umlal	v8.2d, v28.2s, v7.2s
        umlal	v8.2d, v14.2s, v14.2s
        umlal	v8.2d, v24.2s, v19.2s
        
        umull	v7.2d, v25.2s, v17.2s       
        umlal	v7.2d, v26.2s, v16.2s
        umlal	v7.2d, v27.2s, v15.2s
        umlal	v7.2d, v28.2s, v14.2s
        umlal	v7.2d, v24.2s, v18.2s        

        umull	v9.2d, v25.2s, v19.2s
        umlal	v9.2d, v26.2s, v18.2s
        umlal	v9.2d, v27.2s, v17.2s
        umlal	v9.2d, v28.2s, v16.2s
        umlal	v9.2d, v29.2s, v15.2s   

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
        
	xtn	v10.2s, v0.2d
	xtn	v11.2s, v1.2d
	xtn	v12.2s, v2.2d
	xtn	v13.2s, v3.2d
	xtn	v14.2s, v4.2d
	xtn	v15.2s, v5.2d
	xtn	v16.2s, v6.2d
	xtn	v17.2s, v7.2d
	xtn	v18.2s, v8.2d
	xtn	v19.2s, v9.2d        

	str	q10, [x20, #960]
	str	q11, [x20, #976]
	str	q12, [x20, #992]
	str	q13, [x20, #1008]
	str	q14, [x20, #1024]
	str	q15, [x20, #1040]
	str	q16, [x20, #1056]
	str	q17, [x20, #1072]
	str	q18, [x20, #1088]
	str	q19, [x20, #1104]

	// T1 ← T1^2
	ldr	q10, [x20, #800]
	ldr	q11, [x20, #816]
	ldr	q12, [x20, #832]
	ldr	q13, [x20, #848]
	ldr	q14, [x20, #864]
	ldr	q15, [x20, #880]
	ldr	q16, [x20, #896]
	ldr	q17, [x20, #912]
	ldr	q18, [x20, #928]
	ldr	q19, [x20, #944]	
	
        dup	v31.2s, w30	
        shl	v0.2d, v31.2d, #1
	
        mul	v20.2s, v16.2s, v31.2s
        mul	v21.2s, v18.2s, v31.2s
        mul	v22.2s, v15.2s, v0.2s
        mul	v23.2s, v17.2s, v0.2s
        mul	v24.2s, v19.2s, v0.2s
        
        shl	v25.2s, v10.2s, #1
        shl	v26.2s, v11.2s, #1
        shl	v27.2s, v12.2s, #1
        shl	v28.2s, v13.2s, #1
        shl	v29.2s, v14.2s, #1
        shl	 v7.2s, v15.2s, #1
        shl	 v8.2s, v16.2s, #1
        shl	 v9.2s, v17.2s, #1
      
        umull	v0.2d, v10.2s, v10.2s
        umlal	v0.2d, v26.2s, v24.2s
        umlal	v0.2d, v27.2s, v21.2s
        umlal	v0.2d, v28.2s, v23.2s
        umlal	v0.2d, v29.2s, v20.2s
        umlal	v0.2d, v22.2s, v15.2s        
        
        umull	v1.2d, v25.2s, v11.2s
        umlal	v1.2d, v24.2s, v12.2s
        umlal	v1.2d, v28.2s, v21.2s
        umlal	v1.2d, v23.2s, v14.2s
        umlal	v1.2d, v20.2s, v7.2s
        
        umull	v2.2d, v25.2s, v12.2s
        umlal	v2.2d, v26.2s, v11.2s
        umlal	v2.2d, v28.2s, v24.2s
        umlal	v2.2d, v29.2s, v21.2s
        umlal	v2.2d, v23.2s, v7.2s
        umlal	v2.2d, v20.2s, v16.2s

        umull	v3.2d, v25.2s, v13.2s
        umlal	v3.2d, v26.2s, v12.2s
        umlal	v3.2d, v24.2s, v14.2s
        umlal	v3.2d, v21.2s, v7.2s
        umlal	v3.2d, v23.2s, v16.2s
        
        umull	v4.2d, v25.2s, v14.2s
        umlal	v4.2d, v26.2s, v28.2s
        umlal	v4.2d, v12.2s, v12.2s
        umlal	v4.2d, v24.2s, v7.2s
        umlal	v4.2d, v8.2s, v21.2s
        umlal	v4.2d, v23.2s, v17.2s       

        umull	v5.2d, v25.2s, v15.2s
        umlal	v5.2d, v26.2s, v14.2s
        umlal	v5.2d, v27.2s, v13.2s
        umlal	v5.2d, v24.2s, v16.2s
        umlal	v5.2d, v21.2s, v9.2s

        umull	v6.2d, v25.2s, v16.2s        
        umlal	v6.2d, v26.2s, v7.2s
        umlal	v6.2d, v27.2s, v14.2s
        umlal	v6.2d, v28.2s, v13.2s
        umlal	v6.2d, v24.2s, v9.2s
        umlal	v6.2d, v21.2s, v18.2s
             
        umull	v8.2d, v25.2s, v18.2s
        umlal	v8.2d, v26.2s, v9.2s
        umlal	v8.2d, v27.2s, v16.2s
        umlal	v8.2d, v28.2s, v7.2s
        umlal	v8.2d, v14.2s, v14.2s
        umlal	v8.2d, v24.2s, v19.2s
        
        umull	v7.2d, v25.2s, v17.2s       
        umlal	v7.2d, v26.2s, v16.2s
        umlal	v7.2d, v27.2s, v15.2s
        umlal	v7.2d, v28.2s, v14.2s
        umlal	v7.2d, v24.2s, v18.2s        

        umull	v9.2d, v25.2s, v19.2s
        umlal	v9.2d, v26.2s, v18.2s
        umlal	v9.2d, v27.2s, v17.2s
        umlal	v9.2d, v28.2s, v16.2s
        umlal	v9.2d, v29.2s, v15.2s   

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
        
	xtn	v10.2s, v0.2d
	xtn	v11.2s, v1.2d
	xtn	v12.2s, v2.2d
	xtn	v13.2s, v3.2d
	xtn	v14.2s, v4.2d
	xtn	v15.2s, v5.2d
	xtn	v16.2s, v6.2d
	xtn	v17.2s, v7.2d
	xtn	v18.2s, v8.2d
	xtn	v19.2s, v9.2d        

	str	q10, [x20, #800]
	str	q11, [x20, #816]
	str	q12, [x20, #832]
	str	q13, [x20, #848]
	str	q14, [x20, #864]
	str	q15, [x20, #880]
	str	q16, [x20, #896]
	str	q17, [x20, #912]
	str	q18, [x20, #928]
	str	q19, [x20, #944]
	
	// X3
	ldr	q0, [x20, #480]
	ldr	q1, [x20, #496]
	ldr	q2, [x20, #512]
	ldr	q3, [x20, #528]
	ldr	q4, [x20, #544]
	ldr	q5, [x20, #560]
	ldr	q6, [x20, #576]
	ldr	q7, [x20, #592]
	ldr	q8, [x20, #608]
	ldr	q9, [x20, #624]	
	
	// Z3
	ldr	q10, [x20, #640]
	ldr	q11, [x20, #656]
	ldr	q12, [x20, #672]
	ldr	q13, [x20, #688]
	ldr	q14, [x20, #704]
	ldr	q15, [x20, #720]
	ldr	q16, [x20, #736]
	ldr	q17, [x20, #752]
	ldr	q18, [x20, #768]
	ldr	q19, [x20, #784]

	// T3 ← X3 + Z3	
	add	v20.2s, v0.2s, v10.2s
	add	v21.2s, v1.2s, v11.2s
	add	v22.2s, v2.2s, v12.2s
	add	v23.2s, v3.2s, v13.2s
	add	v24.2s, v4.2s, v14.2s
	add	v25.2s, v5.2s, v15.2s
	add	v26.2s, v6.2s, v16.2s
	add	v27.2s, v7.2s, v17.2s
	add	v28.2s, v8.2s, v18.2s
	add	v29.2s, v9.2s, v19.2s
	
	str	q20, [x20, #1120]
	str	q21, [x20, #1136]
	str	q22, [x20, #1152]
	str	q23, [x20, #1168]
	str	q24, [x20, #1184]
	str	q25, [x20, #1200]
	str	q26, [x20, #1216]
	str	q27, [x20, #1232]
	str	q28, [x20, #1248]
	str	q29, [x20, #1264]	

	// Z3 ← X3 - Z3	
	mov	v30.d[0], x21
	add	v0.2s, v30.2s, v0.2s
	mov	v30.d[0], x22
	mov	v31.d[0], x23	
	add	v1.2s, v30.2s, v1.2s
	add	v2.2s, v31.2s, v2.2s
	add	v3.2s, v30.2s, v3.2s
	add	v4.2s, v31.2s, v4.2s
	add	v5.2s, v30.2s, v5.2s
	add	v6.2s, v31.2s, v6.2s
	add	v7.2s, v30.2s, v7.2s
	add	v8.2s, v31.2s, v8.2s
	add	v9.2s, v30.2s, v9.2s	
	
	sub	v10.2s, v0.2s, v10.2s
	sub	v11.2s, v1.2s, v11.2s
	sub	v12.2s, v2.2s, v12.2s
	sub	v13.2s, v3.2s, v13.2s
	sub	v14.2s, v4.2s, v14.2s
	sub	v15.2s, v5.2s, v15.2s
	sub	v16.2s, v6.2s, v16.2s
	sub	v17.2s, v7.2s, v17.2s
	sub	v18.2s, v8.2s, v18.2s
	sub	v19.2s, v9.2s, v19.2s
	
	// Z3 ← Z3^2
        dup	v31.2s, w30	
        shl	v0.2d, v31.2d, #1
	
        mul	v20.2s, v16.2s, v31.2s
        mul	v21.2s, v18.2s, v31.2s
        mul	v22.2s, v15.2s, v0.2s
        mul	v23.2s, v17.2s, v0.2s
        mul	v24.2s, v19.2s, v0.2s
        
        shl	v25.2s, v10.2s, #1
        shl	v26.2s, v11.2s, #1
        shl	v27.2s, v12.2s, #1
        shl	v28.2s, v13.2s, #1
        shl	v29.2s, v14.2s, #1
        shl	 v7.2s, v15.2s, #1
        shl	 v8.2s, v16.2s, #1
        shl	 v9.2s, v17.2s, #1
      
        umull	v0.2d, v10.2s, v10.2s
        umlal	v0.2d, v26.2s, v24.2s
        umlal	v0.2d, v27.2s, v21.2s
        umlal	v0.2d, v28.2s, v23.2s
        umlal	v0.2d, v29.2s, v20.2s
        umlal	v0.2d, v22.2s, v15.2s        
        
        umull	v1.2d, v25.2s, v11.2s
        umlal	v1.2d, v24.2s, v12.2s
        umlal	v1.2d, v28.2s, v21.2s
        umlal	v1.2d, v23.2s, v14.2s
        umlal	v1.2d, v20.2s, v7.2s
        
        umull	v2.2d, v25.2s, v12.2s
        umlal	v2.2d, v26.2s, v11.2s
        umlal	v2.2d, v28.2s, v24.2s
        umlal	v2.2d, v29.2s, v21.2s
        umlal	v2.2d, v23.2s, v7.2s
        umlal	v2.2d, v20.2s, v16.2s

        umull	v3.2d, v25.2s, v13.2s
        umlal	v3.2d, v26.2s, v12.2s
        umlal	v3.2d, v24.2s, v14.2s
        umlal	v3.2d, v21.2s, v7.2s
        umlal	v3.2d, v23.2s, v16.2s
        
        umull	v4.2d, v25.2s, v14.2s
        umlal	v4.2d, v26.2s, v28.2s
        umlal	v4.2d, v12.2s, v12.2s
        umlal	v4.2d, v24.2s, v7.2s
        umlal	v4.2d, v8.2s, v21.2s
        umlal	v4.2d, v23.2s, v17.2s       

        umull	v5.2d, v25.2s, v15.2s
        umlal	v5.2d, v26.2s, v14.2s
        umlal	v5.2d, v27.2s, v13.2s
        umlal	v5.2d, v24.2s, v16.2s
        umlal	v5.2d, v21.2s, v9.2s

        umull	v6.2d, v25.2s, v16.2s        
        umlal	v6.2d, v26.2s, v7.2s
        umlal	v6.2d, v27.2s, v14.2s
        umlal	v6.2d, v28.2s, v13.2s
        umlal	v6.2d, v24.2s, v9.2s
        umlal	v6.2d, v21.2s, v18.2s
             
        umull	v8.2d, v25.2s, v18.2s
        umlal	v8.2d, v26.2s, v9.2s
        umlal	v8.2d, v27.2s, v16.2s
        umlal	v8.2d, v28.2s, v7.2s
        umlal	v8.2d, v14.2s, v14.2s
        umlal	v8.2d, v24.2s, v19.2s
        
        umull	v7.2d, v25.2s, v17.2s       
        umlal	v7.2d, v26.2s, v16.2s
        umlal	v7.2d, v27.2s, v15.2s
        umlal	v7.2d, v28.2s, v14.2s
        umlal	v7.2d, v24.2s, v18.2s        

        umull	v9.2d, v25.2s, v19.2s
        umlal	v9.2d, v26.2s, v18.2s
        umlal	v9.2d, v27.2s, v17.2s
        umlal	v9.2d, v28.2s, v16.2s
        umlal	v9.2d, v29.2s, v15.2s   

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
        
	xtn	v10.2s, v0.2d
	xtn	v11.2s, v1.2d
	xtn	v12.2s, v2.2d
	xtn	v13.2s, v3.2d
	xtn	v14.2s, v4.2d
	xtn	v15.2s, v5.2d
	xtn	v16.2s, v6.2d
	xtn	v17.2s, v7.2d
	xtn	v18.2s, v8.2d
	xtn	v19.2s, v9.2d        

	str	q10, [x20, #640]
	str	q11, [x20, #656]
	str	q12, [x20, #672]
	str	q13, [x20, #688]
	str	q14, [x20, #704]
	str	q15, [x20, #720]
	str	q16, [x20, #736]
	str	q17, [x20, #752]
	str	q18, [x20, #768]
	str	q19, [x20, #784]
	
	// X3 ← T3^2
	ldr	q10, [x20, #1120]
	ldr	q11, [x20, #1136]
	ldr	q12, [x20, #1152]
	ldr	q13, [x20, #1168]
	ldr	q14, [x20, #1184]
	ldr	q15, [x20, #1200]
	ldr	q16, [x20, #1216]
	ldr	q17, [x20, #1232]
	ldr	q18, [x20, #1248]
	ldr	q19, [x20, #1264]	
	
        dup	v31.2s, w30	
        shl	v0.2d, v31.2d, #1
	
        mul	v20.2s, v16.2s, v31.2s
        mul	v21.2s, v18.2s, v31.2s
        mul	v22.2s, v15.2s, v0.2s
        mul	v23.2s, v17.2s, v0.2s
        mul	v24.2s, v19.2s, v0.2s
        
        shl	v25.2s, v10.2s, #1
        shl	v26.2s, v11.2s, #1
        shl	v27.2s, v12.2s, #1
        shl	v28.2s, v13.2s, #1
        shl	v29.2s, v14.2s, #1
        shl	 v7.2s, v15.2s, #1
        shl	 v8.2s, v16.2s, #1
        shl	 v9.2s, v17.2s, #1
      
        umull	v0.2d, v10.2s, v10.2s
        umlal	v0.2d, v26.2s, v24.2s
        umlal	v0.2d, v27.2s, v21.2s
        umlal	v0.2d, v28.2s, v23.2s
        umlal	v0.2d, v29.2s, v20.2s
        umlal	v0.2d, v22.2s, v15.2s        
        
        umull	v1.2d, v25.2s, v11.2s
        umlal	v1.2d, v24.2s, v12.2s
        umlal	v1.2d, v28.2s, v21.2s
        umlal	v1.2d, v23.2s, v14.2s
        umlal	v1.2d, v20.2s, v7.2s
        
        umull	v2.2d, v25.2s, v12.2s
        umlal	v2.2d, v26.2s, v11.2s
        umlal	v2.2d, v28.2s, v24.2s
        umlal	v2.2d, v29.2s, v21.2s
        umlal	v2.2d, v23.2s, v7.2s
        umlal	v2.2d, v20.2s, v16.2s

        umull	v3.2d, v25.2s, v13.2s
        umlal	v3.2d, v26.2s, v12.2s
        umlal	v3.2d, v24.2s, v14.2s
        umlal	v3.2d, v21.2s, v7.2s
        umlal	v3.2d, v23.2s, v16.2s
        
        umull	v4.2d, v25.2s, v14.2s
        umlal	v4.2d, v26.2s, v28.2s
        umlal	v4.2d, v12.2s, v12.2s
        umlal	v4.2d, v24.2s, v7.2s
        umlal	v4.2d, v8.2s, v21.2s
        umlal	v4.2d, v23.2s, v17.2s       

        umull	v5.2d, v25.2s, v15.2s
        umlal	v5.2d, v26.2s, v14.2s
        umlal	v5.2d, v27.2s, v13.2s
        umlal	v5.2d, v24.2s, v16.2s
        umlal	v5.2d, v21.2s, v9.2s

        umull	v6.2d, v25.2s, v16.2s        
        umlal	v6.2d, v26.2s, v7.2s
        umlal	v6.2d, v27.2s, v14.2s
        umlal	v6.2d, v28.2s, v13.2s
        umlal	v6.2d, v24.2s, v9.2s
        umlal	v6.2d, v21.2s, v18.2s
             
        umull	v8.2d, v25.2s, v18.2s
        umlal	v8.2d, v26.2s, v9.2s
        umlal	v8.2d, v27.2s, v16.2s
        umlal	v8.2d, v28.2s, v7.2s
        umlal	v8.2d, v14.2s, v14.2s
        umlal	v8.2d, v24.2s, v19.2s
        
        umull	v7.2d, v25.2s, v17.2s       
        umlal	v7.2d, v26.2s, v16.2s
        umlal	v7.2d, v27.2s, v15.2s
        umlal	v7.2d, v28.2s, v14.2s
        umlal	v7.2d, v24.2s, v18.2s        

        umull	v9.2d, v25.2s, v19.2s
        umlal	v9.2d, v26.2s, v18.2s
        umlal	v9.2d, v27.2s, v17.2s
        umlal	v9.2d, v28.2s, v16.2s
        umlal	v9.2d, v29.2s, v15.2s   

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
        
	xtn	v10.2s, v0.2d
	xtn	v11.2s, v1.2d
	xtn	v12.2s, v2.2d
	xtn	v13.2s, v3.2d
	xtn	v14.2s, v4.2d
	xtn	v15.2s, v5.2d
	xtn	v16.2s, v6.2d
	xtn	v17.2s, v7.2d
	xtn	v18.2s, v8.2d
	xtn	v19.2s, v9.2d        

	str	q10, [x20, #480]
	str	q11, [x20, #496]
	str	q12, [x20, #512]
	str	q13, [x20, #528]
	str	q14, [x20, #544]
	str	q15, [x20, #560]
	str	q16, [x20, #576]
	str	q17, [x20, #592]
	str	q18, [x20, #608]
	str	q19, [x20, #624]
		
	// T1
	ldr	q10, [x20, #800]
	ldr	q11, [x20, #816]
	ldr	q12, [x20, #832]
	ldr	q13, [x20, #848]
	ldr	q14, [x20, #864]
	ldr	q15, [x20, #880]
	ldr	q16, [x20, #896]
	ldr	q17, [x20, #912]
	ldr	q18, [x20, #928]
	ldr	q19, [x20, #944]	
	
	// T2
	ldr	q0, [x20, #960]
	ldr	q1, [x20, #976]
	ldr	q2, [x20, #992]
	ldr	q3, [x20, #1008]
	ldr	q4, [x20, #1024]
	ldr	q5, [x20, #1040]
	ldr	q6, [x20, #1056]
	ldr	q7, [x20, #1072]
	ldr	q8, [x20, #1088]
	ldr	q9, [x20, #1104]	

	// T3 ← T1 - T2
	mov	v30.d[0], x21
	add	v20.2s, v30.2s, v10.2s
	mov	v30.d[0], x22
	mov	v31.d[0], x23	
	add	v21.2s, v30.2s, v11.2s
	add	v22.2s, v31.2s, v12.2s
	add	v23.2s, v30.2s, v13.2s
	add	v24.2s, v31.2s, v14.2s
	add	v25.2s, v30.2s, v15.2s
	add	v26.2s, v31.2s, v16.2s
	add	v27.2s, v30.2s, v17.2s
	add	v28.2s, v31.2s, v18.2s
	add	v29.2s, v30.2s, v19.2s	
	
	sub	v10.2s, v20.2s, v0.2s
	sub	v11.2s, v21.2s, v1.2s
	sub	v12.2s, v22.2s, v2.2s
	sub	v13.2s, v23.2s, v3.2s
	sub	v14.2s, v24.2s, v4.2s
	sub	v15.2s, v25.2s, v5.2s
	sub	v16.2s, v26.2s, v6.2s
	sub	v17.2s, v27.2s, v7.2s
	sub	v18.2s, v28.2s, v8.2s
	sub	v19.2s, v29.2s, v9.2s
	
	str	q10, [x20, #1120]
	str	q11, [x20, #1136]
	str	q12, [x20, #1152]
	str	q13, [x20, #1168]
	str	q14, [x20, #1184]
	str	q15, [x20, #1200]
	str	q16, [x20, #1216]
	str	q17, [x20, #1232]
	str	q18, [x20, #1248]
	str	q19, [x20, #1264]
	
	uxtl	v0.2d, v0.2s
	uxtl	v1.2d, v1.2s
	uxtl	v2.2d, v2.2s
	uxtl	v3.2d, v3.2s
	uxtl	v4.2d, v4.2s
	uxtl	v5.2d, v5.2s
	uxtl	v6.2d, v6.2s
	uxtl	v7.2d, v7.2s
	uxtl	v8.2d, v8.2s
	uxtl	v9.2d, v9.2s	
	
	// T4 ← ((A + 2)/4) · T3 + T2
	mov	v31.d[0], x12
	
        umull	v20.2d, v10.2s, v31.2s
        add	v0.2d, v0.2d, v20.2d        
        umull	v21.2d, v11.2s, v31.2s
        add	v1.2d, v1.2d, v21.2d        
        umull	v22.2d, v12.2s, v31.2s
        add	v2.2d, v2.2d, v22.2d        
        umull	v23.2d, v13.2s, v31.2s
        add	v3.2d, v3.2d, v23.2d        
        umull	v24.2d, v14.2s, v31.2s
        add	v4.2d, v4.2d, v24.2d        
        umull	v25.2d, v15.2s, v31.2s
        add	v5.2d, v5.2d, v25.2d        
        umull	v26.2d, v16.2s, v31.2s
        add	v6.2d, v6.2d, v26.2d        
        umull	v27.2d, v17.2s, v31.2s
        add	v7.2d, v7.2d, v27.2d        
        umull	v28.2d, v18.2s, v31.2s
        add	v8.2d, v8.2d, v28.2d        
        umull	v29.2d, v19.2s, v31.2s 
        add	v9.2d, v9.2d, v29.2d       
        
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
        
	xtn	v20.2s, v0.2d
	xtn	v21.2s, v1.2d
	xtn	v22.2s, v2.2d
	xtn	v23.2s, v3.2d
	xtn	v24.2s, v4.2d
	xtn	v25.2s, v5.2d
	xtn	v26.2s, v6.2d
	xtn	v27.2s, v7.2d
	xtn	v28.2s, v8.2d
	xtn	v29.2s, v9.2d

	// Z2 ← T3 · T4
	ldr	q10, [x20, #1120]
	ldr	q11, [x20, #1136]
	ldr	q12, [x20, #1152]
	ldr	q13, [x20, #1168]
	ldr	q14, [x20, #1184]
	ldr	q15, [x20, #1200]
	ldr	q16, [x20, #1216]
	ldr	q17, [x20, #1232]
	ldr	q18, [x20, #1248]
	ldr	q19, [x20, #1264]

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
        
	xtn	v10.2s, v0.2d
	xtn	v11.2s, v1.2d
	xtn	v12.2s, v2.2d
	xtn	v13.2s, v3.2d
	xtn	v14.2s, v4.2d
	xtn	v15.2s, v5.2d
	xtn	v16.2s, v6.2d
	xtn	v17.2s, v7.2d
	xtn	v18.2s, v8.2d
	xtn	v19.2s, v9.2d        
        
	str	q10, [x20, #320]
	str	q11, [x20, #336]
	str	q12, [x20, #352]
	str	q13, [x20, #368]
	str	q14, [x20, #384]
	str	q15, [x20, #400]
	str	q16, [x20, #416]
	str	q17, [x20, #432]
	str	q18, [x20, #448]
	str	q19, [x20, #464]

	// X2 ← T1 · T2
	ldr	q10, [x20, #800]
	ldr	q11, [x20, #816]
	ldr	q12, [x20, #832]
	ldr	q13, [x20, #848]
	ldr	q14, [x20, #864]
	ldr	q15, [x20, #880]
	ldr	q16, [x20, #896]
	ldr	q17, [x20, #912]
	ldr	q18, [x20, #928]
	ldr	q19, [x20, #944]
	
	ldr	q20, [x20, #960]
	ldr	q21, [x20, #976]
	ldr	q22, [x20, #992]
	ldr	q23, [x20, #1008]
	ldr	q24, [x20, #1024]
	ldr	q25, [x20, #1040]
	ldr	q26, [x20, #1056]
	ldr	q27, [x20, #1072]
	ldr	q28, [x20, #1088]
	ldr	q29, [x20, #1104]	

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
        
	xtn	v10.2s, v0.2d
	xtn	v11.2s, v1.2d
	xtn	v12.2s, v2.2d
	xtn	v13.2s, v3.2d
	xtn	v14.2s, v4.2d
	xtn	v15.2s, v5.2d
	xtn	v16.2s, v6.2d
	xtn	v17.2s, v7.2d
	xtn	v18.2s, v8.2d
	xtn	v19.2s, v9.2d        
        
	str	q10, [x20, #160]
	str	q11, [x20, #176]
	str	q12, [x20, #192]
	str	q13, [x20, #208]
	str	q14, [x20, #224]
	str	q15, [x20, #240]
	str	q16, [x20, #256]
	str	q17, [x20, #272]
	str	q18, [x20, #288]
	str	q19, [x20, #304]

	// Z3 ← Z3 · X1	
	ldr	q10, [x20, #640]
	ldr	q11, [x20, #656]
	ldr	q12, [x20, #672]
	ldr	q13, [x20, #688]
	ldr	q14, [x20, #704]
	ldr	q15, [x20, #720]
	ldr	q16, [x20, #736]
	ldr	q17, [x20, #752]
	ldr	q18, [x20, #768]
	ldr	q19, [x20, #784]
	
	ldr	q20, [x20, #0]
	ldr	q21, [x20, #16]
	ldr	q22, [x20, #32]
	ldr	q23, [x20, #48]
	ldr	q24, [x20, #64]
	ldr	q25, [x20, #80]
	ldr	q26, [x20, #96]
	ldr	q27, [x20, #112]
	ldr	q28, [x20, #128]
	ldr	q29, [x20, #144]	

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
        
	xtn	v10.2s, v0.2d
	xtn	v11.2s, v1.2d
	xtn	v12.2s, v2.2d
	xtn	v13.2s, v3.2d
	xtn	v14.2s, v4.2d
	xtn	v15.2s, v5.2d
	xtn	v16.2s, v6.2d
	xtn	v17.2s, v7.2d
	xtn	v18.2s, v8.2d
	xtn	v19.2s, v9.2d        
        
	str	q10, [x20, #640]
	str	q11, [x20, #656]
	str	q12, [x20, #672]
	str	q13, [x20, #688]
	str	q14, [x20, #704]
	str	q15, [x20, #720]
	str	q16, [x20, #736]
	str	q17, [x20, #752]
	str	q18, [x20, #768]
	str	q19, [x20, #784]

	sub 	x6, x6, #1
	cmp     x6, #0
	bge     .L2
	
	mov     x6, #63
	sub 	x5, x5, #16
	cmp     x5, #0
	bge     .L1
	
	// reduce X2
	ldr	q10, [x20, #160]
	ldr	q11, [x20, #176]
	ldr	q12, [x20, #192]
	ldr	q13, [x20, #208]
	ldr	q14, [x20, #224]
	ldr	q15, [x20, #240]
	ldr	q16, [x20, #256]
	ldr	q17, [x20, #272]
	ldr	q18, [x20, #288]
	ldr	q19, [x20, #304]
	
	uxtl	v0.2d, v10.2s
	uxtl	v1.2d, v11.2s
	uxtl	v2.2d, v12.2s
	uxtl	v3.2d, v13.2s
	uxtl	v4.2d, v14.2s
	uxtl	v5.2d, v15.2s
	uxtl	v6.2d, v16.2s
	uxtl	v7.2d, v17.2s
	uxtl	v8.2d, v18.2s
	uxtl	v9.2d, v19.2s	
       
        usra	v1.2d, v0.2d, #26
        and	v0.16b, v0.16b, v30.16b
        
        usra	v2.2d, v1.2d, #25
        and	v1.16b, v1.16b, v25.16b
        
        usra	v3.2d, v2.2d, #26
        and	v2.16b, v2.16b, v30.16b        
        
        usra	v4.2d, v3.2d, #25
        and	v3.16b, v3.16b, v25.16b
        
        usra	v5.2d, v4.2d, #26
        and	v4.16b, v4.16b, v30.16b
        
        usra	v6.2d, v5.2d, #25
        and	v5.16b, v5.16b, v25.16b        

        usra	v7.2d, v6.2d, #26
        and	v6.16b, v6.16b, v30.16b
        
        usra	v8.2d, v7.2d, #25
        and	v7.16b, v7.16b, v25.16b
        
        usra	v9.2d, v8.2d, #26
        and	v8.16b, v8.16b, v30.16b
               
        bic	v10.16b, v9.16b, v25.16b
        usra	v0.2d, v10.2d, #25        
        usra	v0.2d, v10.2d, #24
        usra	v0.2d, v10.2d, #21                
        and	v9.16b, v9.16b, v25.16b
                
        usra	v1.2d, v0.2d, #26
        and	v0.16b, v0.16b, v30.16b

	// store X2
	str	q0, [x0, #0]
	str	q1, [x0, #16]
	str	q2, [x0, #32]
	str	q3, [x0, #48]
	str	q4, [x0, #64]
	str	q5, [x0, #80]
	str	q6, [x0, #96]
	str	q7, [x0, #112]
	str	q8, [x0, #128]
	str	q9, [x0, #144]	

	// reduce Z2
	ldr	q10, [x20, #320]
	ldr	q11, [x20, #336]
	ldr	q12, [x20, #352]
	ldr	q13, [x20, #368]
	ldr	q14, [x20, #384]
	ldr	q15, [x20, #400]
	ldr	q16, [x20, #416]
	ldr	q17, [x20, #432]
	ldr	q18, [x20, #448]
	ldr	q19, [x20, #464]

	uxtl	v0.2d, v10.2s
	uxtl	v1.2d, v11.2s
	uxtl	v2.2d, v12.2s
	uxtl	v3.2d, v13.2s
	uxtl	v4.2d, v14.2s
	uxtl	v5.2d, v15.2s
	uxtl	v6.2d, v16.2s
	uxtl	v7.2d, v17.2s
	uxtl	v8.2d, v18.2s
	uxtl	v9.2d, v19.2s	
	
        usra	v1.2d, v0.2d, #26
        and	v0.16b, v0.16b, v30.16b
        
        usra	v2.2d, v1.2d, #25
        and	v1.16b, v1.16b, v25.16b
        
        usra	v3.2d, v2.2d, #26
        and	v2.16b, v2.16b, v30.16b        
        
        usra	v4.2d, v3.2d, #25
        and	v3.16b, v3.16b, v25.16b
        
        usra	v5.2d, v4.2d, #26
        and	v4.16b, v4.16b, v30.16b
        
        usra	v6.2d, v5.2d, #25
        and	v5.16b, v5.16b, v25.16b        

        usra	v7.2d, v6.2d, #26
        and	v6.16b, v6.16b, v30.16b
        
        usra	v8.2d, v7.2d, #25
        and	v7.16b, v7.16b, v25.16b
        
        usra	v9.2d, v8.2d, #26
        and	v8.16b, v8.16b, v30.16b
               
        bic	v10.16b, v9.16b, v25.16b
        usra	v0.2d, v10.2d, #25        
        usra	v0.2d, v10.2d, #24
        usra	v0.2d, v10.2d, #21                
        and	v9.16b, v9.16b, v25.16b
                
        usra	v1.2d, v0.2d, #26
        and	v0.16b, v0.16b, v30.16b

	// store Z2
	str	q0, [x0, #160]
	str	q1, [x0, #176]
	str	q2, [x0, #192]
	str	q3, [x0, #208]
	str	q4, [x0, #224]
	str	q5, [x0, #240]
	str	q6, [x0, #256]
	str	q7, [x0, #272]
	str	q8, [x0, #288]
	str	q9, [x0, #304]
	
	ldp	d14, d15, [sp, #144]
	ldp	d12, d13, [sp, #128]
	ldp	d10, d11, [sp, #112]
	ldp	d8,  d9,  [sp, #96]
	ldp	x29, x30, [sp, #80]
	ldp	x27, x28, [sp, #64]	
	ldp	x25, x26, [sp, #48]	
	ldp	x23, x24, [sp, #32]
	ldp	x21, x22, [sp, #16]
	ldp	x19, x20, [sp, #0]	
	add	sp, sp, #1632

	ret
.section	.note.GNU-stack,"",@progbits
