/**************************************************************************//**
 * @file     main.c
 * @version  V1.00
 * @brief    Secure sample code for Collaborative Secure Software Development
 *
 * @note
 * Copyright (C) 2018 Nuvoton Technology Corp. All rights reserved.
 ******************************************************************************/

#include <arm_cmse.h>
#include <stdio.h>
#include "NuMicro.h"                      /* Device header */
#include "partition_M2351.h"

#include "libiota.h"
#include "helper.h"
#include "iota_certs.h"
#include "ns_certs.h"

#include "aes.h"
#include "sha256.h"
#include "ssl.h"
#include "rsa.h"
#include "error.h"
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>

#define NEXT_BOOT_BASE  0x10040000
#define JUMP_HERE       0xe7fee7ff      /* Instruction Code of "B ." */
#define IS_USE_RS485NMM     0    /* 1:Select NMM_Mode , 0:Select AAD_Mode */
#define MATCH_ADDRSS1       0xC0

void UART0_Init(void)
{
    /*---------------------------------------------------------------------------------------------------------*/
    /* Init UART                                                                                               */
    /*---------------------------------------------------------------------------------------------------------*/
    /* Reset UART0 */
    SYS_ResetModule(UART0_RST);

    /* Configure UART0 and set UART0 baud rate */
    UART_Open(UART0, 115200);
}

void UART1_Init(void)
{
    /*---------------------------------------------------------------------------------------------------------*/
    /* Init UART                                                                                               */
    /*---------------------------------------------------------------------------------------------------------*/
    /* Reset UART1 */
    SYS_ResetModule(UART1_RST);

    /* Configure UART1 and set UART1 Baudrate */
    UART_Open(UART1, 115200);
}

/* typedef for NonSecure callback functions */
typedef __NONSECURE_CALL int32_t (*NonSecure_funcptr)(uint32_t);

__NONSECURE_ENTRY
int32_t Secure_PA11_LED_On(uint32_t num);
__NONSECURE_ENTRY
int32_t Secure_PA11_LED_Off(uint32_t num);
__NONSECURE_ENTRY
uint32_t GetSystemCoreClock(void);
__NONSECURE_ENTRY
void UART1_IRQHandler(void);
	__NONSECURE_ENTRY
void RS485_HANDLE(void);
__NONSECURE_ENTRY
void RS485_9bitModeSlave(void);
__NONSECURE_ENTRY
uint8_t* Get_Request_Buffer(void);
__NONSECURE_ENTRY
uint32_t Get_Request_Buffer_Len(void);
__NONSECURE_ENTRY
void UARTTx (unsigned char* req_ser, int req_ser_ln);
__NONSECURE_ENTRY
void UARTRx(void);
__NONSECURE_ENTRY
iota_ret call_iota(unsigned char* req_ser, const int req_ser_len, unsigned char* out_ser, const int max_out);

iota_ret hash_app_text(uint8_t *arg, uint32_t arg_len, uint8_t **meas, uint32_t *meas_len);
void measure_app_text(unsigned char sha256[32]);
void SYS_Init(void);
void DEBUG_PORT_Init(void);
void Nonsecure_Init(void);
void UART0_Init(void);
void UART1_Init(void);
int32_t LED_On(void);
int32_t LED_Off(void);
void SysTick_Handler(void);
void print_iota_error(iota_ret ret);
extern char GetChar(void);

uint8_t req_buf[4096];
uint32_t req_buf_len = 0;
uint32_t tx_len = 5;
int counter = 0;
int buffer_size = 3000;

iota_meas_func meas_funcs[] = {
    {
        .type = 0,
        .name = "",
        .func = hash_app_text,
        .free_func = NULL
    }
};

/*----------------------------------------------------------------------------
  Secure functions exported to NonSecure application
  Must place in Non-secure Callable
 *----------------------------------------------------------------------------*/
__NONSECURE_ENTRY
int32_t Secure_PA11_LED_On(uint32_t num)
{
    (void)num;
    //printf("Secure PA11 LED On call by secure\n");
    PA11 = 0;
    return 0;
}

__NONSECURE_ENTRY
int32_t Secure_PA11_LED_Off(uint32_t num)
{
    (void)num;
    //printf("Secure PA11 LED Off call by secure\n");
    PA11 = 1;
    return 1;
}

__NONSECURE_ENTRY
uint32_t GetSystemCoreClock(void)
{
    //printf("System core clock = %d.\n", SystemCoreClock);
    return SystemCoreClock;
}

/*---------------------------------------------------------------------------------------------------------*/
/* ISR to handle UART Channel 1 interrupt event                                                            */
/*---------------------------------------------------------------------------------------------------------*/
__NONSECURE_ENTRY
void UART1_IRQHandler(void)
{
    uint8_t u8InChar;
	
	  /* Rx Ready or Time-out INT */
    if(UART_GET_INT_FLAG(UART1, UART_INTSTS_RDAINT_Msk | UART_INTSTS_RXTOINT_Msk))
    {
        /* Read data until RX FIFO is empty */
      while(UART_GET_RX_EMPTY(UART1) == 0)
        {
            u8InChar = (uint8_t)UART_READ(UART1);	
						req_buf[counter++] = u8InChar;
				}
    }
		
		if(UART1->FIFOSTS & (UART_FIFOSTS_BIF_Msk | UART_FIFOSTS_FEF_Msk | UART_FIFOSTS_PEF_Msk | UART_FIFOSTS_RXOVIF_Msk))
    {
        UART1->FIFOSTS = (UART_FIFOSTS_BIF_Msk | UART_FIFOSTS_FEF_Msk | UART_FIFOSTS_PEF_Msk | UART_FIFOSTS_RXOVIF_Msk);
    }
}


__NONSECURE_ENTRY
void UARTTx (unsigned char* req_ser, int req_ser_ln)
{
    /* Enable RTS and CTS autoflow control */
    UART_EnableFlowCtrl(UART1);

    /* Send 1k bytes data */
    for(int u32Idx = 0; u32Idx < req_ser_ln; u32Idx++)
    {
        /* Send 1 byte data */
        UART_WRITE(UART1, req_ser[u32Idx]);
			  //printf("%u", req_ser[u32Idx]);

        /* Wait if Tx FIFO is full */
        while(UART_IS_TX_FULL(UART1));
    }
    //printf("\n Transmit Done\n");
}

__NONSECURE_ENTRY
void UARTRx(void)
{
    uint32_t u32Idx;
	  int flag = 1;

    /* Enable RTS and CTS autoflow control */
    UART_EnableFlowCtrl(UART1);

    /* Set RTS Trigger Level as 8 bytes */
    UART1->FIFO = (UART1->FIFO & (~UART_FIFO_RTSTRGLV_Msk)) | UART_FIFO_RTSTRGLV_8BYTES;

    /* Set RX Trigger Level as 8 bytes */
    UART1->FIFO = (UART1->FIFO & (~UART_FIFO_RFITL_Msk)) | UART_FIFO_RFITL_8BYTES;

    /* Set Timeout time 0x3E bit-time and time-out counter enable */
    UART_SetTimeoutCnt(UART1, 0x3E);

    /* Enable RDA and RTO Interrupt */
    UART_EnableInt(UART1, (UART_INTEN_RDAIEN_Msk | UART_INTEN_RLSIEN_Msk | UART_INTEN_RXTOIEN_Msk));

    /* Wait for receive all bytes data */
    while(counter < buffer_size)
		{
			if (counter != 0 && counter < 1000 && flag){
					uint32_t *p = req_buf;
					*p++;
					uint32_t size = *p++;
					buffer_size = size;
				  flag = 0;
					//printf("%d", buffer_size);
			}
		}
		
		/*for(u32Idx = 0; u32Idx < counter; u32Idx++)
    {
        printf("%d", req_buf[u32Idx]);			 		
		}*/
		
		req_buf_len = counter;

    /* Disable RDA and RTO Interrupt */
    UART_DisableInt(UART1, (UART_INTEN_RDAIEN_Msk | UART_INTEN_RLSIEN_Msk | UART_INTEN_RXTOIEN_Msk));
}

__NONSECURE_ENTRY
uint8_t* Get_Request_Buffer(void)
{
	 return req_buf;	
}
__NONSECURE_ENTRY
uint32_t Get_Request_Buffer_Len(void)
{
	 return req_buf_len;
}

__NONSECURE_ENTRY
iota_ret call_iota(unsigned char* req_ser, const int req_ser_len, unsigned char* out_ser, const int max_out){
  	iota_ret ret;
    iota_msg *req, *resp, *reqtest;
    size_t num_funcs;
    size_t expected_funcs = 0;
    size_t i;
    size_t expected_len;
		unsigned char* resp_ser;
		int resp_ser_len;		
		iota_meas_func *meas_func = meas_funcs;
	  iota iota_inst_req;
	  iota iota_inst_resp;
	
	  //IOTA_SIGNED_FLAG | IOTA_ENCRYPTED_FLAG
	
	  ret = iota_init(&iota_inst_req, meas_funcs, IOTA_SIGNED_FLAG | IOTA_ENCRYPTED_FLAG, (uint8_t*)tz_pubcert_pem, tz_pubcert_pem_sz);
			if (ret != IOTA_OK) {
				printf("\nS_Measurer: Failed to Initialize IoTA...\r\n");
				return ret;
		}	

		printf("\nS_Measurer: IoTA Instance Initialized...\r\n");
		
		req = malloc(sizeof(iota_msg));
				
		if (req == NULL) { printf("\nS_Measurer: Malloc Failed on Allocating Request from NS...\r\n"); return IOTA_ERR_MALLOC_FAIL;}
		
		printf("\nS_Measurer: Starting Deserialization of IoTA Request...\r\n");
		
		ret = iota_deserialize(&iota_inst_req, req_ser, req_ser_len, req);
		if (ret != IOTA_OK) {
				printf("\nS_Measurer: Deserialization of NS Request Failed...\r\n");
				return ret;
		}	
		
		ret = iota_init(&iota_inst_resp, meas_funcs, IOTA_SIGNED_FLAG | IOTA_ENCRYPTED_FLAG, (uint8_t*)ns_pubcert_pem, ns_pubcert_pem_sz);
			if (ret != IOTA_OK) {
				printf("\nS_Measurer: Failed to Initialize IoTA...\r\n");
				return ret;
		}	
		
		printf("\nS_Measurer: Request Received from NS World Deserialized...\r\n");

		if ((ret = iota_do(&iota_inst_resp, req, &resp)) != IOTA_OK) {
			printf("\nS_Measurer: Error While Generating Response...\r\n");
        print_iota_error(ret);
        return ret;
    }
		
		printf("\nS_Measurer: IoTA Response Generated with Measurement...\r\n");
		
		printf("\nS_Measurer: Starting Serialization of IoTA Response...\r\n");
				
		ret = iota_serialize(&iota_inst_resp, resp, &resp_ser, (uint32_t*)&resp_ser_len);
		
		if (resp_ser_len > max_out) {
			return IOTA_ERR_UNKNOWN;
		}
		
		free(req);
	  free(req_ser);
		
		printf("\nS_Measurer: IoTA Response Serialized...\r\n");
		
		iota_msg_deinit(&resp);
		memcpy(out_ser, resp_ser, resp_ser_len);
		
		printf("\nS_Measurer: Sending Serialized Response to NS World...\r\n");

		return IOTA_OK;
}

void Nonsecure_Init(void)
{
    NonSecure_funcptr fp;

    /* SCB_NS.VTOR points to the Non-secure vector table base address. */
    SCB_NS->VTOR = NEXT_BOOT_BASE;

    /* 1st Entry in the vector table is the Non-secure Main Stack Pointer. */
    __TZ_set_MSP_NS(*((uint32_t *)SCB_NS->VTOR)); /* Set up MSP in Non-secure code */

    /* 2nd entry contains the address of the Reset_Handler (CMSIS-CORE) function */
    fp = ((NonSecure_funcptr)(*(((uint32_t *)SCB_NS->VTOR) + 1)));

    /* Clear the LSB of the function address to indicate the function-call
       will cause a state switch from Secure to Non-secure */
    fp = cmse_nsfptr_create(fp);

    /* Check if the Reset_Handler address is in Non-secure space */
    if(cmse_is_nsfptr(fp) && (((uint32_t)fp & 0xf0000000) == 0x10000000))
    {
			  printf("\nS_Measurer: Calling Non-secure Code...\n");
        fp(0); /* Non-secure function call */
    }
    else
    {
        /* Something went wrong */
			printf("\nS_Measurer: No code in non-secure region!\n");
			printf("\nS_Measurer: CPU will halted at non-secure state\n");

        /* Set nonsecure MSP in nonsecure region */
        __TZ_set_MSP_NS(NON_SECURE_SRAM_BASE + 512);

        /* Try to halted in non-secure state (SRAM) */
        M32(NON_SECURE_SRAM_BASE) = JUMP_HERE;
        fp = (NonSecure_funcptr)(NON_SECURE_SRAM_BASE + 1);
        fp(0);

        while(1);
    }
}

void SYS_Init(void)
{
	 /* Set PF multi-function pins for XT1_OUT(PF.2) and XT1_IN(PF.3) */
    SYS->GPF_MFPL = (SYS->GPF_MFPL & (~SYS_GPF_MFPL_PF2MFP_Msk)) | SYS_GPF_MFPL_PF2MFP_XT1_OUT;
    SYS->GPF_MFPL = (SYS->GPF_MFPL & (~SYS_GPF_MFPL_PF3MFP_Msk)) | SYS_GPF_MFPL_PF3MFP_XT1_IN;

    /*---------------------------------------------------------------------------------------------------------*/
    /* Init System Clock                                                                                       */
    /*---------------------------------------------------------------------------------------------------------*/

    /* Enable HIRC clock */
    CLK_EnableXtalRC(CLK_PWRCTL_HIRCEN_Msk);

    /* Wait for HIRC clock ready */
    CLK_WaitClockReady(CLK_STATUS_HIRCSTB_Msk);

    /* Select HCLK clock source as HIRC and HCLK clock divider as 1 */
    CLK_SetHCLK(CLK_CLKSEL0_HCLKSEL_HIRC, CLK_CLKDIV0_HCLK(1));

    /* Enable HXT clock */
    CLK_EnableXtalRC(CLK_PWRCTL_HXTEN_Msk);

    /* Wait for HXT clock ready */
    CLK_WaitClockReady(CLK_STATUS_HXTSTB_Msk);

    /* Enable PLL */
    CLK->PLLCTL = CLK_PLLCTL_128MHz_HIRC;

    /* Waiting for PLL stable */
    CLK_WaitClockReady(CLK_STATUS_PLLSTB_Msk);

    /* Select HCLK clock source as PLL and HCLK source divider as 2 */
    CLK_SetHCLK(CLK_CLKSEL0_HCLKSEL_PLL, CLK_CLKDIV0_HCLK(2));

    /* Enable UART module clock */
    CLK_EnableModuleClock(UART0_MODULE);
    CLK_EnableModuleClock(UART1_MODULE);

    /* Select UART module clock source as HXT and UART module clock divider as 1 */
    CLK_SetModuleClock(UART0_MODULE, CLK_CLKSEL1_UART0SEL_HXT, CLK_CLKDIV0_UART0(1));
    CLK_SetModuleClock(UART1_MODULE, CLK_CLKSEL1_UART1SEL_HXT, CLK_CLKDIV0_UART1(1));

    /*---------------------------------------------------------------------------------------------------------*/
    /* Init I/O Multi-function                                                                                 */
    /*---------------------------------------------------------------------------------------------------------*/

    /* Set PB multi-function pins for UART1 RXD(PB.6), TXD(PB.7), nRTS(PB.8) and nCTS(PB.9) */
    SYS->GPB_MFPL = (SYS->GPB_MFPL & (~SYS_GPB_MFPL_PB6MFP_Msk)) | SYS_GPB_MFPL_PB6MFP_UART1_RXD;
    SYS->GPB_MFPL = (SYS->GPB_MFPL & (~SYS_GPB_MFPL_PB7MFP_Msk)) | SYS_GPB_MFPL_PB7MFP_UART1_TXD;
    SYS->GPB_MFPH = (SYS->GPB_MFPH & (~SYS_GPB_MFPH_PB8MFP_Msk)) | SYS_GPB_MFPH_PB8MFP_UART1_nRTS;
    SYS->GPB_MFPH = (SYS->GPB_MFPH & (~SYS_GPB_MFPH_PB9MFP_Msk)) | SYS_GPB_MFPH_PB9MFP_UART1_nCTS;

    /* Set multi-function pins for UART0 RXD and TXD */
    SYS->GPB_MFPH = (SYS->GPB_MFPH & (~(UART0_RXD_PB12_Msk | UART0_TXD_PB13_Msk))) | UART0_RXD_PB12 | UART0_TXD_PB13; 

}

iota_ret hash_app_text(uint8_t *arg, uint32_t arg_len, uint8_t **meas, uint32_t *meas_len) {
	*meas = malloc(sizeof(unsigned char)*32);
	if (!*meas) return IOTA_ERR_MEAS;
	measure_app_text(*meas);
	*meas_len = sizeof(unsigned char)*32;
	return IOTA_OK;
}	

void measure_app_text(unsigned char sha256[32]) {
	unsigned char* start = (unsigned char*)0x3000c004;
	unsigned char* end =   (unsigned char*)0x3000c004 + sizeof(uint32_t);
	mbedtls_sha256(start, end - start, sha256, 0);
}

void print_iota_error(iota_ret ret){
		printf("\nS_Measurer: %s", iota_strerror(ret));
	  printf("\nS_Measurer: %s", "\r\n");
}

/*----------------------------------------------------------------------------
  Main function
 *----------------------------------------------------------------------------*/
int main(void)
{
	  /*
    printf("\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|     Pin Configure                                         |\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|  ______                                            _____  |\n");
    printf("| |      |                                          |     | |\n");
    printf("| |Master|--UART1_TXD(PB.7)  <==>  UART1_RXD(PB.6)--|Slave| |\n");
    printf("| |      |--UART1_nCTS(PB.9) <==> UART1_nRTS(PB.8)--|     | |\n");
    printf("| |______|                                          |_____| |\n");
    printf("|                                                           |\n");
    printf("+-----------------------------------------------------------+\n");*/
		
	  /* Unlock protected registers */
    SYS_UnlockReg();

    /* Init System, peripheral clock and multi-function I/O */
    SYS_Init();
	
	   /* Lock protected registers */
    SYS_LockReg();

    /* Init UART0 for printf */
    UART0_Init();

    /* Init UART0 for transfer*/
    UART1_Init();
		
		
    printf("+------------------------------------------------------------+\n");
    printf("|       NuVoton M2351 - IoTA Demo Measurer (Trustzone)       |\n");
    printf("+------------------------------------------------------------+\n");
    
	  printf("\nS_Measurer: Secure Code is Running...\n");

    /* Init GPIO Port A for secure LED control */
    GPIO_SetMode(PA, BIT13 | BIT12 | BIT11 | BIT10, GPIO_MODE_OUTPUT);

    /* Init GPIO Port C for non-secure LED control */
    GPIO_SetMode(PC_NS, BIT1, GPIO_MODE_OUTPUT);
		
		Nonsecure_Init();
		
		while(1);
}