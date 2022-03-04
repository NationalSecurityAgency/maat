/**************************************************************************//**
 * @file     main_ns.c
 * @version  V1.00
 * @brief    Non-secure sample code for Collaborative Secure Software Development
 *
 * @note
 * Copyright (C) 2018 Nuvoton Technology Corp. All rights reserved.
 ******************************************************************************/

#include <arm_cmse.h>
#include "NuMicro.h"                    /* Device header */
#include "cssd_lib.h"                   /* Collaborative Secure Software Development Library header */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "ns_certs.h"
#include "libiota.h"
#include <stdarg.h>
#include <string.h>
#include "aes.h"
#include "sha256.h"
#include "ssl.h"
#include "rsa.h"
#include "error.h"

uint32_t blink __attribute__((section(".ARM.__at_0x3000c004"))) = 500;

iota iota_inst;
uint8_t* req_buf;
uint32_t req_buf_len;
int32_t i32Item;

extern char GetChar(void);
int32_t main(void);
void UARTTx (unsigned char* req_ser, int req_ser_ln);
void UARTRx ();
uint8_t* Get_Request_Buffer(void);
uint32_t Get_Request_Buffer_Len(void);
void SysTick_Handler(void);
void print_iota_error(iota_ret ret);
iota_ret call_iota(unsigned char* req_ser, const int req_ser_len, unsigned char* out_ser, const int max_out);

/*----------------------------------------------------------------------------
  SysTick IRQ Handler
 *----------------------------------------------------------------------------*/
void SysTick_Handler(void)
{
    static uint32_t u32Ticks;

    if (u32Ticks < blink/2)
			Secure_PA11_LED_On(0u);
		else 
			Secure_PA11_LED_Off(0u);
		
		if (u32Ticks > blink)
			u32Ticks = 0;
		else
			u32Ticks++;
}

void print_iota_error(iota_ret ret){
		printf("\nNS_Measurer: %s", iota_strerror(ret));
	  printf("\nNS_Measurer: %s", "\r\n");
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
	
	iota_ret ret;
	iota_msg *resp;
	uint8_t resp_buf[4096];
		
	/* Init GPIO Port C for non-secure LED control */
  GPIO_SetMode(PC_NS, BIT0, GPIO_MODE_OUTPUT);

  /* Call secure API to get system core clock */
  SystemCoreClock = GetSystemCoreClock();

  /* Generate Systick interrupt every 10 ms */
  SysTick_Config(SystemCoreClock / 100);
	
	printf("\nNS_Measurer: Nonsecure Code is Running...\n");
	
	printf("\nNS_Measurer: Is this Device Compromised? Y or N\n");
	
	i32Item = getchar();
	
	if(i32Item == 'Y' || i32Item == 'y')
    blink = 50;
	
	printf("\nNS_Measurer: Waiting for IoTA Request...\n");
		
	//RS485_9bitModeSlave();
	UARTRx();
		
	req_buf = Get_Request_Buffer();
	req_buf_len = Get_Request_Buffer_Len();  
		
  printf("\nNS_Measurer: Bytes Received -> %d\r\n", req_buf_len);
		
	printf("\nNS_Measurer: Requesting IoTA Measurement to S World...\r\n");
		
	ret = call_iota(req_buf, req_buf_len, resp_buf, 4096);
	if (ret != IOTA_OK) {printf("\nNS_Measurer: Response from S World Generated Errors...\r\n"); 
			print_iota_error(ret);
			return ret;}
	
	printf("\nNS_Measurer: The Size of the Buffer Received from S World is %d...\r\n", ((iota_msg_hdr*)resp_buf)->len);
  
	resp = malloc(sizeof(iota_msg));
			
	//RS485_9bitModeMaster(resp_buf, ((iota_msg_hdr*)resp_buf)->len);
	UARTTx(resp_buf, ((iota_msg_hdr*)resp_buf)->len);
			
	printf("\nNS_Measurer: IoTA Response Sent to the Master --> OK!\r\n");		
	
	while(1);
}