/**************************************************************************//**
 * @file     cssd_lib.h
 * @version  V1.00
 * @brief    M2351 Collaborative Secure Software Development Library header file
 *
 * @note
 * Copyright (C) 2018 Nuvoton Technology Corp. All rights reserved.
 ******************************************************************************/
#ifndef __CSSD_LIB_H__
#define __CSSD_LIB_H__

/*----------------------------------------------------------------------------
  NonSecure Callable Functions from Secure Region
 *----------------------------------------------------------------------------*/
extern int32_t Secure_PA11_LED_On(uint32_t num);
extern int32_t Secure_PA11_LED_Off(uint32_t num);
extern int32_t Secure_PA12_LED_On(uint32_t num);
extern int32_t Secure_PA12_LED_Off(uint32_t num);
extern int32_t Secure_PA13_LED_On(uint32_t num);
extern int32_t Secure_PA13_LED_Off(uint32_t num);
extern uint32_t GetSystemCoreClock(void);

#endif //__CSSD_LIB_H__
