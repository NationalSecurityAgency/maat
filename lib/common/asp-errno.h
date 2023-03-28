/*
 * Copyright 2023 United States Government
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __MAAT_COMMON_ASP_ERRNO_H__
#define __MAAT_COMMON_ASP_ERRNO_H__

/*! \file
 * Return codes from ASP functions
 * 0 always means sucess
 * non-zero is failure and may be one of the following
 */
#define ASP_APB_SUCCESS (0)
#define ASP_APB_ERROR_GENERIC (-1)
#define ASP_APB_ERROR_NOMEM (-2)
#define ASP_APB_ERROR_IO (-3)
#define ASP_APB_ERROR_BADXML (-4)
#define ASP_APB_ERROR_NOTIMPLEMENTED (-5)
#define ASP_APB_ERROR_INVALIDSATISFIER (-6)
#define ASP_APB_ERROR_INVALIDSERVICE (-7)
#define ASP_APB_ERROR_UNSUPPORTEDFEATURE (-8)
#define ASP_APB_ERROR_BADPARAM (-9)
#define ASP_APB_ERROR_GRAPHOPERATION (-10)
#define ASP_APB_ERROR_INVALIDCONFIGFILENAME (-11)
#define ASP_APB_ERROR_SOCKWRITEFAILURE (-12)
#define ASP_APB_ERROR_SOCKREADFAILURE (-13)
#define ASP_APB_ERROR_SOCKCLOSEDOTHEREND (-14)
#define ASP_APB_ERROR_UNEXPECTEDMESSAGE (-15)
#define ASP_APB_ERROR_ADDRESSSPACEORTYPE (-16)
#define ASP_APB_ERROR_UUIDTYPECONFLICT (-17)
#define ASP_APB_ERROR_MARSHALL (-18)
/**
 * Platform specific error codes start from here and are defined in the
 * platform header
 */
#define ASP_APB_PLATFORM_ERROR_BASE (1000)

#endif
