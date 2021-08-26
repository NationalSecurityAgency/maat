/*
 * Copyright 2020 United States Government
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

/**
 * taint.h: Define macros used by the CQUAL++ static taint
 * checker. Defines all macros as empty/identity unless the CQUAL
 * macro is defined.
 */
#ifdef CQUAL
#define __tainted   $tainted
#define __untainted $untainted
#define __flow_1     $_1
#define __flow_2     $_2
#define __flow_1_2   $_1_2
#define UNTAINT(x) (($untainted typeof(x))(x))
#define TAINT(x)   (($tainted typeof(x))(x))
#else
#define __tainted
#define __untainted
#define __flow_1
#define __flow_2
#define __flow_1_2
#define UNTAINT(x) (x)
#define TAINT(x) (x)
#endif
